"""What the remediation-script editor does, apart from drawing it.

`remediation_window.py` is the AppKit shell and decides nothing; every rule that
the offline suite can cover is here, for the reason `console_window.py` gives: an
`if` inside an untestable window is a bug nobody will find.

The editor works on three verbs. **Check** compiles the text and validates its
metadata without running it. **Save** refuses anything Check refuses. **Run** executes
the script for real, through the same executor the incident pipeline uses, so
what the editor shows is what an incident would record.
"""

import io
import keyword
import tokenize
from dataclasses import dataclass
from typing import Callable, Optional

from netdnsmonitor.remediation_scripts import (
    NAME_RE,
    ORIGIN_BUILTIN,
    ORIGIN_CUSTOM,
    ORIGIN_MODIFIED,
    RunResult,
    ScriptStore,
    inspect_source,
    new_script_template,
)

ORIGIN_LABELS = {
    ORIGIN_BUILTIN: "built-in",
    ORIGIN_MODIFIED: "built-in, modified",
    ORIGIN_CUSTOM: "custom",
}

# Token kinds the window colours. Anything else keeps the default text colour.
KIND_KEYWORD = "keyword"
KIND_STRING = "string"
KIND_COMMENT = "comment"
KIND_NUMBER = "number"
KIND_BUILTIN_NAME = "name"

_BUILTIN_NAMES = frozenset({"True", "False", "None", "self", "ctx"})


@dataclass(frozen=True)
class ScriptRow:
    name: str
    label: str
    origin: str
    valid: bool
    enabled: bool


def utf16_length(text: str) -> int:
    """Length in UTF-16 code units, which is what NSString offsets count.

    Python indexes by code point; Cocoa by UTF-16 unit. They differ for anything
    outside the Basic Multilingual Plane (an emoji in a comment), and a colour
    range computed in code points would then land on the wrong characters.
    """
    return len(text.encode("utf-16-le")) // 2


def highlight_spans(source: str) -> list[tuple[int, int, str]]:
    """(start, length, kind) in UTF-16 units for the coloured tokens in `source`.

    Built on `tokenize`, so a string containing `#` is a string and not a comment.
    Source that does not tokenize (unterminated string mid-edit) yields the spans
    found before the error; an editor must not stop colouring while the user types.
    """
    lines = source.splitlines(keepends=True)
    # Offset of each line's start, in UTF-16 units.
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + utf16_length(line))

    def offset(row: int, col: int) -> int:
        line = lines[row - 1] if row - 1 < len(lines) else ""
        return starts[min(row - 1, len(starts) - 1)] + utf16_length(line[:col])

    spans: list[tuple[int, int, str]] = []
    # Python 3.12+ splits an f-string into START ... END tokens; the whole of it,
    # braces included, is coloured as one string.
    fstring_start = getattr(tokenize, "FSTRING_START", -1)
    fstring_end = getattr(tokenize, "FSTRING_END", -2)
    open_fstrings: list[tuple[int, int]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            kind = None
            if tok.type == fstring_start:
                open_fstrings.append(tok.start)
                continue
            if tok.type == fstring_end and open_fstrings:
                begin = open_fstrings.pop()
                if not open_fstrings:
                    length = offset(*tok.end) - offset(*begin)
                    if length > 0:
                        spans.append((offset(*begin), length, KIND_STRING))
                continue
            if open_fstrings:
                continue
            if tok.type == tokenize.COMMENT:
                kind = KIND_COMMENT
            elif tok.type == tokenize.STRING:
                kind = KIND_STRING
            elif tok.type == tokenize.NUMBER:
                kind = KIND_NUMBER
            elif tok.type == tokenize.NAME:
                if keyword.iskeyword(tok.string):
                    kind = KIND_KEYWORD
                elif tok.string in _BUILTIN_NAMES:
                    kind = KIND_BUILTIN_NAME
            if kind is None:
                continue
            if tok.start[0] != tok.end[0]:
                # A multi-line token (a docstring): one span from start to end.
                length = offset(tok.end[0], tok.end[1]) - offset(*tok.start)
            else:
                length = utf16_length(tok.string)
            if length > 0:
                spans.append((offset(*tok.start), length, kind))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return spans


def format_run(name: str, result: RunResult, seconds: float) -> str:
    """The text the editor's output pane shows for one run."""
    lines = [f">>> {name}  ({seconds:.2f}s)", f"outcome: {result.outcome}"]
    if result.timed_out:
        lines.append("(the script is still running in the background and cannot be stopped)")
    if result.log:
        lines.append("ctx.log output:")
        lines += [f"    {line}" for line in result.log]
    if result.detail:
        lines += ["", "traceback (shown here only, never recorded in a report):", result.detail]
    return "\n".join(lines)


class EditorSession:
    """The editor's state and operations, with the window's I/O left out.

    `run_source(name, source, classification)` is `executor.run_source` from the
    live executor. `clock` is injected for the tests.
    """

    def __init__(
        self,
        store: ScriptStore,
        run_source: Optional[Callable[..., RunResult]] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.store = store
        self.run_source = run_source
        if clock is None:
            import time

            clock = time.monotonic
        self.clock = clock

    def rows(self) -> list[ScriptRow]:
        rows = []
        for info in self.store.list_scripts():
            flags = []
            if not info.valid:
                flags.append("INVALID")
            if not info.enabled:
                flags.append("off")
            suffix = f" ({', '.join(flags)})" if flags else ""
            rows.append(
                ScriptRow(
                    info.name,
                    f"{info.name}  [{ORIGIN_LABELS.get(info.origin, info.origin)}]{suffix}",
                    info.origin,
                    info.valid,
                    info.enabled,
                )
            )
        return rows

    def load(self, name: str) -> str:
        return self.store.source(name) or ""

    def description(self, name: str) -> str:
        info = self.store.info(name)
        if info is None:
            return ""
        where = ", ".join(info.classifications) or "none (built-in order comes from the ladder)"
        privilege = "needs the sudoers grant" if info.needs_privilege else "no privilege needed"
        return (
            f"{info.name} -- {info.kind}, {privilege}. Runs for: {where}.\n"
            f"Why: {info.reason or '(none given)'}\n\n{info.description}"
        ).strip()

    def check(self, name: str, text: str) -> list[str]:
        """Problems that would stop `text` being saved as `name`; empty when fine."""
        _meta, problems = inspect_source(text, expected_name=name)
        return problems

    def save(self, name: str, text: str) -> tuple[bool, str]:
        problems = self.store.save(name, text)
        if problems:
            return False, "not saved:\n  " + "\n  ".join(problems)
        info = self.store.info(name)
        if info is not None and info.origin == ORIGIN_BUILTIN:
            return True, f"saved: {name} now matches the built-in, so the override was removed"
        return True, f"saved {name}; it applies from the next incident"

    def remove(self, name: str) -> str:
        return self.store.remove(name)

    def can_remove(self, name: str) -> bool:
        """Reset applies to a modified built-in, delete to a custom script."""
        info = self.store.info(name)
        return info is not None and info.origin in (ORIGIN_MODIFIED, ORIGIN_CUSTOM)

    def remove_verb(self, name: str) -> str:
        info = self.store.info(name)
        return "Delete" if info is not None and info.origin == ORIGIN_CUSTOM else "Reset"

    def create(self, name: str, classification: str = "dns") -> tuple[bool, str, str]:
        """(ok, message, text). Creates nothing on disk; the first Save does."""
        name = name.strip()
        if not NAME_RE.match(name):
            return (
                False,
                "a name is lowercase letters, digits and underscores, starting with a letter",
                "",
            )
        if self.store.info(name) is not None:
            return False, f"{name} already exists", ""
        return (
            True,
            f"new script {name}; Save to keep it",
            new_script_template(name, classification),
        )

    def needs_confirmation(self, name: str) -> bool:
        """A repair changes the machine, so its test run asks first."""
        info = self.store.info(name)
        return info is not None and info.kind == "repair"

    def test_run(self, name: str, text: str, classification: Optional[str] = None) -> str:
        """Run `text` (saved or not) as `name` and format what happened.

        Blocks for up to the script timeout; the window calls it on a worker.
        """
        if self.run_source is None:
            return "running scripts is not wired into this editor"
        problems = self.check(name, text)
        if problems:
            return "not run:\n  " + "\n  ".join(problems)
        if classification is None:
            info = self.store.info(name)
            if info is not None and info.classifications:
                classification = info.classifications[0]
        started = self.clock()
        try:
            result = self.run_source(name, text, classification)
        except Exception as exc:  # noqa: BLE001 - a test run must not take the window down
            return f"failed: the run raised {type(exc).__name__}"
        return format_run(name, result, self.clock() - started)
