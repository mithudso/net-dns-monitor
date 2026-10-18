"""Where remediation scripts live, how they are checked, and how one is run.

Every step on the troubleshooting ladder is a Python file. The shipped ones sit in
`netdnsmonitor/remediations/`; a user's edits and additions sit in a per-user
directory. `docs/REMEDIATION_SCRIPTS.md` is the author's manual for the script
format and the `ctx` object; this module is the machinery behind it.

Three rules shape the code:

* **Listing never executes a script.** The metadata (`NAME`, `KIND`, ...) is read
  from the syntax tree with `ast.literal_eval`. The editor lists every script on
  open, and a script that does something at import time must not do it then.
* **A script's failure is data.** `execute` turns a raise, a timeout, a
  `sys.exit()` and a wrong return type into an outcome string that names the
  exception *class* only -- the message can carry command output or a URL
  (CLAUDE.md non-negotiable 4) -- and nothing escapes into a tick (5).
* **An override is a file with the built-in's name.** Reset is deleting that file,
  so "what is the shipped logic" never needs a second copy of it.

Nothing here touches the network or runs a subprocess: the script receives its
side effects through the `ctx` object `repair_executor` builds (non-negotiable 3).
"""

import ast
import contextlib
import os
import re
import tempfile
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from netdnsmonitor.ladder import DNS_LADDER, FAILOVER_STEP, NETWORK_LADDER, LadderStep

BUILTIN_DIR = Path(__file__).resolve().parent / "remediations"
DEFAULT_USER_DIR = "~/Library/Application Support/net-dns-monitor/remediations"

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
KINDS = ("check", "repair")
CLASSIFICATION_VALUES = ("network", "dns")

# A built-in step can make several 5s subprocess calls, so this is a ceiling on a
# stuck script rather than a budget for a healthy one.
DEFAULT_TIMEOUT_SECONDS = 60.0

ORIGIN_BUILTIN = "builtin"
ORIGIN_MODIFIED = "modified"
ORIGIN_CUSTOM = "custom"

# Metadata constants a script may set at module level, with the type each must be.
_FIELD_TYPES = {
    "NAME": str,
    "KIND": str,
    "NEEDS_PRIVILEGE": bool,
    "REASON": str,
    "CLASSIFICATIONS": (tuple, list),
    "ORDER": int,
    "ENABLED": bool,
}


def builtin_steps() -> list[LadderStep]:
    """Every shipped ladder step, in ladder order, each once."""
    seen: dict[str, LadderStep] = {}
    for step in [*NETWORK_LADDER, *DNS_LADDER, FAILOVER_STEP]:
        seen.setdefault(step.name, step)
    return list(seen.values())


@dataclass(frozen=True)
class ScriptInfo:
    """What the store knows about one script without having run it."""

    name: str
    kind: str
    needs_privilege: bool
    reason: str
    description: str
    classifications: tuple
    order: int
    enabled: bool
    origin: str
    path: Optional[Path]
    problems: tuple = field(default_factory=tuple)

    @property
    def valid(self) -> bool:
        return not self.problems


def inspect_source(source: str, expected_name: Optional[str] = None) -> tuple[dict, list[str]]:
    """(metadata, problems) for a script's text, without executing any of it.

    `problems` is empty exactly when the script could be installed and run. The
    metadata dict always carries every field, defaulted, so a half-written script
    can still be listed.
    """
    meta: dict = {
        "NAME": expected_name or "",
        "KIND": "",
        "NEEDS_PRIVILEGE": False,
        "REASON": "",
        "CLASSIFICATIONS": (),
        "ORDER": 100,
        "ENABLED": True,
        "DESCRIPTION": "",
    }
    problems: list[str] = []
    try:
        tree = ast.parse(source)
        compile(source, "<remediation>", "exec")
    except SyntaxError as exc:
        where = f" on line {exc.lineno}" if exc.lineno else ""
        return meta, [f"syntax error{where}: {exc.msg}"]
    except (ValueError, RecursionError) as exc:
        # NUL bytes and pathologically nested source raise these, not SyntaxError.
        return meta, [f"the source cannot be compiled ({type(exc).__name__})"]

    meta["DESCRIPTION"] = ast.get_docstring(tree) or ""
    seen: set[str] = set()
    has_run = False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run":
            has_run = isinstance(node, ast.FunctionDef) and bool(node.args.args or node.args.vararg)
            continue
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in _FIELD_TYPES:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            problems.append(f"{target.id} must be a literal value")
            continue
        expected = _FIELD_TYPES[target.id]
        # bool is an int subclass: ORDER = True would otherwise pass.
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            problems.append(f"{target.id} has the wrong type ({type(value).__name__})")
            continue
        meta[target.id] = value
        seen.add(target.id)

    if not has_run:
        problems.append("define `def run(ctx):` that returns the outcome string")
    for required in ("NAME", "KIND"):
        if required not in seen:
            problems.append(f"{required} is required")
    name = meta["NAME"]
    if "NAME" in seen and not NAME_RE.match(name):
        problems.append(
            "NAME must be lowercase letters, digits and underscores, starting with a letter"
        )
    elif expected_name is not None and "NAME" in seen and name != expected_name:
        problems.append(f"NAME is {name!r} but the file is {expected_name}.py; they must match")
    if "KIND" in seen and meta["KIND"] not in KINDS:
        problems.append(f"KIND must be one of {', '.join(KINDS)}")
    classifications = tuple(meta["CLASSIFICATIONS"])
    bad = [c for c in classifications if c not in CLASSIFICATION_VALUES]
    if bad:
        problems.append(
            f"CLASSIFICATIONS may only contain {', '.join(CLASSIFICATION_VALUES)} (got {bad})"
        )
    meta["CLASSIFICATIONS"] = classifications
    return meta, problems


@dataclass
class RunResult:
    """One execution of a script.

    `outcome` is what the report records. `detail` is for the editor only: a
    traceback can carry paths and command text, so it is never part of `outcome`.
    """

    outcome: str
    detail: str = ""
    log: list = field(default_factory=list)
    timed_out: bool = False


def execute(name: str, source: str, ctx, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> RunResult:
    """Run `source`'s `run(ctx)` on a worker thread and return its outcome.

    A thread, not the caller's stack: the caller is a tick, and a script that
    hangs must cost the report one `unknown:` line rather than the monitor. The
    cost of the thread is that a script stuck in a CPU loop cannot be killed;
    it is abandoned (it is a daemon thread) and reported as not finished.
    """
    box: dict = {}

    def target() -> None:
        try:
            namespace = {"__name__": f"netdnsmonitor_remediation_{name}"}
            exec(compile(source, f"<remediation:{name}>", "exec"), namespace)  # noqa: S102
            func = namespace.get("run")
            if not callable(func):
                box["outcome"] = "failed: the script defines no run(ctx)"
                return
            box["value"] = func(ctx)
        except BaseException as exc:  # noqa: BLE001 - sys.exit() in a script must not pass
            box["error"] = type(exc).__name__
            box["detail"] = traceback.format_exc()

    thread = threading.Thread(target=target, name=f"remediation-{name}", daemon=True)
    thread.start()
    thread.join(timeout)
    log = list(getattr(ctx, "log_lines", []))
    if thread.is_alive():
        return RunResult(
            f"unknown: {name} did not finish within {timeout:g}s; it may still be running",
            log=log,
            timed_out=True,
        )
    if "error" in box:
        return RunResult(
            f"failed: the {name} step raised {box['error']}", detail=box.get("detail", ""), log=log
        )
    if "outcome" in box:
        return RunResult(box["outcome"], log=log)
    value = box.get("value")
    if value is None:
        return RunResult(
            f"failed: the {name} script returned no outcome (run(ctx) must return a string)",
            log=log,
        )
    if not isinstance(value, str) or not value.strip():
        kind = type(value).__name__ if not isinstance(value, str) else "an empty string"
        return RunResult(
            f"failed: the {name} script returned {kind}, not an outcome string", log=log
        )
    return RunResult(value, log=log)


class ScriptStore:
    """The shipped scripts plus, when permitted, the user's overrides and additions.

    `user_dir=None` is the built-ins-only store: what the App Store edition and
    every offline test use, because running user-authored code is neither
    permitted there (Guideline 2.5.2) nor deterministic in a test.
    """

    def __init__(self, user_dir: Optional[Path] = None, builtin_dir: Path = BUILTIN_DIR):
        self.user_dir = Path(user_dir) if user_dir is not None else None
        self.builtin_dir = Path(builtin_dir)

    @property
    def editable(self) -> bool:
        return self.user_dir is not None

    # --- reading ---------------------------------------------------------

    def _read(self, path: Path) -> Optional[str]:
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None

    def builtin_names(self) -> list[str]:
        return [step.name for step in builtin_steps()]

    def builtin_source(self, name: str) -> Optional[str]:
        if not NAME_RE.match(name):
            return None
        return self._read(self.builtin_dir / f"{name}.py")

    def _user_path(self, name: str) -> Optional[Path]:
        if self.user_dir is None or not NAME_RE.match(name):
            return None
        return self.user_dir / f"{name}.py"

    def user_source(self, name: str) -> Optional[str]:
        path = self._user_path(name)
        return self._read(path) if path is not None else None

    def source(self, name: str) -> Optional[str]:
        """The text that runs for `name`: the override if there is one."""
        override = self.user_source(name)
        return override if override is not None else self.builtin_source(name)

    def names(self) -> list[str]:
        """Built-in step names in ladder order, then custom names alphabetically."""
        names = list(self.builtin_names())
        if self.user_dir is not None and self.user_dir.is_dir():
            try:
                extra = sorted(
                    p.stem
                    for p in self.user_dir.glob("*.py")
                    if NAME_RE.match(p.stem) and p.stem not in names
                )
            except OSError:
                extra = []
            names += extra
        return names

    def info(self, name: str) -> Optional[ScriptInfo]:
        builtin = self.builtin_source(name)
        override = self.user_source(name)
        text = override if override is not None else builtin
        if text is None:
            return None
        meta, problems = inspect_source(text, expected_name=name)
        if override is not None:
            origin = ORIGIN_MODIFIED if builtin is not None else ORIGIN_CUSTOM
            path = self._user_path(name)
        else:
            origin, path = ORIGIN_BUILTIN, self.builtin_dir / f"{name}.py"
        return ScriptInfo(
            name=name,
            kind=meta["KIND"],
            needs_privilege=meta["NEEDS_PRIVILEGE"],
            reason=meta["REASON"],
            description=meta["DESCRIPTION"],
            classifications=meta["CLASSIFICATIONS"],
            order=meta["ORDER"],
            enabled=meta["ENABLED"],
            origin=origin,
            path=path,
            problems=tuple(problems),
        )

    def list_scripts(self) -> list[ScriptInfo]:
        return [info for name in self.names() if (info := self.info(name)) is not None]

    def custom_steps(self, classification: str) -> list[LadderStep]:
        """Ladder steps contributed by custom scripts for one classification.

        Built-in steps are not here: their order and tags are `ladder.py`'s. An
        invalid or disabled custom script contributes nothing, so a typo cannot
        put a step on the ladder that then fails every incident.
        """
        builtin = set(self.builtin_names())
        chosen = []
        for info in self.list_scripts():
            if info.name in builtin or not info.valid or not info.enabled:
                continue
            if classification in info.classifications:
                chosen.append(info)
        chosen.sort(key=lambda i: (i.order, i.name))
        return [LadderStep(i.name, i.kind, i.needs_privilege, i.reason) for i in chosen]

    # --- writing ---------------------------------------------------------

    def save(self, name: str, source: str) -> list[str]:
        """Install `source` as `name`. Returns the problems; empty means saved.

        Saving text identical to the built-in removes the override instead, so
        "modified" always means the logic really differs from the shipped one.
        """
        if self.user_dir is None:
            return ["editing remediation scripts is not available in this build"]
        if not NAME_RE.match(name):
            return ["the name must be lowercase letters, digits and underscores"]
        source = source.replace("\r\n", "\n")
        if not source.endswith("\n"):
            source += "\n"
        _meta, problems = inspect_source(source, expected_name=name)
        if problems:
            return problems
        builtin = self.builtin_source(name)
        if builtin is not None and builtin == source:
            self.remove(name)
            return []
        try:
            self.user_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=self.user_dir, prefix=f".{name}.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(source)
                os.chmod(tmp, 0o600)
                os.replace(tmp, self.user_dir / f"{name}.py")
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError as exc:
            return [f"could not write the script ({type(exc).__name__})"]
        return []

    def remove(self, name: str) -> str:
        """Reset a modified built-in, or delete a custom script. Returns what happened."""
        path = self._user_path(name)
        if path is None:
            return "nothing to remove in this build"
        if not path.exists():
            if self.builtin_source(name) is not None:
                return f"{name} is a built-in with no changes; there is nothing to reset"
            return f"{name} does not exist"
        was_builtin = self.builtin_source(name) is not None
        try:
            path.unlink()
        except OSError as exc:
            return f"could not remove {name} ({type(exc).__name__})"
        return f"reset {name} to the built-in" if was_builtin else f"deleted {name}"


def new_script_template(name: str, classification: str = "dns") -> str:
    """Starting text for a new custom script, documented in place."""
    return f'''"""{name} -- one line saying what this step does.

Say here what it checks or repairs, what each outcome string means, and what it
changes on the machine. The editor shows this text as the script's description.
"""

NAME = "{name}"  # must match the file name
KIND = "check"  # "check" reads only; "repair" changes something
NEEDS_PRIVILEGE = False  # True if it needs the sudoers grant
REASON = "Why this step is worth running, in words an IT reader will understand."
CLASSIFICATIONS = ("{classification}",)  # which incidents run it: "network", "dns"
ORDER = 100  # lower runs earlier among custom steps
ENABLED = True  # False keeps the file but leaves it off the ladder


def run(ctx):
    """Return one line starting ok:, failed:, partial:, unknown: or skipped:."""
    result = ctx.run(["/usr/sbin/scutil", "--dns"])
    if ctx.did_not_complete(result):
        return f"unknown: scutil did not complete ({{result.stderr}})"
    if result.returncode != 0:
        return f"failed: scutil exited {{result.returncode}}"
    return "ok: read the DNS configuration"
'''
