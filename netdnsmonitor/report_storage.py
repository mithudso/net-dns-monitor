"""Persist an incident report (report.py) to disk as both JSON (for tooling)
and Markdown (for a human to open and hand to IT) -- the automatic-save step
that produces the artifact IT needs without anyone re-running diagnostics.
"""

import contextlib
import json
import os
import tempfile

from netdnsmonitor.report import render_markdown


def save_report(report: dict, directory: str) -> dict:
    os.makedirs(directory, exist_ok=True)
    timestamp = report["started_at"].replace(":", "-")
    json_path = os.path.join(directory, f"{timestamp}.json")
    markdown_path = os.path.join(directory, f"{timestamp}.md")

    # Build both payloads *before* opening either destination. Opening a path
    # in "w" mode truncates it to zero bytes immediately, so rendering or
    # encoding after the open leaves a 0-byte file behind on any error --
    # which is exactly how empty .md reports ended up on disk.
    json_text = json.dumps(report, indent=2)
    markdown_text = render_markdown(report)

    _atomic_write(json_path, json_text)
    _atomic_write(markdown_path, markdown_text)

    return {"json_path": json_path, "markdown_path": markdown_path}


def _atomic_write(path: str, text: str) -> None:
    """Write UTF-8 text so the target only ever holds complete content.

    Encode UTF-8 explicitly. Launched from launchd (no `LANG` set) the process
    locale encoding is ASCII, so a default `open(..., "w")` raises
    UnicodeEncodeError on any non-ASCII byte -- a curly quote from the Claude
    escalation text, a `µ`, or the U+FFFD the log readers substitute via
    `errors="replace"`. The JSON half survived that because `json.dump`
    defaults to `ensure_ascii=True`, which is why the failure showed up as a
    full .json beside a 0-byte .md. Confirmed from the real launchd log:

        report_storage.py, line 22, in save_report
        UnicodeEncodeError: 'ascii' codec can't encode character '\\u201c'

    Commit 7d09658 pinned `encoding="utf-8"` on the three subprocess *read*
    sites after the mirror-image UnicodeDecodeError crash; these were the
    write sites it missed.

    Write to a sibling temp file and `os.replace()` it into place so a failed
    or partial write can never truncate the destination. `os.replace` is
    atomic within a filesystem, and the temp file is created in the same
    directory to guarantee that.

    Two deliberate side effects: reports land at 0600 rather than 0644
    (`mkstemp` default, preserved by `os.replace`), which only tightens an
    owner-owned artifact; and a `tmp*.tmp` can be orphaned if the process is
    SIGKILLed mid-write, never on a normal exception.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        # suppress(OSError), because the cleanup must not replace the exception
        # being propagated: if os.replace failed, the useful error is that one,
        # not a follow-on failure to unlink the temp file.
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
