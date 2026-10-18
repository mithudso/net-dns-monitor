"""The shipped remediation scripts, one Python file per troubleshooting-ladder step.

These files are data for `netdnsmonitor.remediation_scripts`, not modules anything
imports. Each is read as text, checked without running it, and executed with a
`ctx` object built by `repair_executor`. A user's edit is saved as a file of the
same name in the per-user directory and wins over the file here; resetting
deletes it. `docs/REMEDIATION_SCRIPTS.md` documents the format and `ctx`.

A built-in script must not import `socket` or `subprocess`: every side effect
goes through `ctx`, which is what lets the offline suite run all of them against
fakes (CLAUDE.md non-negotiable 3). A test enforces it.
"""
