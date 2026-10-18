"""check_interface_state -- is the link itself up?

Runs `scutil --nwi`, which prints the network interfaces the system considers
reachable and which is primary. It reads only; nothing on the machine changes.

Outcomes:
  * the tool's output, unchanged, when it ran and exited 0;
  * `no output from scutil --nwi` when it ran and printed nothing, so an empty
    reading is never mistaken for "no findings";
  * `failed: ...` when it exited non-zero or did not run to completion.

Part of the NETWORK ladder, first step. Edit it to read other state, but keep the
rule: a command that did not run must say so, never return an empty string.
"""

NAME = "check_interface_state"
KIND = "check"
NEEDS_PRIVILEGE = False
REASON = "Confirm the link itself is up before blaming anything above it."
CLASSIFICATIONS = ("network",)
ORDER = 10
ENABLED = True


def run(ctx):
    return ctx.report_command([ctx.tools.SCUTIL, "--nwi"])
