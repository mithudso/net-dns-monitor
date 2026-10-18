"""switch_to_backup_network -- move the machine to the backup network.

The last rung: every cheaper, more easily reversed repair has already been tried.
This script does not build the `networksetup` command itself. It calls
`ctx.failover(classification)`, which is `failover.attempt_failover`, the one
place that:

  * checks the new service order with `service_order.is_order_intact` (same
    length, same set, no duplicates, nothing that looks like a flag);
  * lists the order again right before writing and refuses if it changed;
  * writes it, then reads it back, and reports `failed:` if the read-back does
    not match, because `networksetup` can exit 0 without changing anything.

Never build a `-ordernetworkservices` argv in a script: a name dropped from that
list deletes a network service from the system (CLAUDE.md non-negotiable 9).

Outcomes are whatever `attempt_failover` returns, plus:
  * `disabled: network failover is not configured` when no failover is wired in;
  * `refused: ...` when no classification was given, because the policy refuses
    classifications it was not configured for and a default would authorise a
    switch the operator never asked for.
"""

NAME = "switch_to_backup_network"
KIND = "repair"
NEEDS_PRIVILEGE = True
REASON = (
    "Every cheaper, more easily reversed repair has already been tried; "
    "moving to the backup link can restore connectivity while the preferred "
    "link is investigated."
)
CLASSIFICATIONS = ("network",)
ORDER = 90
ENABLED = True


def run(ctx):
    if ctx.failover is None:
        return "disabled: network failover is not configured"
    if not ctx.classification:
        return "refused: the failover step needs the classification it is responding to"
    return ctx.failover(ctx.classification)
