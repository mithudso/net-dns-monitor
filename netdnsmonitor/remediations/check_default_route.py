"""check_default_route -- does the machine have a default route?

Runs `netstat -rn -f inet` and `netstat -rn -f inet6` and reports both tables.
It reads only.

Outcomes:
  * `IPv4 routes:` / `IPv6 routes:` sections with each table's text;
  * a first line `partial: could not read one route table` when one table failed;
  * a first line `failed: could not read either route table` when both failed.

A missing default route looks like an outage from userspace and is fixed
completely differently from one, which is why this runs before any repair.
"""

NAME = "check_default_route"
KIND = "check"
NEEDS_PRIVILEGE = False
REASON = (
    "A missing default route is indistinguishable from an outage "
    "from userspace, and is fixed completely differently."
)
CLASSIFICATIONS = ("network",)
ORDER = 20
ENABLED = True


def run(ctx):
    findings = [
        (label, ctx.report_command([ctx.tools.NETSTAT, "-rn", "-f", family]))
        for label, family in (("IPv4", "inet"), ("IPv6", "inet6"))
    ]
    failures = sum(result.startswith("failed:") for _, result in findings)
    if failures == 2:
        prefix = "failed: could not read either route table\n"
    elif failures:
        prefix = "partial: could not read one route table\n"
    else:
        prefix = ""
    return prefix + "\n\n".join(f"{label} routes:\n{result}" for label, result in findings)
