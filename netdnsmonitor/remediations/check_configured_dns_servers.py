"""check_configured_dns_servers -- which resolvers is the system using?

Runs `scutil --dns` and reports its output. It reads only.

Outcomes: the tool's output; `no output from scutil --dns`; or `failed: ...` when
the command exited non-zero or did not complete.

Part of the DNS ladder, first step: establish which resolvers are in use before
anything is changed about them.
"""

NAME = "check_configured_dns_servers"
KIND = "check"
NEEDS_PRIVILEGE = False
REASON = (
    "Establish which resolvers the system is actually using before changing anything about them."
)
CLASSIFICATIONS = ("dns",)
ORDER = 10
ENABLED = True


def run(ctx):
    return ctx.report_command([ctx.tools.SCUTIL, "--dns"])
