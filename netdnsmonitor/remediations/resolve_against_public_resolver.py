"""resolve_against_public_resolver -- does a public resolver answer for a known name?

Asks a public DNS server (not the system resolver) for `ctx.probe_domain`
(`example.com` by default) through `ctx.query_public_dns`. This separates a broken
local resolver from a name that cannot be resolved anywhere. It changes nothing.

`ctx.query_public_dns` returns True, False or None, and None is not False:

  * True  -> `<domain> resolved via public resolver`
  * False -> `<domain> did NOT resolve via public resolver`
  * None  -> `could not obtain a usable public resolver result ...`, which says
    nothing about the name: no reply, no route, UDP 53 blocked, or a bad reply.

Do not collapse the None case into "did NOT resolve": that would tell someone DNS
is broken everywhere when nothing was learned.
"""

NAME = "resolve_against_public_resolver"
KIND = "check"
NEEDS_PRIVILEGE = False
REASON = "Separates a broken local resolver from a name that genuinely cannot be resolved anywhere."
CLASSIFICATIONS = ("dns",)
ORDER = 40
ENABLED = True


def run(ctx):
    domain = ctx.probe_domain
    answered = ctx.query_public_dns(domain)
    if answered is None:
        return (
            f"could not obtain a usable public resolver result for {domain} "
            "(no usable reply: timed out, no route, UDP port 53 blocked, "
            "or an invalid or truncated reply); this "
            "says nothing about the name"
        )
    if answered:
        return f"{domain} resolved via public resolver"
    return f"{domain} did NOT resolve via public resolver"
