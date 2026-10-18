"""flush_dns_cache -- clear the DNS cache, and signal mDNSResponder if permitted.

Two actions, reported separately because they succeed separately:

  1. `dscacheutil -flushcache` clears the cache and needs no privilege.
  2. `killall -HUP mDNSResponder` makes the resolver daemon drop its own cache.
     That daemon belongs to another user, so without the sudoers grant (the
     "Grant elevated permissions" button) the signal is refused. With the grant,
     the script retries it through `sudo -n`.

Outcomes, most to least successful:
  * `ok`                     both succeeded unprivileged;
  * `ok (HUP sent ...)`      the cache was flushed and the granted rule sent the HUP;
  * `partial: ...`           the cache flushed but the HUP did not (the text says
                             whether that was a missing grant, a rule that did not
                             match, or a command that did not complete);
  * `failed: ...`            `dscacheutil` itself failed.

The HUP is a signal and its effect is not read back, so the text says "sent", not
"restarted". Never return `ok` when only half of this happened.
"""

NAME = "flush_dns_cache"
KIND = "repair"
NEEDS_PRIVILEGE = False
REASON = "A cached negative or stale answer keeps failing long after the underlying fault is gone."
CLASSIFICATIONS = ("dns",)
ORDER = 30
ENABLED = True


def run(ctx):
    unavailable = ctx.unavailable("flushing the DNS cache")
    if unavailable is not None:
        return unavailable
    flush = ctx.run([ctx.tools.DSCACHEUTIL, "-flushcache"])
    if ctx.did_not_complete(flush):
        return f"failed: {ctx.tools.DSCACHEUTIL} did not complete ({flush.stderr})"
    if flush.returncode != 0:
        return f"failed: {flush.stderr.strip()}"
    hup = ctx.run(list(ctx.tools.MDNS_HUP))
    if hup.returncode == 0:
        return "ok"
    if ctx.did_not_complete(hup):
        # Nothing was refused, so the grant is not the fix and the hint would be wrong.
        return (
            "partial: dscacheutil cache flushed; the mDNSResponder HUP did not "
            f"complete ({hup.stderr})"
        )
    if ctx.is_granted():
        elevated = ctx.run([ctx.tools.SUDO, "-n", *ctx.tools.MDNS_HUP])
        if elevated.returncode == 0:
            return "ok (HUP sent to mDNSResponder using the granted privilege)"
        if ctx.did_not_complete(elevated):
            return (
                "partial: cache flushed; the HUP sent through the granted sudo rule "
                f"did not complete ({elevated.stderr})"
            )
        # The grant exists but did not work: the rule may not match, or sudoers.d
        # may not be included. The fix differs from "no grant", so say which.
        return (
            "partial: cache flushed, but the granted sudo rule did not signal "
            f"mDNSResponder ({elevated.stderr.strip()})"
        )
    return (
        "partial: dscacheutil cache flushed, but mDNSResponder HUP "
        f"failed ({hup.stderr.strip()}) -- requires elevated privilege. {ctx.tools.GRANT_HINT}"
    )
