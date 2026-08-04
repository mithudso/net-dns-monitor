"""Work out *where* an outage is, by comparing what this machine sees with what a
peer on the same LAN sees.

One machine cannot tell these apart. "I can't reach the internet" looks identical
whether the Wi-Fi card has wedged, the router is down, the ISP is out, or DNS
alone is broken. A second machine on the same network is the missing reference:
if it is fine, the fault is on this side; if it is equally broken, it is upstream
of both.

Three signals from us (`external_reachable`, `dns_ok`, and whether any peer
answers at all) and two from the peer (`external_reachable`, `dns_ok`) resolve it:

  peer unreachable                  -> LOCAL_MACHINE
      Nothing on the LAN answers, including a machine that was answering
      minutes ago. Our own link is the thing that changed.

  peer fine, we can't get out       -> LOCAL_MACHINE
      The LAN works, the peer's internet works, ours doesn't. Route, firewall,
      VPN, or interface -- but ours.

  peer also can't get out           -> UPSTREAM_OUTAGE
      Two machines, same symptom, independent stacks. Router, modem or ISP.

  only DNS broken here              -> LOCAL_DNS
      We can open TCP to an address but cannot resolve names, while the peer
      resolves fine. Our resolver configuration, cache, or /etc/resolver.

  DNS broken on both               -> DNS_OUTAGE
      Both machines reach addresses and neither can resolve. The resolver they
      share -- usually the router's, or whatever DHCP handed out.

Pure logic with no I/O, so every branch is testable without a network. Verdicts
are deliberately coarse: four causes a person can act on, not a probability
distribution. Where the evidence does not support a verdict it says
`INCONCLUSIVE` and why, rather than guessing -- a confident wrong answer here
sends someone to reboot the wrong thing.
"""

from typing import Optional

LOCAL_MACHINE = "local_machine"
LOCAL_NETWORK = "local_network"
LOCAL_DNS = "local_dns"
DNS_OUTAGE = "dns_outage"
UPSTREAM_OUTAGE = "upstream_outage"
INCONCLUSIVE = "inconclusive"

# What each verdict means, in the words the window and the forensic log use.
SUMMARIES = {
    LOCAL_MACHINE: "This machine",
    LOCAL_NETWORK: "The local network",
    LOCAL_DNS: "DNS resolution on this machine",
    DNS_OUTAGE: "DNS resolution for the whole network",
    UPSTREAM_OUTAGE: "Upstream of this network (router, modem or ISP)",
    INCONCLUSIVE: "Not determined",
}


def localize(
    our_external_reachable: Optional[bool],
    our_dns_ok: Optional[bool],
    peers: Optional[list] = None,
) -> dict:
    """Return {verdict, summary, confidence, reason, evidence}.

    `peers` is a list of dicts as recorded by peers.py, each optionally carrying
    `external_reachable` and `dns_ok`. A peer that answered recently but reports
    neither is still useful -- it proves the LAN works.
    """
    reachable = [p for p in (peers or []) if p.get("answered")]
    informative = [
        p
        for p in reachable
        if p.get("external_reachable") is not None or p.get("dns_ok") is not None
    ]

    evidence = {
        "our_external_reachable": our_external_reachable,
        "our_dns_ok": our_dns_ok,
        "peers_asked": len(peers or []),
        "peers_answered": len(reachable),
        "peers_reporting_state": len(informative),
    }

    # Nothing wrong that we can see. Say so rather than inventing a cause.
    if our_external_reachable is not False and our_dns_ok is not False:
        return _verdict(
            INCONCLUSIVE,
            "low",
            "Nothing is currently failing on this machine, so there is nothing to locate.",
            evidence,
        )

    if not peers:
        return _verdict(
            INCONCLUSIVE,
            "low",
            "No peer is known on this network, so there is nothing to compare against. "
            "Run the monitor on a second machine to make this answerable.",
            evidence,
        )

    if not reachable:
        # Every known peer went silent at the same time as our connectivity. The
        # shared element is our own link.
        return _verdict(
            LOCAL_MACHINE,
            "high",
            f"None of the {len(peers)} known peer(s) answered. A peer on the same "
            "network is reachable without leaving the LAN, so losing all of them "
            "at once points at this machine's own link rather than anything "
            "beyond the router.",
            evidence,
        )

    peer_external = _consensus(informative, "external_reachable")
    peer_dns = _consensus(informative, "dns_ok")
    evidence["peer_external_reachable"] = peer_external
    evidence["peer_dns_ok"] = peer_dns

    # --- the network layer -------------------------------------------------
    if our_external_reachable is False:
        if peer_external is True:
            return _verdict(
                LOCAL_MACHINE,
                "high",
                "A peer on this network reached the internet at the same moment "
                "this machine could not. The LAN and the upstream link are both "
                "working, so the fault is on this machine -- interface, route, "
                "firewall or VPN.",
                evidence,
            )
        if peer_external is False:
            return _verdict(
                UPSTREAM_OUTAGE,
                "high",
                "A peer on this network cannot reach the internet either. Two "
                "machines with independent network stacks failing the same check "
                "puts the fault upstream of both -- router, modem or ISP.",
                evidence,
            )
        # The peer answered, so the LAN is intact, but it did not say whether it
        # can get out. That still rules out this machine's link.
        return _verdict(
            LOCAL_NETWORK,
            "medium",
            "A peer on this network answered, so this machine's link and the LAN "
            "are working -- but the peer did not report whether it can reach the "
            "internet, so this cannot distinguish a router problem from an ISP "
            "one. Upgrade the peer to report its state for a sharper answer.",
            evidence,
        )

    # --- the DNS layer -----------------------------------------------------
    if peer_dns is True:
        return _verdict(
            LOCAL_DNS,
            "high",
            "This machine can open connections by address but cannot resolve "
            "names, while a peer on the same network resolves them fine. That is "
            "this machine's resolver configuration, its cache, or an "
            "/etc/resolver override -- not the network.",
            evidence,
        )
    if peer_dns is False:
        return _verdict(
            DNS_OUTAGE,
            "high",
            "Neither this machine nor a peer can resolve names, while addresses "
            "are still reachable. The resolver they share is the fault -- usually "
            "whatever DHCP handed out, often the router itself.",
            evidence,
        )
    return _verdict(
        LOCAL_DNS,
        "medium",
        "This machine cannot resolve names but can still reach addresses, and no "
        "peer reported its own DNS state. A resolver problem on this machine is "
        "the most likely cause, but a peer reporting its DNS state would settle it.",
        evidence,
    )


def _consensus(peers: list, field: str) -> Optional[bool]:
    """True/False only when every peer that reported agrees; None otherwise.

    Disagreement between peers is not a tiebreak to win -- it means the peers are
    not in the same situation, and the honest answer is that this signal cannot
    be used. Returning a majority verdict here would manufacture confidence.
    """
    values = [p.get(field) for p in peers if p.get(field) is not None]
    if not values:
        return None
    first = bool(values[0])
    return first if all(bool(v) == first for v in values) else None


def _verdict(verdict: str, confidence: str, reason: str, evidence: dict) -> dict:
    return {
        "verdict": verdict,
        "summary": SUMMARIES[verdict],
        "confidence": confidence,
        "reason": reason,
        "evidence": evidence,
    }
