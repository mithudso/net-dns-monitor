"""Work out *where* an outage is, by comparing what this machine sees with what a
peer on the same LAN sees.

One machine cannot tell these apart. "I can't reach the internet" looks identical
whether the Wi-Fi card has wedged, the router is down, the ISP is out, or DNS
alone is broken. A second machine on the same network is the missing reference:
if it is fine, the fault is on this side; if it is equally broken, it is upstream
of both.

Three signals from us (`external_reachable`, `dns_ok`, and whether any peer
answers at all) and two from the peer (`external_reachable`, `dns_ok`) resolve it:

  peer unreachable, we can't get out -> LOCAL_MACHINE
      Nothing on the LAN answers, including a machine that was answering
      minutes ago, and our external check fails too. Our own link is the
      thing that changed. If we can still get out, silent peers say nothing
      about our link, and the DNS layer decides instead. Resting on a single
      silent peer, this is only medium confidence: that peer may be asleep.

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
    # Hedged on purpose: the verdict is only returned when no peer gives a usable
    # internet answer, which leaves this machine's route and everything beyond the
    # LAN both possible. "The local network" read as a finding.
    LOCAL_NETWORK: "Undetermined: this machine's route or the network beyond it",
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
    supplied = list(peers or [])
    reachable = [p for p in supplied if p.get("answered") is True]
    # Explicitly reported as not answering, as opposed to not saying either way.
    # The distinction carries a whole verdict: "every peer went silent" is the
    # high-confidence LOCAL_MACHINE signal below, and a caller that simply omits
    # the key would otherwise trigger it. Passing raw registry dicts instead of
    # PeerRegistry.localization_view() produced exactly that -- a peer reporting
    # itself perfectly healthy yielded "this machine", at high confidence.
    silent = [p for p in supplied if p.get("answered") is False]
    informative = [
        p
        for p in reachable
        if p.get("external_reachable") is not None or p.get("dns_ok") is not None
    ]

    evidence = {
        "our_external_reachable": our_external_reachable,
        "our_dns_ok": our_dns_ok,
        # "known", not "asked": nothing here sends a probe, and the count
        # includes peers with no address that could not have been asked.
        "peers_known": len(supplied),
        "peers_answered": len(reachable),
        "peers_reporting_state": len(informative),
    }

    # Nothing wrong that we can see. Say so rather than inventing a cause -- and
    # say what "see" rests on, because (None, None) is "not probed yet", not
    # "probed and healthy".
    if our_external_reachable is not False and our_dns_ok is not False:
        if our_external_reachable is None and our_dns_ok is None:
            reason = "This machine has not been probed yet, so there is nothing to compare."
        else:
            reason = (
                "This machine's most recent probe "
                f"(external_reachable={our_external_reachable}, dns_ok={our_dns_ok}) "
                "showed no failure, so there is nothing to locate."
            )
        return _verdict(INCONCLUSIVE, "low", reason, evidence)

    if not peers:
        # "Heard from", not "known": the registry keeps month-old records, and
        # this branch is reached with sixteen of them on file. Telling that
        # reader no peer is known sends them to install a monitor they have.
        return _verdict(
            INCONCLUSIVE,
            "low",
            "No peer on this network has been heard from within the current window, "
            "so there is nothing to compare against. A second machine running the "
            "monitor, and reachable, would make this answerable.",
            evidence,
        )

    if not reachable and not silent:
        # Peers were supplied but none of them says whether it answered, so the
        # strongest signal available is unusable. Refusing to guess here is the
        # whole point: the alternative reading of this state is a high-confidence
        # "this machine", which is the wrong thing to tell someone.
        return _verdict(
            INCONCLUSIVE,
            "low",
            f"{len(supplied)} peer(s) were supplied but none reports whether it "
            "answered, so this cannot tell 'the LAN is fine' from 'nothing on the "
            "LAN is reachable'. Pass PeerRegistry.localization_view(), which sets "
            "that flag.",
            evidence,
        )

    if not reachable and our_external_reachable is False:
        # Every known peer went silent at the same time as our connectivity. The
        # shared element is our own link. Only a failed external check supplies
        # the "our connectivity" half: when addresses are reachable, or the check
        # was not probed, silent peers are not evidence against the link, and
        # the DNS layer below decides with no peer state to lean on.
        reason = (
            f"None of the {len(silent)} known peer(s) answered. A peer on the same "
            "network is reachable without leaving the LAN, so losing all of them "
            "at once points at this machine's own link rather than anything "
            "beyond the router."
        )
        # One silence cannot tell "our link died" from "that machine went to
        # sleep". A peer stays in the `current` window for minutes after its lid
        # closes, so during an ISP outage a lone sleeping laptop would otherwise
        # yield "this machine" at high confidence -- sending someone to reboot the
        # wrong thing. Two or more peers going quiet at the same moment is far
        # less likely to be coincidental sleep, so they keep high confidence.
        if len(silent) < 2:
            return _verdict(
                LOCAL_MACHINE,
                "medium",
                reason + " This rests on a single silent peer, though, and a single "
                "peer may simply be asleep or switched off, so an outage beyond the "
                "router is not ruled out.",
                evidence,
            )
        return _verdict(LOCAL_MACHINE, "high", reason, evidence)

    peer_external = _consensus(informative, "external_reachable")
    # A peer that cannot get out cannot vouch for or against a resolver: its DNS
    # failure is a symptom of its own outage, the same rule the network layer
    # below applies to this machine. Counting it would turn one peer behind a
    # blocked VPN into a high-confidence "the shared resolver is down".
    dns_witnesses = [p for p in informative if p.get("external_reachable") is not False]
    peer_dns = _consensus(dns_witnesses, "dns_ok")
    # Peers that reported DNS but were set aside above; the fallthrough reasons
    # must not call them "no peer reported".
    excluded = [
        p
        for p in informative
        if p.get("external_reachable") is False and p.get("dns_ok") is not None
    ]
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
        # A peer answered, so the LAN is reachable from here, but no usable peer
        # report says whether the internet is (none reported, or they disagree).
        # That does not rule out this machine's route, firewall or VPN, so the
        # reason lists every cause that is still possible.
        return _verdict(
            LOCAL_NETWORK,
            "medium",
            "A peer on this network answered, so the LAN is reachable from this "
            "machine. The peers gave no single answer about whether they can reach "
            "the internet (none reported it, or they disagree), so the fault could "
            "still be this machine's route, firewall or VPN, the router, or the ISP. "
            "Upgrade the peers to report their state for a sharper answer.",
            evidence,
        )

    # --- the DNS layer -----------------------------------------------------
    # Only True or None reach here. None means external reachability was not
    # probed, so no reason below may claim this machine reaches addresses, and
    # no verdict that would rest on that claim may be high confidence.
    if our_external_reachable is None:
        if peer_dns is True:
            return _verdict(
                LOCAL_DNS,
                "medium",
                "This machine cannot resolve names, while a peer on the same "
                "network resolves them fine. External reachability was not probed "
                "here, so a wider connectivity fault is not ruled out, but the "
                "likeliest cause is this machine's resolver configuration, its "
                "cache, or an /etc/resolver override.",
                evidence,
            )
        if peer_dns is False:
            return _verdict(
                DNS_OUTAGE,
                "medium",
                "Neither this machine nor a peer can resolve names. External "
                "reachability was not probed here, so a wider outage is not ruled "
                "out, but the likeliest fault is the resolver they share -- usually "
                "whatever DHCP handed out, often the router itself.",
                evidence,
            )
        return _verdict(
            LOCAL_DNS,
            "medium",
            "This machine cannot resolve names, external reachability was not "
            f"probed, and {_dns_witness_note(excluded)}. A resolver problem on "
            "this machine is possible, but so is a wider connectivity fault.",
            evidence,
        )

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
        "This machine cannot resolve names but can still reach addresses, and "
        f"{_dns_witness_note(excluded)}. A resolver problem on this machine is "
        "the most likely cause, but a peer reporting its DNS state would settle it.",
        evidence,
    )


def _dns_witness_note(excluded: list) -> str:
    """Why no peer's DNS reading was usable: none reported, or all were set aside."""
    if not excluded:
        return "no peer reported its own DNS state"
    return (
        f"{len(excluded)} peer(s) reported DNS but cannot reach the internet "
        "themselves, so their DNS reading says nothing about the resolver"
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
