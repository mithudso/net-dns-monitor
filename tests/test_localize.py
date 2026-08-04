"""Fault localization: the decision matrix that turns "the internet is broken"
into a specific thing to go and fix.

Pure logic, so every branch is covered without a network. The point of most of
these is not that the happy path works -- it is that the verdict is *specific*
and that the module refuses to guess when the evidence does not support one.
"""

import pytest

from netdnsmonitor.localize import (
    DNS_OUTAGE,
    INCONCLUSIVE,
    LOCAL_DNS,
    LOCAL_MACHINE,
    LOCAL_NETWORK,
    UPSTREAM_OUTAGE,
    localize,
)


def peer(answered=True, external=None, dns=None, host="mac-b"):
    return {
        "host": host,
        "answered": answered,
        "external_reachable": external,
        "dns_ok": dns,
    }


# --- nothing to locate -----------------------------------------------------


def test_a_healthy_machine_gets_no_verdict():
    """Asked when nothing is wrong, the honest answer is "nothing to locate" --
    not a cause invented for a symptom that does not exist.
    """
    result = localize(our_external_reachable=True, our_dns_ok=True, peers=[peer(external=True)])
    assert result["verdict"] == INCONCLUSIVE
    assert result["confidence"] == "low"


def test_unknown_own_state_is_not_treated_as_a_failure():
    """`dns_ok` is None when `domains` is empty -- the documented config foot-gun.
    Unknown must not be read as broken, or an empty domains list would produce a
    confident verdict about an outage that is not happening.
    """
    result = localize(our_external_reachable=True, our_dns_ok=None, peers=[peer(external=True)])
    assert result["verdict"] == INCONCLUSIVE


def test_no_peers_means_the_question_cannot_be_answered():
    """One machine genuinely cannot tell these cases apart. Saying so, and saying
    what would fix it, beats a guess.
    """
    result = localize(our_external_reachable=False, our_dns_ok=None, peers=[])
    assert result["verdict"] == INCONCLUSIVE
    assert "second machine" in result["reason"]


# --- the network layer -----------------------------------------------------


def test_every_peer_silent_points_at_this_machine():
    """A peer is reachable without leaving the LAN. Losing all of them at the
    same moment as connectivity means our own link is what changed.
    """
    result = localize(
        our_external_reachable=False,
        our_dns_ok=None,
        peers=[peer(answered=False), peer(answered=False, host="mac-c")],
    )
    assert result["verdict"] == LOCAL_MACHINE
    assert result["confidence"] == "high"
    assert result["evidence"]["peers_answered"] == 0


def test_a_working_peer_while_we_are_cut_off_points_at_this_machine():
    result = localize(
        our_external_reachable=False, our_dns_ok=None, peers=[peer(external=True, dns=True)]
    )
    assert result["verdict"] == LOCAL_MACHINE
    assert result["confidence"] == "high"
    assert "interface, route, firewall or VPN" in result["reason"]


def test_a_peer_equally_cut_off_points_upstream():
    """Two independent network stacks failing the same check is the strongest
    signal available that the fault is beyond both.
    """
    result = localize(our_external_reachable=False, our_dns_ok=None, peers=[peer(external=False)])
    assert result["verdict"] == UPSTREAM_OUTAGE
    assert result["confidence"] == "high"


def test_a_peer_that_answers_but_reports_nothing_still_rules_out_this_machine():
    """An older peer, or one that has not probed yet. It proves the LAN is intact,
    which is worth a medium-confidence answer rather than nothing at all.
    """
    result = localize(our_external_reachable=False, our_dns_ok=None, peers=[peer()])
    assert result["verdict"] == LOCAL_NETWORK
    assert result["confidence"] == "medium"


def test_a_silent_peer_is_ignored_when_another_one_answers():
    """A switched-off machine must not be counted as evidence of an outage."""
    result = localize(
        our_external_reachable=False,
        our_dns_ok=None,
        peers=[peer(answered=False, host="asleep"), peer(external=True, host="awake")],
    )
    assert result["verdict"] == LOCAL_MACHINE
    assert result["evidence"]["peers_answered"] == 1


# --- the DNS layer ---------------------------------------------------------


def test_dns_broken_here_but_not_on_the_peer_is_a_local_resolver_problem():
    result = localize(
        our_external_reachable=True, our_dns_ok=False, peers=[peer(external=True, dns=True)]
    )
    assert result["verdict"] == LOCAL_DNS
    assert result["confidence"] == "high"
    assert "/etc/resolver" in result["reason"]


def test_dns_broken_on_both_is_a_shared_resolver_problem():
    result = localize(
        our_external_reachable=True, our_dns_ok=False, peers=[peer(external=True, dns=False)]
    )
    assert result["verdict"] == DNS_OUTAGE
    assert result["confidence"] == "high"
    assert "share" in result["reason"]


def test_dns_broken_here_with_a_silent_peer_dns_state_is_only_medium():
    result = localize(our_external_reachable=True, our_dns_ok=False, peers=[peer(external=True)])
    assert result["verdict"] == LOCAL_DNS
    assert result["confidence"] == "medium"


def test_the_network_layer_is_decided_before_the_dns_layer():
    """If we cannot reach an address at all, "DNS is also failing" is a symptom,
    not the cause. Reporting LOCAL_DNS here would send someone to the wrong
    subsystem.
    """
    result = localize(
        our_external_reachable=False, our_dns_ok=False, peers=[peer(external=True, dns=True)]
    )
    assert result["verdict"] == LOCAL_MACHINE


# --- disagreement between peers -------------------------------------------


def test_peers_that_disagree_do_not_produce_a_majority_verdict():
    """Disagreement means the peers are not in the same situation, so the signal
    is unusable. A majority vote here would manufacture confidence -- and with two
    peers there is no majority to have.
    """
    result = localize(
        our_external_reachable=False,
        our_dns_ok=None,
        peers=[peer(external=True, host="a"), peer(external=False, host="b")],
    )
    assert result["verdict"] == LOCAL_NETWORK
    assert result["confidence"] == "medium"
    assert result["evidence"]["peer_external_reachable"] is None


def test_peers_that_agree_are_used():
    result = localize(
        our_external_reachable=False,
        our_dns_ok=None,
        peers=[peer(external=False, host="a"), peer(external=False, host="b")],
    )
    assert result["verdict"] == UPSTREAM_OUTAGE
    assert result["evidence"]["peer_external_reachable"] is False


# --- shape -----------------------------------------------------------------


@pytest.mark.parametrize(
    "external,dns,peers",
    [
        (False, None, []),
        (False, None, [peer(answered=False)]),
        (False, None, [peer(external=True)]),
        (False, None, [peer(external=False)]),
        (True, False, [peer(external=True, dns=True)]),
        (True, False, [peer(external=True, dns=False)]),
        (True, True, [peer()]),
        (None, None, None),
    ],
)
def test_every_path_returns_a_complete_verdict(external, dns, peers):
    """These land in a forensic document and a window. A missing key would raise
    at render time, inside an AppKit callback where the traceback is invisible.
    """
    result = localize(external, dns, peers)
    assert set(result) == {"verdict", "summary", "confidence", "reason", "evidence"}
    assert result["summary"]
    assert result["reason"]
    assert result["confidence"] in ("low", "medium", "high")


def test_evidence_records_what_was_actually_asked():
    """The verdict is a judgement; the evidence is what it was based on. A reader
    six months later needs the second one to trust the first.
    """
    result = localize(
        our_external_reachable=False,
        our_dns_ok=True,
        peers=[peer(external=True), peer(answered=False, host="off")],
    )
    assert result["evidence"]["peers_asked"] == 2
    assert result["evidence"]["peers_answered"] == 1
    assert result["evidence"]["peers_reporting_state"] == 1
    assert result["evidence"]["our_external_reachable"] is False
