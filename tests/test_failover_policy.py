"""The policy is where a wrong answer costs the most: a switch that should not
have happened rewrites the system's network order, and a switch that should
have happened leaves the user offline. Both directions are tested, including
every refusal reason.
"""

from netdnsmonitor.failover_policy import (
    BACKUP,
    FAILBACK,
    FAILOVER,
    NONE,
    PREFERRED,
    decide,
    next_preferred_streak,
)

NOW = 1_000_000.0


def failover_case(**overrides):
    kwargs = dict(
        active_side=PREFERRED,
        classification="network",
        preferred_ok=False,
        backup_ok=True,
        consecutive_preferred_ok=0,
        failback_threshold=3,
        now=NOW,
        last_switch_at=None,
        cooldown_seconds=300.0,
        switch_times=[],
        max_switches_per_hour=4,
    )
    kwargs.update(overrides)
    return decide(**kwargs)


def failback_case(**overrides):
    kwargs = dict(
        active_side=BACKUP,
        classification="healthy",
        preferred_ok=True,
        backup_ok=True,
        consecutive_preferred_ok=3,
    )
    kwargs.update(overrides)
    return failover_case(**kwargs)


# --- failover ---------------------------------------------------------------


def test_fails_over_when_preferred_is_down_and_backup_is_verified():
    decision = failover_case()
    assert decision.action == FAILOVER
    assert "backup verified reachable" in decision.reason


def test_no_failover_on_a_non_trigger_classification():
    """Configured default is network-only; a DNS fault must not move the link."""
    decision = failover_case(classification="dns")
    assert decision.action == NONE
    assert "not a failover trigger" in decision.reason


def test_dns_can_be_opted_into_as_a_trigger():
    decision = failover_case(
        classification="dns", trigger_classifications=frozenset({"network", "dns"})
    )
    assert decision.action == FAILOVER


def test_no_failover_when_backup_is_also_down():
    decision = failover_case(backup_ok=False)
    assert decision.action == NONE
    assert "trade one dead path for another" in decision.reason


def test_no_failover_when_backup_was_never_probed():
    """None is not False: an absent backup adapter is not a verified path."""
    decision = failover_case(backup_ok=None)
    assert decision.action == NONE
    assert "not probed" in decision.reason


def test_no_failover_when_preferred_answers_on_its_own_interface():
    decision = failover_case(preferred_ok=True)
    assert decision.action == NONE
    assert "not specific to this path" in decision.reason


def test_unprobed_preferred_still_allows_failover():
    """preferred_ok=None plus a network-classified outage plus a verified
    backup is still a good reason to move; only a positive reading blocks it.
    """
    assert failover_case(preferred_ok=None).action == FAILOVER


def test_cooldown_blocks_failover_and_says_how_long():
    decision = failover_case(last_switch_at=NOW - 60, cooldown_seconds=300)
    assert decision.action == NONE
    assert "cooldown" in decision.reason and "240s" in decision.reason


def test_failover_resumes_once_cooldown_expires():
    assert failover_case(last_switch_at=NOW - 301, cooldown_seconds=300).action == FAILOVER


def test_budget_exhaustion_blocks_failover():
    decision = failover_case(
        switch_times=[NOW - 10, NOW - 20, NOW - 30, NOW - 40], max_switches_per_hour=4
    )
    assert decision.action == NONE
    assert "budget exhausted" in decision.reason


def test_switches_older_than_an_hour_leave_the_budget_window():
    decision = failover_case(
        switch_times=[NOW - 3601, NOW - 4000, NOW - 5000, NOW - 6000],
        max_switches_per_hour=4,
    )
    assert decision.action == FAILOVER


def test_future_dated_switches_do_not_pin_the_budget():
    """A backwards clock jump (sleep/wake) must not strand the feature."""
    decision = failover_case(
        switch_times=[NOW + 500, NOW + 600, NOW + 700, NOW + 800],
        max_switches_per_hour=4,
    )
    assert decision.action == FAILOVER


def test_backwards_clock_jump_does_not_freeze_the_cooldown():
    decision = failover_case(last_switch_at=NOW + 10_000, cooldown_seconds=300)
    assert decision.action == FAILOVER


def test_zero_budget_disables_switching_entirely():
    decision = failover_case(max_switches_per_hour=0)
    assert decision.action == NONE
    assert "disabled" in decision.reason


def test_disabled_switching_is_not_reported_as_an_exhausted_budget():
    """A limit of 0 means switching is off; "0 switches, limit 0, exhausted"
    reads as a brake that will release, and it never will.
    """
    decision = failover_case(max_switches_per_hour=0)
    assert "disabled" in decision.reason
    assert "exhausted" not in decision.reason


def test_negative_budget_fails_closed_not_open():
    """A config typo must not silently remove the ceiling on a flapping link."""
    decision = failover_case(max_switches_per_hour=-4)
    assert decision.action == NONE
    # The limit actually enforced is 0, so the reason must not name -4.
    assert "-4" not in decision.reason


def test_an_unprobed_preferred_is_not_reported_as_unreachable():
    """None is not False: the reason must not claim a reading never taken."""
    decision = failover_case(preferred_ok=None)
    assert decision.action == FAILOVER
    assert "could not be probed" in decision.reason
    assert "unreachable" not in decision.reason


# --- failback ---------------------------------------------------------------


def test_fails_back_once_preferred_is_stable():
    decision = failback_case()
    assert decision.action == FAILBACK


def test_no_failback_before_the_streak_threshold():
    decision = failback_case(consecutive_preferred_ok=2, failback_threshold=3)
    assert decision.action == NONE
    assert "2/3 consecutive checks" in decision.reason


def test_zero_failback_threshold_still_requires_one_healthy_check():
    """The threshold is user-editable and reaches here unclamped. At 0 the
    first good probe would fail back on no evidence of stability at all --
    exactly the flap the streak exists to prevent.
    """
    assert failback_case(consecutive_preferred_ok=0, failback_threshold=0).action == NONE
    assert failback_case(consecutive_preferred_ok=0, failback_threshold=-3).action == NONE
    assert failback_case(consecutive_preferred_ok=1, failback_threshold=0).action == FAILBACK


def test_no_failback_while_preferred_is_still_down():
    decision = failback_case(preferred_ok=False)
    assert decision.action == NONE
    assert "still unreachable" in decision.reason


def test_no_failback_while_preferred_adapter_is_absent():
    decision = failback_case(preferred_ok=None)
    assert decision.action == NONE
    assert "absent" in decision.reason


def test_cooldown_blocks_failback_too():
    """Braking only one direction still permits a half-oscillation per cooldown."""
    decision = failback_case(last_switch_at=NOW - 10, cooldown_seconds=300)
    assert decision.action == NONE
    assert "cooldown" in decision.reason


def test_budget_exhaustion_leaves_us_resting_on_the_working_backup():
    decision = failback_case(
        switch_times=[NOW - 1, NOW - 2, NOW - 3, NOW - 4], max_switches_per_hour=4
    )
    assert decision.action == NONE
    assert "budget exhausted" in decision.reason


# --- streak counter ---------------------------------------------------------


def test_streak_advances_on_success():
    assert next_preferred_streak(2, True) == 3


def test_streak_resets_on_failure():
    assert next_preferred_streak(9, False) == 0


def test_streak_resets_when_interface_is_absent():
    """An adapter unplugged for an hour must not fail back on its first probe."""
    assert next_preferred_streak(9, None) == 0


def test_every_decision_carries_a_reason():
    for decision in (
        failover_case(),
        failover_case(backup_ok=False),
        failover_case(classification="healthy"),
        failback_case(),
        failback_case(preferred_ok=None),
    ):
        assert decision.reason
        assert decision.action in (NONE, FAILOVER, FAILBACK)
