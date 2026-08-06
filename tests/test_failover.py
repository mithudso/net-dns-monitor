"""No subprocess, no sockets, no real network config. A FakeRunner stands in
for `networksetup` and keeps a mutable service order that the reorder command
actually rewrites, so the read-back verification is exercised for real.
"""

import json
from types import SimpleNamespace

import pytest

from netdnsmonitor.failover import FailoverStore, NetworkFailover

ORDER = [
    "AX88179B",
    "USB 10/100/1000 LAN",
    "USB 10/100/1G/2.5G LAN",
    "M3100",
    "Thunderbolt Bridge",
    "Wi-Fi",
    "iPhone USB",
]
DEVICES = {
    "AX88179B": "en6",
    "USB 10/100/1000 LAN": "en7",
    "USB 10/100/1G/2.5G LAN": "en9",
    "M3100": "en12",
    "Thunderbolt Bridge": "bridge0",
    "Wi-Fi": "en0",
    "iPhone USB": "en11",
}
DISABLED = {"USB 10/100/1G/2.5G LAN", "M3100"}


class FakeRunner:
    """Reproduces the two networksetup calls this module makes."""

    def __init__(self, order=None, apply_result=None, list_fails=False, obey=True):
        self.order = list(order or ORDER)
        self.apply_result = apply_result
        self.list_fails = list_fails
        self.obey = obey  # False = exit 0 but ignore the request
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        if args[:2] == ["networksetup", "-listnetworkserviceorder"]:
            if self.list_fails:
                return SimpleNamespace(returncode=1, stdout="", stderr="boom")
            return SimpleNamespace(returncode=0, stdout=self._listing(), stderr="")
        if args[:2] == ["networksetup", "-ordernetworkservices"]:
            if self.apply_result is not None:
                return self.apply_result
            if self.obey:
                self.order = list(args[2:])
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    def _listing(self):
        lines = ["An asterisk (*) denotes that a network service is disabled."]
        position = 0
        for name in self.order:
            if name in DISABLED:
                marker = "*"
            else:
                position += 1
                marker = str(position)
            lines.append(f"({marker}) {name}")
            lines.append(f"(Hardware Port: {name}, Device: {DEVICES[name]})")
            lines.append("")
        return "\n".join(lines)

    @property
    def applied_orders(self):
        return [c[2:] for c in self.calls if c[:2] == ["networksetup", "-ordernetworkservices"]]


@pytest.fixture
def store(tmp_path):
    return FailoverStore(str(tmp_path / "failover.json"))


def build(store, runner, prober=None, **kwargs):
    defaults = dict(
        preferred_service="AX88179B",
        backup_service="Wi-Fi",
        store=store,
        interface_prober=prober or (lambda dev: {"en6": False, "en0": True}.get(dev)),
        run_fn=runner,
        failback_threshold=3,
        cooldown_seconds=0.0,
        max_switches_per_hour=4,
        time_fn=lambda: 1_000_000.0,
    )
    defaults.update(kwargs)
    return NetworkFailover(**defaults)


# --- failover ---------------------------------------------------------------


def test_failover_promotes_the_backup_and_keeps_every_service():
    runner = FakeRunner()
    outcome = build(store=FailoverStore("/dev/null/nope"), runner=runner).attempt_failover("network")
    assert outcome.startswith("ok:")
    applied = runner.applied_orders[0]
    assert applied[0] == "Wi-Fi"
    assert sorted(applied) == sorted(ORDER), "no service may be dropped"
    assert len(applied) == 7


def test_failover_records_the_exact_pre_failover_order(store):
    runner = FakeRunner()
    build(store, runner).attempt_failover("network")
    assert store.original_order == ORDER


def test_no_failover_when_backup_is_also_down(store):
    runner = FakeRunner()
    failover = build(store, runner, prober=lambda dev: False)
    outcome = failover.attempt_failover("network")
    assert outcome.startswith("no switch:")
    assert runner.applied_orders == []


def test_no_failover_on_a_dns_incident_by_default(store):
    runner = FakeRunner()
    outcome = build(store, runner).attempt_failover("dns")
    assert outcome.startswith("no switch:")
    assert runner.applied_orders == []


def test_failover_is_a_no_op_when_already_on_the_backup(store):
    runner = FakeRunner(order=["Wi-Fi"] + [n for n in ORDER if n != "Wi-Fi"])
    outcome = build(store, runner).attempt_failover("network")
    assert outcome == "no switch: already on the backup network"
    assert runner.applied_orders == []


def test_already_on_backup_costs_no_interface_probe(store):
    """The short-circuit must happen before probing, not after."""
    probes = []
    runner = FakeRunner(order=["Wi-Fi"] + [n for n in ORDER if n != "Wi-Fi"])
    build(store, runner, prober=lambda dev: probes.append(dev) or True).attempt_failover("network")
    assert probes == []


# --- honesty about what actually happened -----------------------------------


def test_exit_zero_without_a_change_is_reported_as_failure(store):
    """networksetup can succeed and do nothing; the order is read back."""
    runner = FakeRunner(obey=False)
    outcome = build(store, runner).attempt_failover("network")
    assert outcome.startswith("failed:")
    assert "unchanged" in outcome


def test_privilege_refusal_is_labelled_needs_privilege(store):
    runner = FakeRunner(
        apply_result=SimpleNamespace(
            returncode=1, stdout="", stderr="You must be running as root to use this command."
        )
    )
    outcome = build(store, runner).attempt_failover("network")
    assert outcome.startswith("NEEDS_PRIVILEGE:")


def test_other_failures_are_not_labelled_needs_privilege(store):
    runner = FakeRunner(
        apply_result=SimpleNamespace(returncode=2, stdout="", stderr="bogus service name")
    )
    outcome = build(store, runner).attempt_failover("network")
    assert outcome.startswith("failed:")
    assert "NEEDS_PRIVILEGE" not in outcome


def test_a_failed_switch_spends_no_budget_but_still_arms_the_cooldown(store):
    """Failures should slow switching down without using up the user's ability
    to switch once it would finally work.
    """
    runner = FakeRunner(obey=False)
    build(store, runner).attempt_failover("network")
    assert store.switch_times == [], "budget is for switches that happened"
    assert store.last_switch_at == 1_000_000.0, "cooldown must space out the retry"


def test_a_persistently_failing_failback_does_not_retry_every_tick(store):
    """The mirror of the stuck-gate bug: while genuinely on the backup, the
    self-heal cannot fire, so nothing but the cooldown stops a failing failback
    from re-running the full reorder on every single poll.
    """
    now = [1_000_000.0]
    runner = failed_over(store)
    runner.obey = False  # every subsequent reorder silently does nothing
    failover = build(
        store, runner, prober=lambda dev: True, cooldown_seconds=900.0,
        time_fn=lambda: now[0],
    )
    # Clear the successful failover's own cooldown, then earn the streak and
    # let the first (doomed) failback attempt happen.
    now[0] += 901
    for _ in range(3):
        failover.attempt_failback()
    assert len(runner.applied_orders) == 2, "one failover + one failed failback"

    # Twenty more ticks, 30s apart: 600s total, well inside the fresh 900s
    # cooldown armed by the failed attempt.
    for _ in range(20):
        now[0] += 30
        failover.attempt_failback()
    assert len(runner.applied_orders) == 2, "cooldown must hold off the retry"

    # Past it, exactly one more attempt -- not one per tick.
    now[0] += 301
    failover.attempt_failback()
    assert len(runner.applied_orders) == 3


# --- hostile state file -----------------------------------------------------


def test_nan_timestamps_cannot_disable_the_rate_brakes(tmp_path):
    """json.load accepts bare NaN, and every comparison against NaN is False --
    which would read as "cooldown expired" and "budget window empty" at once.
    """
    path = tmp_path / "failover.json"
    path.write_text('{"last_switch_at": NaN, "switch_times": [NaN, Infinity]}')
    store = FailoverStore(str(path))
    assert store.last_switch_at is None
    assert store.switch_times == []


def test_boolean_timestamps_are_rejected(tmp_path):
    path = tmp_path / "failover.json"
    path.write_text('{"last_switch_at": true, "switch_times": [true]}')
    store = FailoverStore(str(path))
    assert store.last_switch_at is None
    assert store.switch_times == []


def test_unreadable_service_list_fails_loudly(store):
    runner = FakeRunner(list_fails=True)
    outcome = build(store, runner).attempt_failover("network")
    assert outcome.startswith("failed:")
    assert runner.applied_orders == []


def test_unknown_service_name_lists_what_is_available(store):
    runner = FakeRunner()
    outcome = build(store, runner, preferred_service="Ethernet").attempt_failover("network")
    assert outcome.startswith("failed:")
    assert "not found" in outcome
    assert "AX88179B" in outcome  # the available list
    assert runner.applied_orders == []


def test_unknown_backup_never_reorders(store):
    runner = FakeRunner()
    outcome = build(store, runner, backup_service="AirPort").attempt_failover("network")
    assert outcome.startswith("failed:")
    assert runner.applied_orders == []


# --- failback ---------------------------------------------------------------


def failed_over(store, **kwargs):
    """Put the system in the post-failover state the way the app would."""
    runner = FakeRunner()
    build(store, runner, **kwargs).attempt_failover("network")
    return runner


def test_failback_restores_the_original_order_exactly(store):
    runner = failed_over(store)
    failover = build(store, runner, prober=lambda dev: True)
    for _ in range(3):  # earn the streak
        outcome = failover.attempt_failback()
    assert outcome.startswith("ok:")
    assert runner.order == ORDER, "Wi-Fi must go back to position 6, not stay second"


def test_failback_waits_for_the_full_streak(store):
    runner = failed_over(store)
    failover = build(store, runner, prober=lambda dev: True)
    assert failover.attempt_failback() is None
    assert failover.attempt_failback() is None
    assert failover.attempt_failback().startswith("ok:")


def test_streak_resets_when_preferred_flaps(store):
    runner = failed_over(store)
    flap = iter([True, True, False, True, True, True])
    failover = build(store, runner, prober=lambda dev: next(flap))
    outcomes = [failover.attempt_failback() for _ in range(6)]
    assert outcomes[:5] == [None, None, None, None, None]
    assert outcomes[5].startswith("ok:")


def test_no_failback_while_preferred_adapter_is_absent(store):
    runner = failed_over(store)
    failover = build(store, runner, prober=lambda dev: None)
    for _ in range(5):
        assert failover.attempt_failback() is None
    assert runner.order[0] == "Wi-Fi"


def test_failback_clears_the_recorded_order(store):
    runner = failed_over(store)
    failover = build(store, runner, prober=lambda dev: True)
    for _ in range(3):
        failover.attempt_failback()
    assert store.original_order is None


def test_failback_is_skipped_entirely_when_never_failed_over(store):
    """The cheap gate: no subprocess and no probe on an ordinary healthy tick."""
    runner = FakeRunner()
    probes = []
    failover = build(store, runner, prober=lambda dev: probes.append(dev) or True)
    assert failover.attempt_failback() is None
    assert runner.calls == []
    assert probes == []


def test_a_refused_switch_does_not_leave_the_failback_gate_stuck_open(store):
    """The pre-failover order is recorded *before* the write, so that a switch
    whose read-back fails can still be undone. The cost of that is a record
    left behind when the write is refused outright -- which on a locked-down
    machine is every time. If it is never cleared, the cheap failback gate is
    permanently open and every healthy tick spends a networksetup subprocess on
    the UI thread, forever, across restarts.
    """
    runner = FakeRunner(
        apply_result=SimpleNamespace(
            returncode=1, stdout="", stderr="You must be running as root to use this command."
        )
    )
    # Default prober: preferred down, backup up -- the state that warrants a switch.
    failover = build(store, runner)
    assert failover.attempt_failover("network").startswith("NEEDS_PRIVILEGE:")
    assert store.original_order is not None, "record is written before the attempt"

    # One tick is enough to notice we are still on preferred and self-heal.
    runner.calls.clear()
    assert failover.attempt_failback() is None
    assert store.original_order is None

    # And from then on the gate is shut: no subprocess at all.
    runner.calls.clear()
    assert failover.attempt_failback() is None
    assert runner.calls == []


def test_self_heal_does_not_discard_a_real_failover(store):
    """Clearing must key off the live order, not the outcome string: a switch
    that landed but could not be read back still needs its record kept.
    """
    runner = failed_over(store)
    assert runner.order[0] == "Wi-Fi"
    failover = build(store, runner, prober=lambda dev: False)
    assert failover.attempt_failback() is None
    assert store.original_order == ORDER, "still on backup -- the record must survive"


def test_manual_reorder_back_to_preferred_clears_the_record(store):
    """The user fixed it by hand while we were failed over."""
    runner = failed_over(store)
    runner.order = list(ORDER)
    failover = build(store, runner, prober=lambda dev: True)
    assert failover.attempt_failback() is None
    assert store.original_order is None


def test_stale_recorded_order_falls_back_to_promote_and_says_so(store):
    """A service was removed while failed over: the record can no longer be
    applied without inventing a name, so the preferred link is promoted and the
    substitution is stated.
    """
    runner = failed_over(store)
    runner.order = [n for n in runner.order if n != "M3100"]
    failover = build(store, runner, prober=lambda dev: True)
    for _ in range(3):
        outcome = failover.attempt_failback()
    assert outcome.startswith("ok:")
    assert "no longer matches" in outcome
    assert runner.order[0] == "AX88179B"
    assert "M3100" not in runner.order


# --- rate brakes ------------------------------------------------------------


def test_cooldown_blocks_a_second_switch(store):
    runner = FakeRunner()
    failover = build(store, runner, cooldown_seconds=300.0)
    assert failover.attempt_failover("network").startswith("ok:")
    runner.order = list(ORDER)  # pretend the link came back and order reverted
    outcome = failover.attempt_failover("network")
    assert outcome.startswith("no switch:")
    assert "cooldown" in outcome


def test_budget_exhaustion_stops_switching(store):
    now = [1_000_000.0]
    runner = FakeRunner()
    failover = build(
        store, runner, cooldown_seconds=0.0, max_switches_per_hour=2,
        time_fn=lambda: now[0],
    )
    for _ in range(2):
        assert failover.attempt_failover("network").startswith("ok:")
        runner.order = list(ORDER)
        now[0] += 1
    outcome = failover.attempt_failover("network")
    assert "budget exhausted" in outcome


# --- persistence ------------------------------------------------------------


def test_state_survives_a_restart(tmp_path):
    path = str(tmp_path / "failover.json")
    runner = FakeRunner()
    build(FailoverStore(path), runner).attempt_failover("network")

    reloaded = FailoverStore(path)
    assert reloaded.original_order == ORDER
    assert reloaded.last_switch_at == 1_000_000.0

    # A restart mid-outage must still be able to fail back.
    failover = build(reloaded, runner, prober=lambda dev: True)
    for _ in range(3):
        outcome = failover.attempt_failback()
    assert outcome.startswith("ok:")
    assert runner.order == ORDER


def test_corrupt_state_file_does_not_crash(tmp_path):
    path = tmp_path / "failover.json"
    path.write_text("{not json")
    store = FailoverStore(str(path))
    assert store.original_order is None
    assert store.switch_times == []


def test_state_file_with_wrong_types_is_ignored(tmp_path):
    path = tmp_path / "failover.json"
    path.write_text(json.dumps({"original_order": "nope", "switch_times": 5}))
    store = FailoverStore(str(path))
    assert store.original_order is None
    assert store.switch_times == []


def test_unwritable_state_path_does_not_raise():
    """Losing the record must degrade the feature, never kill the tick."""
    store = FailoverStore("/dev/null/cannot/exist/failover.json")
    store.original_order = ORDER
    store.save()  # must not raise
    runner = FakeRunner()
    assert build(store, runner).attempt_failover("network").startswith("ok:")
