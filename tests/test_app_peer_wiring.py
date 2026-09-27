"""Peer discovery as wired into the rumps shell.

Every test binds `peer_port` 0, so the OS picks a free port at bind time, and
substitutes loopback for the broadcast list, so nothing in the suite ever sends
a datagram onto a real network or collides with the installed app on the
default port.
"""

import pytest

from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.peers import CURRENT, load_record


class FakeFlapGate:
    def __init__(self, state="healthy", consecutive_failures=0):
        self.state = state
        self.consecutive_failures = consecutive_failures


class FakeStateMachine:
    def __init__(self, flap_state="healthy", consecutive_failures=0):
        self.flap_gate = FakeFlapGate(flap_state, consecutive_failures)

    def tick(self):
        return None


@pytest.fixture(autouse=True)
def _loopback_only(monkeypatch):
    monkeypatch.setattr("netdnsmonitor.peer_net.broadcast_addresses", lambda: ["127.0.0.1"])
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.show",
        # Signature must match: show() takes `activate`, and the launch path
        # passes activate=False so it does not steal focus at login.
        lambda self, activate=True: None,
    )


def make_app(tmp_path, **overrides):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()
    app.ping_job = lambda: ({"ok": True, "rtt_ms": 61.0, "error": None}, (0, 0))
    # 0, not a port probed for freeness first: another process can take a
    # probed port before the bind. start() reads the bound port back.
    app.config["peer_port"] = 0
    app.config["peer_record_path"] = str(tmp_path / "peers.json")
    app.config.update(overrides)
    return app


# --- startup is not blocked --------------------------------------------------


def test_constructing_the_app_opens_no_socket_and_starts_no_thread(tmp_path):
    """The requirement was explicitly that startup not block on any of this. It
    also keeps every other test that builds this class off the network.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert app.peer_network is None


def test_the_first_peer_tick_starts_discovery(tmp_path):
    app = make_app(tmp_path)
    app.peer_tick()
    try:
        assert app.peer_network is not None
        assert app.peer_network.started is True
    finally:
        app.peer_network.stop()


def test_discovery_can_be_turned_off_entirely(tmp_path):
    """It broadcasts this machine's hostname and health onto the LAN, so there has
    to be a switch that opens no socket at all.
    """
    app = make_app(tmp_path, peer_discovery_enabled=False)
    app.peer_tick()
    assert app.peer_network is None


def test_a_failed_bind_is_not_fatal_and_is_retried_next_tick(tmp_path, monkeypatch):
    """A monitor that will not run because a UDP port was busy has its priorities
    backwards.
    """
    calls = []
    real_start = None

    def failing_start(self):
        calls.append(1)
        self.start_error = "Address already in use"
        return False

    monkeypatch.setattr("netdnsmonitor.peer_net.PeerNetwork.start", failing_start)
    app = make_app(tmp_path)
    app.peer_tick()
    assert app.peer_network is None
    app.peer_tick()
    assert len(calls) == 2  # retried rather than given up on
    assert real_start is None


def test_a_network_whose_reader_died_is_rebuilt_on_the_next_tick(tmp_path):
    """`started` stays True after the reader thread ends. Checking only for None
    kept announcing from a dead listener, and discovery never came back.
    """
    app = make_app(tmp_path)
    app.peer_tick()
    dead = app.peer_network
    try:
        dead.socket.close()  # the reader thread exits when its socket goes away
        assert _wait(lambda: not dead.alive())
        app.peer_tick()
        assert app.peer_network is not dead
        assert app.peer_network.alive()
    finally:
        dead.stop()
        if app.peer_network is not None:
            app.peer_network.stop()


def test_localization_is_not_started_without_a_live_listener(tmp_path):
    """Pongs arrive on the listener thread. Without one, the verdict computed a
    few seconds later would read every peer as silent.
    """
    app = make_app(tmp_path)
    app.peer_tick()
    network = app.peer_network
    try:
        network.stop()
        app._begin_localization()
        assert app._localize_due_at is None
    finally:
        network.stop()


def test_the_peer_record_is_written_at_most_every_thirty_seconds(tmp_path, monkeypatch):
    """Every peer message marks the registry dirty and the UI tick runs every second,
    so an unthrottled save rewrote peers.json once a second on a busy LAN.
    """
    saves = []
    monkeypatch.setattr("netdnsmonitor.app.save_record", lambda registry, path: saves.append(path))
    app = make_app(tmp_path)

    app._mark_peers_dirty()
    app.ui_tick()
    app._mark_peers_dirty()
    app.ui_tick()

    assert len(saves) == 1
    assert app._peers_dirty is True  # still owed, not dropped


def test_the_app_keeps_working_with_discovery_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr("netdnsmonitor.peer_net.PeerNetwork.start", lambda self: False)
    app = make_app(tmp_path)
    app.peer_tick()
    app.ping_tick()
    app._ping_thread.join(timeout=5)
    app._drain_ping_results()
    assert "61ms" in app.title


# --- discovery ---------------------------------------------------------------


def test_two_instances_find_each_other(tmp_path):
    """Two apps, two ports, loopback in place of broadcast -- the real protocol
    end to end through the rumps shell rather than the module in isolation.
    """
    a = make_app(tmp_path / "a")
    b = make_app(tmp_path / "b")
    a.peer_tick()
    b.peer_tick()
    try:
        # Point each at the other, as a real broadcast would.
        a.peer_network.send_port = b.peer_network.bind_port
        b.peer_network.send_port = a.peer_network.bind_port

        a.peer_network.announce()
        assert _wait(lambda: a.instance_id in b.peer_registry.peers)
        b.peer_network.announce()
        assert _wait(lambda: b.instance_id in a.peer_registry.peers)

        assert b.peer_registry.bucket(b.peer_registry.peers[a.instance_id]) == CURRENT
    finally:
        a.peer_network.stop()
        b.peer_network.stop()


def test_each_instance_gets_its_own_id(tmp_path):
    """Two copies on one machine are genuinely two instances, and a hostname is
    not unique enough to key on.
    """
    a = make_app(tmp_path / "a")
    b = make_app(tmp_path / "b")
    assert a.instance_id != b.instance_id


def test_the_advertised_status_is_the_same_three_state_decision_as_the_menu_bar(tmp_path):
    app = make_app(tmp_path)
    assert app._peer_status() == "healthy"
    app.ping_stats = dict(app.ping_stats, down=True)
    assert app._peer_status() == "incident"
    app.ping_stats = dict(app.ping_stats, down=False)
    app.state_machine = FakeStateMachine("healthy", consecutive_failures=1)
    assert app._peer_status() == "flaky"


# --- the file record ---------------------------------------------------------


def test_a_sweep_writes_the_record_file(tmp_path):
    app = make_app(tmp_path)
    app.peer_tick()
    try:
        record = load_record(app.config["peer_record_path"])
        assert record["self_id"] == app.instance_id
        assert set(record["peers"]) == {"current", "recent", "other"}
    finally:
        app.peer_network.stop()


def test_a_restart_remembers_the_hosts_from_the_previous_run(tmp_path):
    """This is what "attempt to connect to them when starting" needs: without the
    record, a fresh process knows nobody until someone announces.
    """
    first = make_app(tmp_path)
    first.peer_registry.observe("peer-x", host="other-mac", address="192.168.1.77")
    first._save_peer_record()

    second = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    second.config["peer_record_path"] = first.config["peer_record_path"]
    second.peer_registry.load(load_record(first.config["peer_record_path"]))

    assert "peer-x" in second.peer_registry.peers
    assert ("peer-x", "192.168.1.77") in second.peer_registry.addresses_to_probe()


def test_a_peer_heard_on_the_listener_thread_is_persisted_from_the_main_thread(tmp_path):
    """The listener only sets a flag; the file write happens on the ui tick. All
    file writing stays on one thread.
    """
    app = make_app(tmp_path)
    app._peers_dirty = False
    app.peer_registry.observe("peer-y", host="mac-y", address="192.168.1.88")
    app._mark_peers_dirty()

    assert not (tmp_path / "peers.json").exists()
    app.ui_tick()
    assert "peer-y" in str(load_record(app.config["peer_record_path"]))
    assert app._peers_dirty is False


# --- the window --------------------------------------------------------------


# render_dashboard_text upper-cases section headings.
PEERS_HEADING = "OTHER MONITORS ON THIS NETWORK"


def test_the_dashboard_lists_known_peers(tmp_path):
    app = make_app(tmp_path)
    app.peer_registry.observe("peer-z", host="mac-z", address="192.168.1.99", status="healthy")
    app.open_dashboard()
    text = app._dashboard.stats_view.string()
    assert PEERS_HEADING in text
    assert "mac-z" in text
    assert "192.168.1.99" in text


def test_the_dashboard_says_so_when_no_peer_has_been_seen(tmp_path):
    app = make_app(tmp_path)
    app.open_dashboard()
    assert "none discovered yet" in app._dashboard.stats_view.string()


def test_a_peer_that_stopped_answering_shows_its_missed_heartbeats(tmp_path):
    """ "Was here, isn't answering now" is the interesting fact, and it is
    invisible if absent peers are hidden.
    """
    app = make_app(tmp_path)
    app.peer_registry.observe("ghost", host="switched-off", address="192.168.1.5")
    app.peer_registry.note_healthcheck_miss("ghost")
    app.peer_registry.note_healthcheck_miss("ghost")
    app.open_dashboard()
    text = app._dashboard.stats_view.string()
    assert "switched-off" in text
    assert "2 missed heartbeat(s)" in text


def test_the_peer_section_is_absent_when_discovery_is_off(tmp_path):
    """With a positive control: asserting only the absence would pass even if the
    heading string were wrong, which is exactly how this test first passed.
    """
    on = make_app(tmp_path / "on")
    on.open_dashboard()
    assert PEERS_HEADING in on._dashboard.stats_view.string()

    off = make_app(tmp_path / "off", peer_discovery_enabled=False)
    off.open_dashboard()
    assert PEERS_HEADING not in off._dashboard.stats_view.string()


def _wait(predicate, timeout=3.0):
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False
