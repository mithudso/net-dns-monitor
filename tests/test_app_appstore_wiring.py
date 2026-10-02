"""The Mac App Store edition, as wired into the rumps shell.

Every test passes `capabilities=` explicitly, so none of them depends on the
environment it runs in. Credentials come from a CredentialStore over a fake
Keychain with an empty environment, consent is a file under tmp_path, and both
dialogs and the URL opener are fakes. No test opens a window, touches the real
Keychain, runs a subprocess or loads a URL.

The store build's rule is that a feature it lacks is absent from the menu and,
wherever it can still be reached, answers with `distribution.unavailable(...)`.
Most assertions compare against that exact text rather than a substring, because
"never ok, never silent" is only checkable against the real sentence.
"""

import subprocess

import pytest
import rumps
import yaml

from netdnsmonitor import app as app_module
from netdnsmonitor import distribution, privileges
from netdnsmonitor.ai_consent import DISCLOSURE, ConsentStore
from netdnsmonitor.app import (
    CONSENT_ITEM,
    CREDENTIAL_ITEMS,
    CREDENTIALS_MENU,
    PRIVACY_POLICY_ITEM,
    REMOVE_CREDENTIALS_ITEM,
    WITHDRAW_CONSENT_ITEM,
    NetDnsMonitorApp,
    build_domains_source,
    build_state_machine,
    bundled_privacy_policy_url,
)
from netdnsmonitor.config import DEFAULT_CONFIG
from netdnsmonitor.credentials import (
    ERR_SEC_DUPLICATE_ITEM,
    ERR_SEC_ITEM_NOT_FOUND,
    CredentialStore,
)
from netdnsmonitor.distribution import UNAVAILABLE_PREFIX, is_unavailable, unavailable
from netdnsmonitor.ladder import LadderStep
from netdnsmonitor.log_watcher import NO_EVIDENCE_PREFIX

STORE = distribution.detect({"NETDNS_DISTRIBUTION": "appstore"})
DIRECT = distribution.detect({})

GATED_TITLES = (
    "Open console",
    "Router",
    "Start at Login",
    "Switch to backup now",
    "Switch back to preferred now",
)

SLACK_URL = "https://hooks.slack.test/services/T000/B000/not-a-real-secret"
API_KEY = "sk-ant-keychain-value-not-real"


class FakeKeychain:
    def __init__(self, items=None):
        self.items = {name: value.encode() for name, value in (items or {}).items()}
        self.calls = []

    def read(self, account):
        self.calls.append(("read", account))
        if account not in self.items:
            return ERR_SEC_ITEM_NOT_FOUND, None
        return 0, self.items[account]

    def add(self, account, value):
        self.calls.append(("add", account))
        if account in self.items:
            return ERR_SEC_DUPLICATE_ITEM
        self.items[account] = value
        return 0

    def update(self, account, value):
        self.calls.append(("update", account))
        self.items[account] = value
        return 0

    def delete(self, account):
        self.calls.append(("delete", account))
        if self.items.pop(account, None) is None:
            return ERR_SEC_ITEM_NOT_FOUND
        return 0


class FakeMessages:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        block = type("Block", (), {"text": "analysis from a fake client"})()
        return type("Response", (), {"content": [block]})()


class FakeClient:
    def __init__(self):
        self.messages = FakeMessages()


def refuse(what):
    def refused(*args, **kwargs):
        pytest.fail(f"{what} must not be called")

    return refused


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch):
    """No dialog, window, subprocess or credential from the environment."""
    monkeypatch.setattr(rumps, "alert", refuse("rumps.alert"))
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.show", lambda self, activate=True: None
    )
    for name in ("ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL", "SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


def build_app(
    tmp_path,
    *,
    capabilities=STORE,
    keychain=None,
    env=None,
    secret_prompt=None,
    choice_prompt=None,
    url_opener=None,
    policy_url=None,
    **config,
):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    routers = []

    def router_factory(**settings):
        routers.append(settings)
        return type("Router", (), {"wan_if": None, "lan_if": None})()

    keychain = FakeKeychain() if keychain is None else keychain
    app = NetDnsMonitorApp(
        config_path=str(path),
        router_factory=router_factory,
        capabilities=capabilities,
        credential_store=CredentialStore(env=env or {}, backend_factory=lambda: keychain),
        consent_store=ConsentStore(path=str(tmp_path / "consent.json")),
        secret_prompt=secret_prompt or refuse("the secret prompt"),
        choice_prompt=choice_prompt or refuse("the choice prompt"),
        url_opener=url_opener or refuse("the URL opener"),
        privacy_policy_url_fn=lambda: policy_url,
    )
    app.routers_built = routers
    app.keychain = keychain
    app.notes = []
    app._notify = lambda subtitle, message: app.notes.append((subtitle, message))
    app.output = []
    app._append_output = app.output.append
    return app


def top_level_titles(app):
    return [
        key
        for key in app.menu
        if not key.startswith("SeparatorMenuItem") and not key.startswith("failover-row-")
    ]


def register_clicked_handlers(app):
    """What `rumps.App.run` does before the event loop: every `@rumps.clicked`
    path is looked up in the menu, and added if missing.
    """
    for register in getattr(rumps.clicked, "*buttons", []):
        register(app)


def config(**overrides):
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(overrides)
    return cfg


# --- the menu ----------------------------------------------------------------


def test_store_build_menu_leaves_out_what_it_cannot_do(tmp_path):
    app = build_app(tmp_path)
    titles = top_level_titles(app)

    for gated in GATED_TITLES:
        assert gated not in titles
    assert CREDENTIALS_MENU in titles
    assert PRIVACY_POLICY_ITEM in titles
    assert CONSENT_ITEM in titles
    assert WITHDRAW_CONSENT_ITEM in titles
    assert "Refresh network status" in titles  # a read, which the sandbox allows
    assert titles[0] == "Open dashboard"


def test_store_build_menu_stays_that_way_once_the_app_runs(tmp_path):
    """`@rumps.clicked` re-adds any path it names that the menu lacks, at run().
    Leaving an item out of the list is not enough if a decorator still names it.
    """
    app = build_app(tmp_path)
    register_clicked_handlers(app)
    for gated in GATED_TITLES:
        assert gated not in top_level_titles(app)


def test_direct_build_menu_keeps_console_router_login_and_switches(tmp_path):
    app = build_app(tmp_path, capabilities=DIRECT)
    register_clicked_handlers(app)
    titles = top_level_titles(app)

    for kept in GATED_TITLES:
        assert kept in titles
    assert CREDENTIALS_MENU in titles
    assert PRIVACY_POLICY_ITEM not in titles
    assert CONSENT_ITEM not in titles
    assert WITHDRAW_CONSENT_ITEM not in titles
    assert titles.index("Open console") < titles.index("Router") < titles.index("Start at Login")
    assert list(app.menu["Router"].keys()) == [
        "Management Console",
        "Configure...",
        "Start",
        "Stop",
        "List Interfaces",
        "Troubleshoot",
    ]
    assert app.menu["Router"]["Start"].callback == app.start_router
    assert app.menu["Start at Login"].callback == app.toggle_login


def test_credentials_submenu_is_the_same_in_both_builds(tmp_path):
    expected = [title for title, _name, _message in CREDENTIAL_ITEMS] + [REMOVE_CREDENTIALS_ITEM]
    for capabilities in (STORE, DIRECT):
        app = build_app(tmp_path, capabilities=capabilities)
        submenu = [
            key for key in app.menu[CREDENTIALS_MENU] if not key.startswith("SeparatorMenuItem")
        ]
        assert submenu == expected
        assert submenu[:3] == [
            "Set Anthropic API key…",
            "Set Slack webhook URL…",
            "Set SMTP password…",
        ]


# --- repairs and failover ----------------------------------------------------


@pytest.mark.parametrize(
    ("step", "feature", "what"),
    [
        ("flush_dns_cache", "privileged_repairs", "flushing the DNS cache"),
        ("renew_dhcp_lease", "privileged_repairs", "renewing the DHCP lease"),
        ("switch_to_backup_network", "network_order_write", "switching to the backup network"),
    ],
)
def test_store_build_repairs_are_unavailable_and_run_nothing(
    tmp_path, monkeypatch, step, feature, what
):
    monkeypatch.setattr(subprocess, "Popen", refuse("subprocess.Popen"))
    for probe in ("is_granted", "primary_interface", "granted_commands_now", "dhcp_interfaces"):
        monkeypatch.setattr(privileges, probe, refuse(f"privileges.{probe}"))
    app = build_app(tmp_path)

    outcome = app.state_machine.repair_executor(LadderStep(step, "repair", True), "network")

    assert is_unavailable(outcome)
    assert outcome == unavailable(feature, what)


def test_store_build_keeps_the_switch_step_on_the_ladder_so_the_report_says_why(tmp_path):
    """A configured failover still puts the step on a network ladder. The step
    reports the switch as unavailable, rather than the ladder silently omitting it.
    """
    machine = build_state_machine(
        config(
            failover_enabled=True,
            failover_preferred_service="AX88179B",
            failover_backup_service="Wi-Fi",
        ),
        capabilities=STORE,
        credential_store=CredentialStore(env={}, backend_factory=FakeKeychain),
        consent=ConsentStore(path=str(tmp_path / "consent.json")),
    )
    assert "network" in machine.failover_classifications
    outcome = machine.repair_executor(
        LadderStep("switch_to_backup_network", "repair", True), "network"
    )
    assert outcome == unavailable("network_order_write", "switching to the backup network")


class RecordingFailover:
    preferred_service = "AX88179B"
    backup_service = "Wi-Fi"
    last_event = None

    def __init__(self):
        self.calls = []

    def attempt_failback(self):
        self.calls.append("attempt_failback")
        return None

    def switch_now(self, target, service=None):
        self.calls.append(("switch_now", target))
        return "ok: switched"

    def snapshot(self):
        return {
            "error": None,
            "active_side": "preferred",
            "active_service": "AX88179B",
            "preferred": {"name": "AX88179B", "found": True, "reachable": True},
            "backup": {"name": "Wi-Fi", "found": True, "reachable": True},
            "backups": [{"name": "Wi-Fi", "found": True, "reachable": True}],
            "auto_enabled": True,
            "last_event": None,
        }


class QuietStateMachine:
    def __init__(self, flap_gate):
        self.flap_gate = flap_gate

    def tick(self):
        return None


@pytest.mark.parametrize(
    ("capabilities", "expected"), [(STORE, []), (DIRECT, ["attempt_failback"])]
)
def test_ticks_fail_back_only_where_the_order_can_be_written(tmp_path, capabilities, expected):
    app = build_app(tmp_path, capabilities=capabilities)
    app.failover = RecordingFailover()
    app.state_machine = QuietStateMachine(app.state_machine.flap_gate)

    app.tick()

    assert app.failover.calls == expected
    assert app.last_tick_error is None


@pytest.mark.parametrize(
    ("handler", "label"),
    [("switch_to_backup", "backup"), ("switch_to_preferred", "preferred")],
)
def test_store_build_manual_switch_says_unavailable_and_writes_nothing(tmp_path, handler, label):
    app = build_app(tmp_path)
    app.failover = RecordingFailover()

    getattr(app, handler)(None)

    assert app.failover.calls == []
    assert app.notes == [
        (
            "Network failover",
            unavailable("network_order_write", f"switching to the {label} network"),
        )
    ]


def test_store_build_failover_rows_are_read_only(tmp_path):
    """The status line must not say "failover is automatic" where nothing can switch."""
    app = build_app(tmp_path)
    app.failover = RecordingFailover()
    app._refresh_failover_menu()
    assert app.failover_rows[0].title == "Active: AX88179B — read-only in this build"

    direct = build_app(tmp_path, capabilities=DIRECT)
    direct.failover = RecordingFailover()
    direct._refresh_failover_menu()
    assert direct.failover_rows[0].title == "Active: AX88179B — failover is automatic"


def test_store_build_unconfigured_failover_does_not_point_at_config_yaml(tmp_path):
    """No setting can make the switch work here, so the row must not suggest one."""
    app = build_app(tmp_path)
    app.failover = None
    app._refresh_failover_menu()
    assert app.failover_rows[0].title == "Failover: not available in this build"
    assert all("config.yaml" not in row.title for row in app.failover_rows)


def test_store_build_launch_does_not_announce_the_missing_console(tmp_path, monkeypatch):
    """auto_open_console defaults on; in the store build that once posted the
    console's unavailable banner on every launch."""
    monkeypatch.setattr("netdnsmonitor.app.install_main_menu", lambda on_action: None)
    app = build_app(tmp_path, open_dashboard_at_launch=False)
    app._install_activation_observer = lambda: None
    app.open_console = refuse("open_console")

    app.launch_tick()

    assert app.notes == []


def test_store_build_starts_with_peer_discovery_off(tmp_path):
    """The broadcast discloses the hostname and triggers the Local Network
    prompt, so the store build waits for the user to turn it on."""
    assert build_app(tmp_path).config["peer_discovery_enabled"] is False
    assert build_app(tmp_path, capabilities=DIRECT).config["peer_discovery_enabled"] is True


def test_store_build_honours_peer_discovery_set_in_the_file(tmp_path):
    app = build_app(tmp_path, peer_discovery_enabled=True)
    assert app.config["peer_discovery_enabled"] is True


# --- the unified log ---------------------------------------------------------


def test_store_build_log_watcher_returns_one_unavailable_line_and_no_log_timer(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("netdnsmonitor.app.make_log_watcher", refuse("make_log_watcher"))
    monkeypatch.setattr("netdnsmonitor.app.make_domain_learner", refuse("make_domain_learner"))
    app = build_app(tmp_path, log_view_enabled=True, learn_domains_from_logs=True)

    lines = app.state_machine.log_watcher()

    assert len(lines) == 1
    assert lines[0].startswith(NO_EVIDENCE_PREFIX)
    assert UNAVAILABLE_PREFIX in lines[0]
    assert app.log_timer is None
    assert app._start_log_read("1m") is False
    assert app._log_thread is None


def test_store_build_builds_no_domain_learner_even_when_configured(monkeypatch):
    monkeypatch.setattr("netdnsmonitor.app.make_domain_learner", refuse("make_domain_learner"))
    source, store = build_domains_source(
        config(learn_domains_from_logs=True, domains=["example.com"]),
        lambda: [],
        capabilities=STORE,
    )
    assert store is None
    assert "example.com" in source


def test_store_build_log_pane_and_prewarm_report_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr("netdnsmonitor.app.make_query_log_reader", refuse("make_query_log_reader"))
    app = build_app(tmp_path)
    text = unavailable("unified_log", "reading the system log")

    assert app._empty_log_pane_text("") == text + "\n"
    assert app._log_read_refused_reason() == text + "\n"
    assert app.log_error == text  # what the Monitor row and pane status line show

    for action_id in ("log_refresh", "log_toggle_level", "log_clear_buffer", "prewarm_dns"):
        app.output.clear()
        app.handle_dashboard_action(action_id)
        assert len(app.output) == 1
        assert is_unavailable(app.output[0].split("\n")[2])
    assert app._action_thread is None
    assert app._log_thread is None
    assert app.log_error == text  # clearing the buffer did not clear the reason


# --- Claude diagnosis --------------------------------------------------------


def test_store_build_escalator_sends_nothing_without_consent_and_sends_after_grant(
    tmp_path, monkeypatch
):
    client = FakeClient()
    keys = []
    monkeypatch.setattr(
        "netdnsmonitor.app.default_client", lambda api_key=None: keys.append(api_key) or client
    )
    prompts = []

    def choice_prompt(title, message, ok_label, cancel_label):
        prompts.append((title, message, ok_label, cancel_label))
        return True

    app = build_app(
        tmp_path,
        keychain=FakeKeychain({"ANTHROPIC_API_KEY": API_KEY}),
        choice_prompt=choice_prompt,
    )
    bundle = {"classification": "network"}

    assert keys == [API_KEY]
    before = app.state_machine.escalator(bundle)
    assert "permission" in before["error"]
    assert client.messages.calls == []
    assert app.menu[CONSENT_ITEM].state == 0

    assert app.allow_claude_diagnosis() == "ok: permission granted"
    assert prompts == [("Allow Claude diagnosis?", DISCLOSURE, "Allow", "Don't Allow")]
    assert app.menu[CONSENT_ITEM].state == 1

    after = app.state_machine.escalator(bundle)
    assert after["analysis"] == "analysis from a fake client"
    assert len(client.messages.calls) == 1

    assert app.withdraw_claude_permission() == "ok: permission withdrawn"
    assert app.menu[CONSENT_ITEM].state == 0
    assert "permission" in app.state_machine.escalator(bundle)["error"]
    assert len(client.messages.calls) == 1


def test_dont_allow_withdraws_an_earlier_grant_and_otherwise_changes_nothing(tmp_path):
    answers = iter([False, True, False])
    app = build_app(tmp_path, choice_prompt=lambda *a: next(answers))

    assert app.allow_claude_diagnosis() == "cancelled: nothing was changed"
    assert not (tmp_path / "consent.json").exists()
    assert app.notes == []

    assert app.allow_claude_diagnosis() == "ok: permission granted"
    assert app.allow_claude_diagnosis() == "ok: permission withdrawn"
    assert app.consent.granted() is False
    assert app.menu[CONSENT_ITEM].state == 0


def test_missing_key_text_names_the_keychain_only_in_the_store_build(tmp_path):
    (tmp_path / "store").mkdir()
    (tmp_path / "direct").mkdir()
    store = build_app(tmp_path / "store", choice_prompt=lambda *a: True)
    store.allow_claude_diagnosis()
    assert "Keychain" in store.state_machine.escalator({})["error"]

    direct = build_app(tmp_path / "direct", capabilities=DIRECT)
    assert direct.consent is None
    assert direct.state_machine.escalator({}) == {
        "error": "ANTHROPIC_API_KEY not set; skipped LLM escalation"
    }


def test_direct_build_uses_a_keychain_key_without_asking_for_consent(tmp_path, monkeypatch):
    client = FakeClient()
    monkeypatch.setattr("netdnsmonitor.app.default_client", lambda api_key=None: client)
    app = build_app(
        tmp_path, capabilities=DIRECT, keychain=FakeKeychain({"ANTHROPIC_API_KEY": API_KEY})
    )
    assert app.state_machine.escalator({"classification": "network"})["analysis"]
    assert CONSENT_ITEM not in top_level_titles(app)


# --- notifications -----------------------------------------------------------


def test_store_build_notifier_reads_the_slack_webhook_from_the_credential_store(
    tmp_path, monkeypatch
):
    webhooks = []

    def fake_make_slack_notifier(webhook_url, timeout):
        webhooks.append(webhook_url)
        return lambda text: {"channel": "slack", "ok": True}

    monkeypatch.setattr("netdnsmonitor.app.make_slack_notifier", fake_make_slack_notifier)
    build_app(
        tmp_path,
        keychain=FakeKeychain({"SLACK_WEBHOOK_URL": SLACK_URL}),
        slack_enabled=True,
        email_enabled=False,
    )
    assert webhooks == [SLACK_URL]


# --- privileges, router, console, login item ---------------------------------


def test_store_build_with_the_router_enabled_builds_no_router_and_probes_no_privileges(
    tmp_path, monkeypatch
):
    for probe in (
        "is_granted",
        "primary_interface",
        "granted_commands_now",
        "dhcp_interfaces",
        "grant",
        "revoke",
    ):
        monkeypatch.setattr(privileges, probe, refuse(f"privileges.{probe}"))
    monkeypatch.setattr("netdnsmonitor.app.install_main_menu", lambda on_action: None)
    monkeypatch.setattr(
        "netdnsmonitor.app.RouterWindowController", refuse("RouterWindowController")
    )
    app = build_app(
        tmp_path,
        router_enabled=True,
        wan_interface="en5",
        lan_interface="en6",
        open_dashboard_at_launch=False,
        # The console has its own unavailable note; this test is about the router.
        auto_open_console=False,
    )
    app._install_activation_observer = lambda: None

    app.launch_tick()
    app.open_dashboard()

    assert app.router is None
    assert app.routers_built == []
    assert app._privilege_status_thread is None
    assert app._permission_rows() == [
        ("Elevated permissions", unavailable("privileged_repairs", "elevated permissions"))
    ]

    app.start_router(None)
    app.stop_router(None)
    app.list_interfaces(None)
    app.troubleshoot_router(None)
    assert app._router_thread is None
    assert app._router_info_thread is None
    assert {message for _subtitle, message in app.notes} == {unavailable("router", "the router")}


@pytest.mark.parametrize(
    ("action_id", "feature", "what"),
    [
        ("open_console", "shell_console", "the console"),
        ("open_router_window", "router", "the router console"),
        ("grant_privileges", "privileged_repairs", "granting elevated permissions"),
        ("revoke_privileges", "privileged_repairs", "revoking elevated permissions"),
    ],
)
def test_store_build_dashboard_actions_print_the_unavailable_text(
    tmp_path, monkeypatch, action_id, feature, what
):
    monkeypatch.setattr(privileges, "grant", refuse("privileges.grant"))
    monkeypatch.setattr(privileges, "revoke", refuse("privileges.revoke"))
    monkeypatch.setattr(
        "netdnsmonitor.app.RouterWindowController", refuse("RouterWindowController")
    )
    monkeypatch.setattr("netdnsmonitor.app.ConsoleWindowController", refuse("the console"))
    app = build_app(tmp_path)

    app.handle_dashboard_action(action_id)

    assert app.output == [f"\n>>> {action_id}\n{unavailable(feature, what)}\n"]
    assert app.console is None
    assert app._privilege_thread is None
    assert app._action_thread is None


def test_store_build_console_and_login_item_handlers_say_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr("netdnsmonitor.app.ConsoleWindowController", refuse("the console"))
    app = build_app(tmp_path)
    sender = rumps.MenuItem("Start at Login")

    app.open_console()
    app.toggle_login(sender)

    assert app.console is None
    assert not (tmp_path / "home" / "Library" / "LaunchAgents").exists()
    assert app.notes == [
        ("Console", unavailable("shell_console", "the console")),
        ("Start at Login", unavailable("launch_agent_login_item", "Start at Login")),
    ]


def test_direct_build_privileged_path_is_unchanged(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(privileges, "primary_interface", lambda *a, **k: "en9")
    monkeypatch.setattr(
        privileges, "granted_commands_now", lambda *a, **k: calls.append("probed") or []
    )
    machine = build_state_machine(
        config(),
        capabilities=DIRECT,
        credential_store=CredentialStore(env={}, backend_factory=FakeKeychain),
    )

    outcome = machine.repair_executor(LadderStep("renew_dhcp_lease", "repair", True))

    assert outcome.startswith("NEEDS_PRIVILEGE")
    assert calls == ["probed"]

    app = build_app(tmp_path, capabilities=DIRECT)
    app._refresh_privilege_status()
    assert app._privilege_status_thread is not None
    app._privilege_status_thread.join(timeout=5)
    assert app._permission_rows() != [
        ("Elevated permissions", unavailable("privileged_repairs", "elevated permissions"))
    ]


def test_capabilities_are_detected_from_the_environment_when_not_given(monkeypatch):
    monkeypatch.setenv("NETDNS_DISTRIBUTION", "appstore")
    machine = build_state_machine(
        config(), credential_store=CredentialStore(env={}, backend_factory=FakeKeychain)
    )
    assert is_unavailable(machine.log_watcher()[0][len(NO_EVIDENCE_PREFIX) + 1 :])


# --- the credential prompt ---------------------------------------------------


@pytest.mark.parametrize("capabilities", [STORE, DIRECT])
def test_a_saved_credential_reaches_the_store_and_is_never_shown(
    tmp_path, monkeypatch, capabilities
):
    webhooks = []

    def fake_make_slack_notifier(webhook_url, timeout):
        webhooks.append(webhook_url)
        return lambda text: {"channel": "slack", "ok": True}

    monkeypatch.setattr("netdnsmonitor.app.make_slack_notifier", fake_make_slack_notifier)
    prompts = []

    def secret_prompt(title, message):
        prompts.append((title, message))
        return SLACK_URL

    app = build_app(
        tmp_path,
        capabilities=capabilities,
        secret_prompt=secret_prompt,
        slack_enabled=True,
        email_enabled=False,
    )
    assert webhooks == []  # nothing saved yet, so no channel

    # Through the menu item's own callback, so the wiring is what is tested.
    app.menu[CREDENTIALS_MENU]["Set Slack webhook URL…"].callback(None)

    assert app.keychain.items["SLACK_WEBHOOK_URL"] == SLACK_URL.encode()
    assert prompts[0][0] == "Set Slack webhook URL"
    assert len(app.notes) == 1
    subtitle, outcome = app.notes[0]
    assert subtitle == CREDENTIALS_MENU
    assert outcome.startswith("ok: SLACK_WEBHOOK_URL saved to the Keychain")
    assert outcome.endswith("; in use now")
    assert SLACK_URL not in outcome
    assert all(SLACK_URL not in text for text in app.output)
    # Applied without a restart: the notifier was rebuilt from the new value.
    assert webhooks == [SLACK_URL]


def test_cancelling_the_credential_prompt_changes_nothing(tmp_path):
    app = build_app(tmp_path, secret_prompt=lambda title, message: None)
    notifier, escalator = app.notifier, app.state_machine.escalator
    app.keychain.calls.clear()

    assert app.set_credential("ANTHROPIC_API_KEY") == "cancelled: nothing was changed"

    assert app.keychain.calls == []
    assert app.keychain.items == {}
    assert app.notes == []
    assert app.notifier is notifier
    assert app.state_machine.escalator is escalator


def test_a_saved_api_key_rebuilds_the_escalator_in_place(tmp_path, monkeypatch):
    client = FakeClient()
    keys = []
    monkeypatch.setattr(
        "netdnsmonitor.app.default_client", lambda api_key=None: keys.append(api_key) or client
    )
    app = build_app(tmp_path, capabilities=DIRECT, secret_prompt=lambda title, message: API_KEY)
    assert "not set" in app.state_machine.escalator({})["error"]

    outcome = app.set_credential("ANTHROPIC_API_KEY")

    assert API_KEY not in outcome
    assert keys == [API_KEY]
    assert app.state_machine.escalator({"classification": "network"})["analysis"]


def test_an_empty_value_is_refused_by_the_store_and_says_so(tmp_path):
    app = build_app(tmp_path, secret_prompt=lambda title, message: "")
    outcome = app.set_credential("SMTP_PASSWORD")
    assert outcome.startswith("failed: an empty value was not saved")
    assert app.keychain.items == {}
    assert app.notes == [(CREDENTIALS_MENU, outcome)]


def test_saving_a_credential_the_environment_overrides_says_so(tmp_path):
    app = build_app(
        tmp_path,
        env={"SMTP_PASSWORD": "from-the-shell"},
        secret_prompt=lambda title, message: "typed-into-the-dialog",
    )
    outcome = app.set_credential("SMTP_PASSWORD")
    assert outcome.startswith("ok: SMTP_PASSWORD saved to the Keychain; not in use")
    assert "also set in the environment" in outcome
    assert "in use now" not in outcome
    assert "typed-into-the-dialog" not in outcome
    assert "from-the-shell" not in outcome

    app.choice_prompt = lambda *a: True
    removed = app.remove_credentials()
    assert "still set in the environment, and still in use: SMTP_PASSWORD" in removed
    assert "from-the-shell" not in removed


MAILABLE = {"email_enabled": True, "email_recipients": ["ops@example.test"], "smtp_username": "ops"}


@pytest.mark.parametrize(
    ("name", "settings", "named"),
    [
        ("SMTP_PASSWORD", {**MAILABLE, "email_recipients": []}, "email_recipients"),
        ("SMTP_PASSWORD", {**MAILABLE, "email_enabled": False}, "email_enabled"),
        ("SMTP_PASSWORD", {**MAILABLE, "smtp_username": None}, "smtp_username"),
        ("SMTP_PASSWORD", {**MAILABLE, "smtp_starttls": False}, "smtp_starttls"),
        ("SLACK_WEBHOOK_URL", {"slack_enabled": False}, "slack_enabled"),
    ],
)
def test_a_credential_nothing_reads_does_not_claim_to_be_in_use(tmp_path, name, settings, named):
    """build_notifier builds no email channel without recipients, and the email
    channel logs in only with a username and TLS. "In use now" there sends
    someone to wait for an alert that cannot use what they just saved.
    """
    app = build_app(
        tmp_path, capabilities=DIRECT, secret_prompt=lambda title, message: "a-value", **settings
    )
    outcome = app.set_credential(name)
    assert outcome.startswith(f"ok: {name} saved to the Keychain; not in use until ")
    assert named in outcome
    assert "in use now" not in outcome
    assert "a-value" not in outcome


def test_a_fully_configured_smtp_password_is_in_use_now(tmp_path):
    app = build_app(
        tmp_path, capabilities=DIRECT, secret_prompt=lambda title, message: "a-value", **MAILABLE
    )
    assert app.set_credential("SMTP_PASSWORD").endswith("; in use now")


def test_a_store_build_api_key_waits_for_claude_permission(tmp_path, monkeypatch):
    """The store build's escalator is gated on consent, so a key saved before
    Allow Claude diagnosis is not used by the next incident.
    """
    monkeypatch.setattr("netdnsmonitor.app.default_client", lambda api_key=None: FakeClient())
    app = build_app(tmp_path, secret_prompt=lambda title, message: API_KEY)

    outcome = app.set_credential("ANTHROPIC_API_KEY")
    assert CONSENT_ITEM in outcome
    assert "in use now" not in outcome
    assert API_KEY not in outcome

    app.consent.grant()
    assert app.set_credential("ANTHROPIC_API_KEY").endswith("; in use now")


def test_a_credential_saved_but_not_applied_says_restart(tmp_path, monkeypatch):
    app = build_app(tmp_path, secret_prompt=lambda title, message: "a-password")

    def exploding(*args, **kwargs):
        raise RuntimeError("detail that must not be shown")

    monkeypatch.setattr("netdnsmonitor.app.build_escalator", exploding)
    outcome = app.set_credential("SMTP_PASSWORD")

    assert app.keychain.items["SMTP_PASSWORD"] == b"a-password"
    assert outcome == (
        "ok: SMTP_PASSWORD saved to the Keychain; not applied to the running app "
        "(RuntimeError), restart to use it"
    )


def test_remove_saved_credentials_asks_then_deletes_all_three(tmp_path):
    answers = iter([False, True])
    app = build_app(
        tmp_path,
        keychain=FakeKeychain({"ANTHROPIC_API_KEY": API_KEY, "SLACK_WEBHOOK_URL": SLACK_URL}),
        choice_prompt=lambda *a: next(answers),
    )

    assert app.remove_credentials() == "cancelled: nothing was changed"
    assert len(app.keychain.items) == 2

    outcome = app.remove_credentials()

    assert app.keychain.items == {}
    assert "ok: ANTHROPIC_API_KEY removed from the Keychain" in outcome
    assert "ok: SLACK_WEBHOOK_URL removed from the Keychain" in outcome
    assert "ok: SMTP_PASSWORD was not in the Keychain" in outcome
    assert API_KEY not in outcome and SLACK_URL not in outcome
    assert app.notes == [(CREDENTIALS_MENU, outcome)]


# --- last report ---------------------------------------------------------------


@pytest.mark.parametrize("capabilities", [STORE, DIRECT])
def test_open_last_report_is_clickable_in_both_builds(tmp_path, capabilities):
    """A bare title with no callback and no `@rumps.clicked` is drawn greyed out."""
    app = build_app(tmp_path, capabilities=capabilities)
    register_clicked_handlers(app)
    assert app.menu["Open last report"].callback == app.open_last_report


def test_open_last_report_hands_an_encoded_file_url_to_the_url_opener(tmp_path, monkeypatch):
    monkeypatch.setattr("webbrowser.open", refuse("webbrowser.open"))
    opened = []
    app = build_app(tmp_path, url_opener=lambda url: opened.append(url) or True)
    report = tmp_path / "Application Support" / "incident report.md"
    app.last_report_path = str(report)

    app.menu["Open last report"].callback(None)

    assert opened == [report.as_uri()]
    assert opened[0].startswith("file:///") and "%20" in opened[0] and " " not in opened[0]
    assert app.notes == []


def test_a_last_report_that_does_not_open_says_so(tmp_path):
    app = build_app(tmp_path, url_opener=lambda url: False)
    app.last_report_path = str(tmp_path / "report.md")

    outcome = app.open_last_report(None)

    assert outcome == f"failed: could not open {app.last_report_path}"
    assert app.notes == [("Last report", outcome)]


def test_an_opener_that_raises_is_reported_by_class_name_only(tmp_path):
    def opener(url):
        raise RuntimeError("NSWorkspace said something about /private/secret-path")

    app = build_app(tmp_path, url_opener=opener)
    app.last_report_path = str(tmp_path / "report.md")

    outcome = app.open_last_report(None)

    assert outcome == f"failed: could not open {app.last_report_path} (RuntimeError)"
    assert app.notes == [("Last report", outcome)]
    assert "secret-path" not in repr(app.notes)


def test_open_last_report_before_any_report_says_so_and_opens_nothing(tmp_path):
    app = build_app(tmp_path)  # the default opener here fails the test if called
    app.last_report_path = None

    outcome = app.open_last_report(None)

    assert app.notes == [("Last report", "No report has been generated yet.")]
    assert outcome == "No report has been generated yet."


# --- privacy policy ------------------------------------------------------------


def test_privacy_policy_opens_the_bundled_url(tmp_path):
    opened = []
    app = build_app(
        tmp_path,
        policy_url="https://example.test/privacy",
        url_opener=lambda url: opened.append(url) or True,
    )
    app.menu[PRIVACY_POLICY_ITEM].callback(None)
    assert opened == ["https://example.test/privacy"]
    assert app.notes == []


def test_privacy_policy_without_a_bundled_url_says_so(tmp_path):
    app = build_app(tmp_path, policy_url=None)
    outcome = app.open_privacy_policy()
    assert "No privacy policy URL is bundled" in outcome
    assert app.notes == [(PRIVACY_POLICY_ITEM, outcome)]


def test_a_source_run_has_no_bundled_privacy_policy_url():
    assert bundled_privacy_policy_url() is None


def test_the_default_credential_store_goes_through_the_conftest_keychain():
    """The conftest guard is only a guard if the app's default store goes through
    it. Checked by the backend's type, before anything is read or written, so a
    broken guard fails here without touching the real Keychain.
    """
    store = app_module.default_credential_store()
    assert type(store._keychain()).__name__ == "_MemoryKeychain"


# --- the dashboard grid ----------------------------------------------------


def test_store_dashboard_grid_omits_every_gated_action_the_build_lacks(tmp_path):
    """A reviewer must not meet an "arbitrary shell" or "grant elevated
    permissions" button whose only answer is that it is unavailable. The grid
    the store build lays out is ALL_ACTIONS minus every gated action whose
    capability this build lacks; the gate in handle_dashboard_action stays for
    any other path in.
    """
    from netdnsmonitor.dashboard import ALL_ACTIONS

    app = build_app(tmp_path)
    ids = [action_id for _, action_id, _ in app.dashboard_actions()]
    lacking = {
        action_id
        for action_id, (feature, _what) in app_module.GATED_DASHBOARD_ACTIONS.items()
        if not getattr(STORE, feature)
    }
    assert lacking >= {"open_console", "open_router_window", "grant_privileges", "prewarm_dns"}
    assert not lacking.intersection(ids)
    assert ids == [action_id for _, action_id, _ in ALL_ACTIONS if action_id not in lacking]
    assert "full_diagnosis" in ids and "open_settings" in ids


def test_direct_dashboard_grid_keeps_every_action(tmp_path):
    from netdnsmonitor.dashboard import ALL_ACTIONS

    app = build_app(tmp_path, capabilities=DIRECT)
    assert app.dashboard_actions() == list(ALL_ACTIONS)


def test_store_dashboard_has_no_log_column_and_skips_the_log_refresh(tmp_path):
    """The log column could only say "unavailable" in the store build, so the
    window leaves it out, and the 1s refresh skips the filter pass that fed it.
    """
    app = build_app(tmp_path)
    dashboard = app._ensure_dashboard()
    assert dashboard.log_column is False
    assert dashboard.log_view is None

    def view(**_kwargs):
        raise AssertionError("the store build must not filter a log it cannot show")

    app.log_buffer.view = view
    app._refresh_log_pane(force=True)


def test_direct_dashboard_keeps_the_log_column(tmp_path):
    app = build_app(tmp_path, capabilities=DIRECT)
    dashboard = app._ensure_dashboard()
    assert dashboard.log_column is True
    assert dashboard.log_view is not None
