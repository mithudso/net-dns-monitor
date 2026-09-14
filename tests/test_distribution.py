from netdnsmonitor import distribution
from netdnsmonitor.distribution import APP_STORE, DIRECT, detect, is_unavailable, unavailable


def test_a_plain_process_is_the_direct_build_with_every_feature():
    caps = detect({})
    assert caps.distribution == DIRECT
    assert not caps.sandboxed
    assert caps.shell_console
    assert caps.privileged_repairs
    assert caps.network_order_write
    assert caps.unified_log
    assert caps.router
    assert caps.launch_agent_login_item
    assert not caps.requires_ai_consent


def test_the_sandbox_turns_off_every_feature_it_would_refuse():
    caps = detect({"APP_SANDBOX_CONTAINER_ID": "com.net-dns-monitor.app"})
    assert caps.distribution == APP_STORE
    assert caps.sandboxed
    assert caps.is_app_store
    assert not caps.shell_console
    assert not caps.privileged_repairs
    assert not caps.network_order_write
    assert not caps.unified_log
    assert not caps.router
    assert not caps.launch_agent_login_item
    assert caps.requires_ai_consent
    assert caps.credentials_from_keychain


def test_the_override_exercises_app_store_behaviour_without_a_sandbox():
    caps = detect({"NETDNS_DISTRIBUTION": "AppStore "})
    assert caps.is_app_store
    assert not caps.sandboxed
    assert not caps.privileged_repairs


def test_the_override_cannot_re_enable_features_inside_the_sandbox():
    caps = detect({"APP_SANDBOX_CONTAINER_ID": "x", "NETDNS_DISTRIBUTION": "direct"})
    assert caps.is_app_store
    assert not caps.network_order_write


def test_an_unrecognised_override_falls_back_to_what_the_process_is():
    assert detect({"NETDNS_DISTRIBUTION": "enterprise"}).distribution == DIRECT
    sandboxed = detect({"NETDNS_DISTRIBUTION": "enterprise", "APP_SANDBOX_CONTAINER_ID": "x"})
    assert sandboxed.distribution == APP_STORE


def test_an_empty_container_id_is_not_a_sandbox():
    assert detect({"APP_SANDBOX_CONTAINER_ID": ""}).distribution == DIRECT


def test_unavailable_text_says_nothing_changed_and_is_recognisable():
    text = unavailable("network_order_write", "switching to the backup network")
    assert text.startswith(distribution.UNAVAILABLE_PREFIX)
    assert "switching to the backup network" in text
    assert "Nothing was changed." in text
    assert "ok" not in text.split(":")[0].lower()
    assert is_unavailable(text)


def test_unavailable_never_reads_as_success_or_failure():
    text = unavailable("privileged_repairs")
    assert not text.startswith(("ok", "failed", "partial", "NEEDS_PRIVILEGE"))


def test_every_gated_feature_has_a_reason():
    caps_fields = {
        "shell_console",
        "privileged_repairs",
        "network_order_write",
        "unified_log",
        "router",
        "launch_agent_login_item",
    }
    assert caps_fields == set(distribution.REASONS)


def test_is_unavailable_rejects_other_values():
    assert not is_unavailable("ok: done")
    assert not is_unavailable(None)
    assert not is_unavailable({"error": "x"})
