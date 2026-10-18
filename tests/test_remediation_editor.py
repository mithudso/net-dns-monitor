"""The editor's logic (everything but the AppKit window) and its wiring into the app."""

import pytest
import rumps

from netdnsmonitor import distribution
from netdnsmonitor.app import REMEDIATION_DIR_ENV, build_remediation_store
from netdnsmonitor.remediation_editor import (
    KIND_COMMENT,
    KIND_KEYWORD,
    KIND_STRING,
    EditorSession,
    format_run,
    highlight_spans,
    utf16_length,
)
from netdnsmonitor.remediation_scripts import RunResult, ScriptStore
from tests.test_app_appstore_wiring import DIRECT, STORE, build_app
from tests.test_remediation_scripts import CUSTOM


@pytest.fixture(autouse=True)
def _no_real_windows(monkeypatch):
    monkeypatch.setattr(rumps, "alert", lambda *a, **k: pytest.fail("rumps.alert"))
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.show", lambda self, activate=True: None
    )


def spans_of(source):
    return [(source[s : s + n], kind) for s, n, kind in highlight_spans(source)]


# --- highlighting ------------------------------------------------------------


def test_a_hash_inside_a_string_is_a_string_not_a_comment():
    spans = spans_of('x = "a # b"  # real\n')
    assert ('"a # b"', KIND_STRING) in spans
    assert ("# real", KIND_COMMENT) in spans
    assert len([s for s in spans if s[1] == KIND_COMMENT]) == 1


def test_keywords_are_coloured_and_identifiers_are_not():
    spans = spans_of("def run(ctx):\n    return None\n")
    assert ("def", KIND_KEYWORD) in spans and ("return", KIND_KEYWORD) in spans
    assert all(text != "run" for text, _ in spans)


def test_a_multiline_docstring_is_one_span():
    source = '"""one\ntwo\nthree"""\n'
    assert spans_of(source) == [(source.rstrip("\n"), KIND_STRING)]


def test_an_fstring_is_one_string_span():
    spans = spans_of('y = f"a {1 + 2} b"\n')
    assert ('f"a {1 + 2} b"', KIND_STRING) in spans


def test_offsets_count_utf16_units_not_code_points():
    """An emoji is one code point and two UTF-16 units; Cocoa counts the latter."""
    source = '# 🎉\nx = "s"\n'
    (comment, string) = [span for span in highlight_spans(source) if span[2] != KIND_KEYWORD]
    assert comment[0] == 0 and comment[1] == utf16_length("# 🎉")
    assert string[0] == utf16_length("# 🎉\nx = ")


def test_half_typed_source_still_colours_what_precedes_the_error():
    spans = spans_of('import re\nx = "unterminated\n')
    assert ("import", KIND_KEYWORD) in spans


# --- the session -------------------------------------------------------------


def make_session(tmp_path, run_source=None):
    store = ScriptStore(user_dir=tmp_path / "u")
    return EditorSession(store, run_source=run_source, clock=iter([0.0, 0.5]).__next__), store


def test_rows_label_origin_and_flag_trouble(tmp_path):
    session, store = make_session(tmp_path)
    store.save("my_check", CUSTOM)
    (store.user_dir).mkdir(exist_ok=True)
    (store.user_dir / "broken_one.py").write_text("def run(ctx:\n")
    labels = {row.name: row.label for row in session.rows()}
    assert labels["check_interface_state"] == "check_interface_state  [built-in]"
    assert labels["my_check"] == "my_check  [custom]"
    assert "INVALID" in labels["broken_one"]


def test_save_reports_why_it_refused(tmp_path):
    session, _ = make_session(tmp_path)
    ok, message = session.save("my_check", "x = (\n")
    assert not ok and "syntax error" in message


def test_save_of_an_unchanged_builtin_says_the_override_is_gone(tmp_path):
    session, store = make_session(tmp_path)
    original = store.builtin_source("check_interface_state")
    session.save("check_interface_state", original + "# edit\n")
    ok, message = session.save("check_interface_state", original)
    assert ok and "override was removed" in message


def test_reset_and_delete_are_offered_only_where_they_apply(tmp_path):
    session, store = make_session(tmp_path)
    assert not session.can_remove("check_interface_state")
    store.save("check_interface_state", store.builtin_source("check_interface_state") + "# e\n")
    store.save("my_check", CUSTOM)
    assert (
        session.can_remove("check_interface_state")
        and session.remove_verb("check_interface_state") == "Reset"
    )
    assert session.remove_verb("my_check") == "Delete"


def test_create_validates_the_name_and_refuses_duplicates(tmp_path):
    session, _ = make_session(tmp_path)
    assert not session.create("Bad Name")[0]
    assert not session.create("flush_dns_cache")[0]
    ok, _message, text = session.create("restart_vpn", "network")
    assert ok and 'NAME = "restart_vpn"' in text and '("network",)' in text
    assert session.check("restart_vpn", text) == []


def test_creating_writes_nothing_until_saved(tmp_path):
    session, store = make_session(tmp_path)
    session.create("restart_vpn")
    assert not (tmp_path / "u").exists()
    assert store.info("restart_vpn") is None


def test_only_repairs_ask_before_a_test_run(tmp_path):
    session, store = make_session(tmp_path)
    assert session.needs_confirmation("flush_dns_cache")
    assert not session.needs_confirmation("check_interface_state")
    assert not session.needs_confirmation("never_heard_of_it")


def test_test_run_refuses_text_that_does_not_check(tmp_path):
    called = []
    session, _ = make_session(tmp_path, run_source=lambda *a: called.append(a))
    out = session.test_run("my_check", "def run(ctx:\n")
    assert out.startswith("not run:") and called == []


def test_test_run_runs_the_text_given_not_the_saved_file(tmp_path):
    seen = []

    def run_source(name, text, classification):
        seen.append((name, text, classification))
        return RunResult("ok: pretend", log=["a note"])

    session, store = make_session(tmp_path, run_source=run_source)
    store.save("my_check", CUSTOM)
    edited = CUSTOM.replace("custom ran", "edited")
    out = session.test_run("my_check", edited)
    assert seen == [("my_check", edited, "dns")]
    assert "outcome: ok: pretend" in out and "a note" in out and "(0.50s)" in out


def test_a_raising_runner_does_not_escape_the_editor(tmp_path):
    def boom(*a):
        raise ValueError("secret detail")

    session, _ = make_session(tmp_path, run_source=boom)
    out = session.test_run("my_check", CUSTOM)
    assert out == "failed: the run raised ValueError"


def test_the_traceback_is_shown_in_the_editor_only():
    out = format_run("s", RunResult("failed: the s step raised OSError", detail="Traceback..."), 1)
    assert "Traceback..." in out and "never recorded" in out


def test_the_description_reads_like_documentation(tmp_path):
    session, _ = make_session(tmp_path)
    text = session.description("renew_dhcp_lease")
    assert "repair" in text and "needs the sudoers grant" in text and "lease_time" in text


# --- the app -----------------------------------------------------------------


def test_the_store_build_gets_no_editor_and_no_custom_scripts(tmp_path):
    caps = distribution.detect({"NETDNS_DISTRIBUTION": "appstore"})
    assert not caps.remediation_editor
    store = build_remediation_store(caps, env={REMEDIATION_DIR_ENV: str(tmp_path)})
    assert not store.editable
    assert store.save("my_check", CUSTOM)


def test_the_direct_build_uses_the_configured_folder(tmp_path):
    store = build_remediation_store(DIRECT, env={REMEDIATION_DIR_ENV: str(tmp_path / "r")})
    assert store.editable and store.user_dir == tmp_path / "r"


def test_the_store_build_menu_and_dashboard_leave_the_editor_out(tmp_path):
    app = build_app(tmp_path, capabilities=STORE)
    assert "Edit remediation scripts" not in [str(k) for k in app.menu]
    ids = [action_id for _, action_id, _ in app.dashboard_actions()]
    assert "open_remediation_editor" not in ids


def test_the_store_build_answers_the_editor_with_the_unavailable_text(tmp_path):
    app = build_app(tmp_path, capabilities=STORE)
    app.open_remediation_editor()
    assert app.notes == [
        (
            "Remediation scripts",
            distribution.unavailable("remediation_editor", "the remediation script editor"),
        )
    ]
    assert app.remediation_window is None


def test_the_direct_build_has_the_menu_item_and_button(tmp_path):
    app = build_app(tmp_path, capabilities=DIRECT)
    assert "Edit remediation scripts" in [str(k) for k in app.menu]
    ids = [action_id for _, action_id, _ in app.dashboard_actions()]
    assert "open_remediation_editor" in ids


def test_a_custom_script_joins_the_apps_ladder_and_its_diagnosis(tmp_path, monkeypatch):
    monkeypatch.setenv(REMEDIATION_DIR_ENV, str(tmp_path / "scripts"))
    app = build_app(tmp_path, capabilities=DIRECT)
    assert app.remediation_store.save("my_check", CUSTOM) == []
    from netdnsmonitor.classifier import Classification

    names = [s.name for s in app.state_machine.ladder(Classification.DNS)]
    assert "my_check" in names
    assert [s.name for s in app._custom_remediation_steps("dns")] == ["my_check"]
    assert app._custom_remediation_steps("network") == []


def test_a_window_that_fails_to_build_costs_the_editor_and_nothing_else(tmp_path, monkeypatch):
    from netdnsmonitor import remediation_window

    def explode(self):
        raise RuntimeError("no window server")

    monkeypatch.setattr(remediation_window.RemediationWindowController, "show", explode)
    posted = []
    app = build_app(tmp_path, capabilities=DIRECT)
    app._notify = lambda subtitle, message: posted.append((subtitle, message))
    app.open_remediation_editor()
    assert app.remediation_window is None
    assert "RuntimeError" in posted[0][1] and "no window server" not in posted[0][1]
