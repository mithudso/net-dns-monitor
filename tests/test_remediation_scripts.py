"""The remediation scripts: shipped files, the store, the runner, the ladder join.

Nothing here runs a real command. Scripts get a `ctx` whose `run` is a fake, and
the user directory is always a tmp_path.
"""

import ast
import re
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from netdnsmonitor import repair_executor
from netdnsmonitor.classifier import Classification
from netdnsmonitor.ladder import (
    DNS_LADDER,
    FAILOVER_STEP,
    NETWORK_LADDER,
    LadderStep,
    ladder_for,
)
from netdnsmonitor.remediation_scripts import (
    BUILTIN_DIR,
    ORIGIN_BUILTIN,
    ORIGIN_CUSTOM,
    ORIGIN_MODIFIED,
    ScriptStore,
    builtin_steps,
    execute,
    inspect_source,
    new_script_template,
)
from netdnsmonitor.state_machine import StateMachine

ROOT = Path(__file__).resolve().parent.parent

CUSTOM = textwrap.dedent(
    '''
    """my_check -- a custom check."""

    NAME = "my_check"
    KIND = "check"
    NEEDS_PRIVILEGE = False
    REASON = "because"
    CLASSIFICATIONS = ("dns",)
    ORDER = 5


    def run(ctx):
        return "ok: custom ran"
    '''
).lstrip()


def fake_run(returncode=0, stdout="out", stderr=""):
    def run(args, **kwargs):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return run


# --- the shipped scripts -----------------------------------------------------


def test_every_ladder_step_has_a_shipped_script_that_matches_it():
    for step in builtin_steps():
        source = (BUILTIN_DIR / f"{step.name}.py").read_text()
        meta, problems = inspect_source(source, expected_name=step.name)
        assert problems == [], step.name
        assert meta["KIND"] == step.kind
        assert meta["NEEDS_PRIVILEGE"] == step.needs_privilege
        assert meta["REASON"] == step.reason


def test_a_shipped_script_declares_the_ladders_it_belongs_to():
    for classification, ladder in (("network", NETWORK_LADDER), ("dns", DNS_LADDER)):
        for step in ladder:
            meta, _ = inspect_source((BUILTIN_DIR / f"{step.name}.py").read_text())
            assert classification in meta["CLASSIFICATIONS"], step.name
    meta, _ = inspect_source((BUILTIN_DIR / f"{FAILOVER_STEP.name}.py").read_text())
    assert "network" in meta["CLASSIFICATIONS"]


def test_no_shipped_script_is_orphaned_or_missing():
    on_disk = {p.stem for p in BUILTIN_DIR.glob("*.py") if not p.name.startswith("_")}
    assert on_disk == {step.name for step in builtin_steps()}


def test_shipped_scripts_reach_the_machine_only_through_ctx():
    """CLAUDE.md non-negotiable 3, applied to the scripts: the injected callable
    touches the network, the script never does.
    """
    forbidden = {"socket", "subprocess", "urllib", "http", "ssl", "smtplib", "os", "shutil"}
    for path in BUILTIN_DIR.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            assert not forbidden.intersection(names), f"{path.name} imports {names}"


def test_every_shipped_script_is_documented_in_the_manual_and_in_its_docstring():
    manual = (ROOT / "docs" / "REMEDIATION_SCRIPTS.md").read_text()
    for step in builtin_steps():
        meta, _ = inspect_source((BUILTIN_DIR / f"{step.name}.py").read_text())
        assert len(meta["DESCRIPTION"]) > 200, f"{step.name} needs a fuller docstring"
        assert step.name in manual, f"{step.name} is not in docs/REMEDIATION_SCRIPTS.md"


def test_every_ctx_field_is_documented_in_the_manual():
    manual = (ROOT / "docs" / "REMEDIATION_SCRIPTS.md").read_text()
    for field in repair_executor.RemediationContext.__dataclass_fields__:
        assert f"ctx.{field}" in manual, f"ctx.{field} is not documented"
    for constant in (
        "DSCACHEUTIL",
        "SCUTIL",
        "NETSTAT",
        "SUDO",
        "IPCONFIG",
        "KILLALL",
        "MDNS_HUP",
        "ALL_INTERFACES_SENTINEL",
        "RESOLVER_DIR",
        "GRANT_HINT",
    ):
        assert f"ctx.tools.{constant}" in manual


# --- inspecting source -------------------------------------------------------


def test_a_valid_script_has_no_problems():
    meta, problems = inspect_source(CUSTOM, expected_name="my_check")
    assert problems == []
    assert meta["CLASSIFICATIONS"] == ("dns",)
    assert meta["ORDER"] == 5
    assert meta["DESCRIPTION"].startswith("my_check")


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda s: s.replace("def run(ctx):", "def go(ctx):"), "run(ctx)"),
        (lambda s: s.replace('KIND = "check"', 'KIND = "fix"'), "KIND must be"),
        (lambda s: s.replace('NAME = "my_check"', 'NAME = "other"'), "must match"),
        (lambda s: s.replace('NAME = "my_check"', 'NAME = "../x"'), "NAME must be lowercase"),
        (lambda s: s.replace('("dns",)', '("wifi",)'), "CLASSIFICATIONS"),
        (lambda s: s.replace("ORDER = 5", "ORDER = True"), "ORDER has the wrong type"),
        (lambda s: s.replace("ORDER = 5", "ORDER = len('x')"), "ORDER must be a literal"),
        (lambda s: s.replace("return", "return (", 1), "syntax error"),
        (lambda s: s.replace('NAME = "my_check"\n', ""), "NAME is required"),
        (lambda s: s.replace("def run(ctx):", "def run():"), "run(ctx)"),
    ],
)
def test_inspect_source_names_what_is_wrong(mutation, expected):
    _meta, problems = inspect_source(mutation(CUSTOM), expected_name="my_check")
    assert any(expected in problem for problem in problems), problems


def test_a_nul_byte_is_a_problem_not_a_crash():
    _meta, problems = inspect_source("x = 1\0\n", expected_name="x")
    assert problems


def test_listing_and_inspecting_never_execute_a_script(tmp_path):
    marker = tmp_path / "ran"
    evil = CUSTOM + f"\nopen({str(marker)!r}, 'w').write('x')\nraise SystemExit(1)\n"
    store = ScriptStore(user_dir=tmp_path / "u")
    assert store.save("my_check", evil) == []
    store.list_scripts()
    store.custom_steps("dns")
    store.info("my_check")
    assert not marker.exists()


# --- running -----------------------------------------------------------------


def test_a_raising_script_reports_the_class_not_the_message():
    source = CUSTOM.replace(
        'return "ok: custom ran"', 'raise RuntimeError("https://hooks.example/SECRET-TOKEN")'
    )
    result = execute("my_check", source, SimpleNamespace(log_lines=[]))
    assert result.outcome == "failed: the my_check step raised RuntimeError"
    assert "SECRET-TOKEN" not in result.outcome
    # The traceback is for the editor only.
    assert "SECRET-TOKEN" in result.detail


def test_sys_exit_in_a_script_is_contained():
    source = CUSTOM.replace('return "ok: custom ran"', "raise SystemExit(3)")
    result = execute("my_check", source, SimpleNamespace(log_lines=[]))
    assert result.outcome == "failed: the my_check step raised SystemExit"


def test_a_script_that_hangs_is_reported_unknown_not_waited_for():
    import threading

    gate = threading.Event()
    source = CUSTOM.replace('return "ok: custom ran"', "ctx.gate.wait(30)\n    return 'late'")
    ctx = SimpleNamespace(log_lines=[], gate=gate)
    try:
        result = execute("my_check", source, ctx, timeout=0.05)
    finally:
        gate.set()
    assert result.timed_out
    assert result.outcome.startswith("unknown: my_check did not finish")


@pytest.mark.parametrize("returned", ["None", "42", "''", "'   '", "['ok']"])
def test_a_script_must_return_an_outcome_string(returned):
    source = CUSTOM.replace('return "ok: custom ran"', f"return {returned}")
    result = execute("my_check", source, SimpleNamespace(log_lines=[]))
    assert result.outcome.startswith("failed: the my_check script returned")


def test_a_script_without_run_fails_as_data():
    result = execute("x", "NAME = 'x'\n", SimpleNamespace(log_lines=[]))
    assert result.outcome == "failed: the script defines no run(ctx)"


def test_ctx_log_is_returned_but_never_part_of_the_outcome():
    source = CUSTOM.replace('return "ok: custom ran"', 'ctx.log("detail")\n    return "ok: done"')
    ctx = SimpleNamespace(log_lines=[], log=lambda m: ctx.log_lines.append(m))
    result = execute("my_check", source, ctx)
    assert result.outcome == "ok: done"
    assert result.log == ["detail"]


# --- the store ---------------------------------------------------------------


def test_builtin_only_store_cannot_save_or_list_custom(tmp_path):
    store = ScriptStore()
    assert not store.editable
    assert store.save("my_check", CUSTOM)
    assert store.custom_steps("dns") == []
    assert store.names() == [step.name for step in builtin_steps()]


def test_editing_a_builtin_writes_an_override_and_reset_restores_it(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    original = store.source("check_interface_state")
    edited = original.replace("--nwi", "--proxy")
    assert store.save("check_interface_state", edited) == []
    assert store.info("check_interface_state").origin == ORIGIN_MODIFIED
    assert "--proxy" in store.source("check_interface_state")
    assert "--nwi" in store.builtin_source("check_interface_state")
    assert "reset" in store.remove("check_interface_state")
    assert store.source("check_interface_state") == original
    assert store.info("check_interface_state").origin == ORIGIN_BUILTIN


def test_saving_text_identical_to_the_builtin_removes_the_override(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    original = store.builtin_source("check_interface_state")
    store.save("check_interface_state", original.replace("--nwi", "--proxy"))
    assert store.save("check_interface_state", original) == []
    assert store.info("check_interface_state").origin == ORIGIN_BUILTIN
    assert not (tmp_path / "u" / "check_interface_state.py").exists()


def test_invalid_text_is_not_saved(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    problems = store.save("my_check", "def run(ctx:\n")
    assert problems and "syntax error" in problems[0]
    assert not (tmp_path / "u").exists() or not list((tmp_path / "u").iterdir())


@pytest.mark.parametrize("name", ["../evil", "a/b", "", "Upper", "x" * 70, ".hidden", "a b"])
def test_a_name_cannot_escape_the_directory(tmp_path, name):
    store = ScriptStore(user_dir=tmp_path / "u")
    assert store.save(name, CUSTOM)
    assert store.user_source(name) is None
    assert store.remove(name)  # a message, not an unlink outside the folder


def test_saved_files_are_private_to_the_user(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    store.save("my_check", CUSTOM)
    assert (tmp_path / "u" / "my_check.py").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "u").stat().st_mode & 0o777 == 0o700


def test_custom_steps_are_ordered_and_filtered(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    store.save("my_check", CUSTOM)
    store.save("zz_net", CUSTOM.replace("my_check", "zz_net").replace('("dns",)', '("network",)'))
    store.save("aa_late", CUSTOM.replace("my_check", "aa_late").replace("ORDER = 5", "ORDER = 50"))
    off = CUSTOM.replace("my_check", "off_one").replace(
        "NEEDS_PRIVILEGE", "ENABLED = False\nNEEDS_PRIVILEGE"
    )
    store.save("off_one", off)
    assert [s.name for s in store.custom_steps("dns")] == ["my_check", "aa_late"]
    assert [s.name for s in store.custom_steps("network")] == ["zz_net"]
    assert store.info("my_check").origin == ORIGIN_CUSTOM


def test_a_broken_custom_file_adds_no_step_and_is_listed_invalid(tmp_path):
    user = tmp_path / "u"
    user.mkdir()
    (user / "my_check.py").write_text("def run(ctx:\n")
    store = ScriptStore(user_dir=user)
    assert store.custom_steps("dns") == []
    assert not store.info("my_check").valid


def test_a_custom_script_cannot_shadow_a_builtin_step_on_the_ladder(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    store.save("flush_dns_cache", store.builtin_source("flush_dns_cache") + "\n# edited\n")
    assert store.custom_steps("dns") == []


# --- the executor ------------------------------------------------------------


def test_an_edited_builtin_runs_in_place_of_the_shipped_one(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    edited = store.builtin_source("check_interface_state").replace(
        'ctx.report_command([ctx.tools.SCUTIL, "--nwi"])', 'f"edited {ctx.tools.SCUTIL}"'
    )
    assert store.save("check_interface_state", edited) == []
    executor = repair_executor.make_repair_executor(run_fn=fake_run(), store=store)
    step = LadderStep("check_interface_state", "check", False)
    assert executor(step) == f"edited {repair_executor.SCUTIL}"


def test_a_custom_script_runs_through_the_executor(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    store.save("my_check", CUSTOM)
    executor = repair_executor.make_repair_executor(run_fn=fake_run(), store=store)
    assert executor(LadderStep("my_check", "check", False)) == "ok: custom ran"


def test_a_broken_override_fails_loudly_instead_of_falling_back(tmp_path):
    user = tmp_path / "u"
    user.mkdir()
    (user / "flush_dns_cache.py").write_text("def run(ctx:\n")
    executor = repair_executor.make_repair_executor(
        run_fn=fake_run(), store=ScriptStore(user_dir=user)
    )
    outcome = executor(LadderStep("flush_dns_cache", "repair", False))
    assert outcome.startswith("failed: the flush_dns_cache script is invalid")


def test_a_disabled_script_is_reported_skipped(tmp_path):
    store = ScriptStore(user_dir=tmp_path / "u")
    shipped = store.builtin_source("flush_dns_cache")
    store.save("flush_dns_cache", shipped.replace("ENABLED = True", "ENABLED = False"))
    ran = []
    executor = repair_executor.make_repair_executor(
        run_fn=lambda *a, **k: ran.append(a) or fake_run()(*a), store=store
    )
    outcome = executor(LadderStep("flush_dns_cache", "repair", False))
    assert outcome.startswith("skipped:")
    assert ran == []


def test_the_default_executor_never_reads_a_user_directory(tmp_path, monkeypatch):
    user = (
        tmp_path / "home" / "Library" / "Application Support" / "net-dns-monitor" / "remediations"
    )
    user.mkdir(parents=True)
    (user / "flush_dns_cache.py").write_text("raise SystemExit\n")
    executor = repair_executor.make_repair_executor(run_fn=fake_run())
    assert executor(LadderStep("flush_dns_cache", "repair", False)) == "ok"


def test_unknown_step_still_says_so():
    executor = repair_executor.make_repair_executor(run_fn=fake_run())
    assert executor(LadderStep("nope", "check", False)) == "unknown step: nope"


def test_the_editor_test_run_executes_unsaved_text():
    executor = repair_executor.make_repair_executor(run_fn=fake_run())
    result = executor.run_source("my_check", CUSTOM, "dns")
    assert result.outcome == "ok: custom ran"


def test_a_script_sees_the_classification_it_runs_for():
    executor = repair_executor.make_repair_executor(run_fn=fake_run())
    source = CUSTOM.replace('return "ok: custom ran"', "return f'ok: {ctx.classification}'")
    assert executor.run_source("my_check", source, "dns").outcome == "ok: dns"


def test_the_failover_script_still_refuses_without_a_classification():
    executor = repair_executor.make_repair_executor(
        run_fn=fake_run(), failover_fn=lambda c: "never"
    )
    assert executor(FAILOVER_STEP).startswith("refused:")
    assert executor(FAILOVER_STEP, "network") == "never"


# --- the ladder --------------------------------------------------------------


def test_custom_steps_run_after_shipped_steps_and_before_the_failover():
    extra = [LadderStep("mine", "check", False)]
    names = [s.name for s in ladder_for(Classification.NETWORK, frozenset({"network"}), extra)]
    assert names[-2:] == ["mine", "switch_to_backup_network"]
    assert names[: len(NETWORK_LADDER)] == [s.name for s in NETWORK_LADDER]


def test_a_custom_step_cannot_duplicate_a_shipped_one():
    extra = [LadderStep("flush_dns_cache", "repair", False)]
    names = [s.name for s in ladder_for(Classification.DNS, frozenset(), extra)]
    assert names.count("flush_dns_cache") == 1


def test_no_ladder_for_a_healthy_or_unclassified_network_even_with_custom_steps():
    extra = [LadderStep("mine", "check", False)]
    assert ladder_for(Classification.HEALTHY, frozenset(), extra) == []
    assert ladder_for(Classification.UNCLASSIFIED, frozenset(), extra) == []


def make_machine(custom_steps_fn):
    return StateMachine(
        prober=lambda: {},
        repair_executor=lambda step, classification=None: "ok",
        escalator=lambda bundle: {},
        custom_steps_fn=custom_steps_fn,
    )


def test_the_state_machine_asks_for_custom_steps_by_classification_value():
    seen = []

    def custom(value):
        seen.append(value)
        return [LadderStep("mine", "check", False)]

    machine = make_machine(custom)
    names = [s.name for s in machine.ladder(Classification.DNS)]
    assert seen == ["dns"] and "mine" in names


def test_a_raising_custom_step_source_leaves_the_shipped_ladder_intact():
    def boom(value):
        raise OSError("unreadable")

    names = [s.name for s in make_machine(boom).ladder(Classification.DNS)]
    assert names == [s.name for s in DNS_LADDER]


def test_template_is_a_valid_script():
    for classification in ("dns", "network"):
        _meta, problems = inspect_source(
            new_script_template("restart_vpn", classification), expected_name="restart_vpn"
        )
        assert problems == []
    assert re.search(r"def run\(ctx\)", new_script_template("restart_vpn"))
