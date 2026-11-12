"""Static documentation failures must name the broken artifact before it ships."""

import importlib.util
import json
import os
import subprocess
from collections import Counter
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "check_docs", Path(__file__).resolve().parent.parent / "scripts/check_docs.py"
)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def _index(root, paths):
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs/high_signal_file_index.json").write_text(
        json.dumps({"files": [{"path": path} for path in paths]})
    )


def test_dead_and_escaping_paths_are_reported(tmp_path):
    _index(tmp_path, ["missing.py", "../outside.py"])
    errors = checker.check_paths(tmp_path)
    assert "index path does not exist: missing.py" in errors
    assert "index path escapes repository: ../outside.py" in errors


def test_valid_paths_do_not_start_any_index_service(tmp_path):
    (tmp_path / "module.py").write_text("pass\n")
    _index(tmp_path, ["module.py"])
    assert checker.check_paths(tmp_path) == []


def test_duplicate_and_malformed_entries_are_reported(tmp_path):
    _index(tmp_path, ["module.py", "module.py"])
    errors = checker.check_paths(tmp_path)
    assert any("duplicate file paths" in error for error in errors)
    (tmp_path / "docs/high_signal_file_index.json").write_text('{"files": [{}]}')
    assert any("no nonempty path" in error for error in checker.check_paths(tmp_path))


def test_dossier_census_and_sources_must_match_cards(tmp_path):
    _index(tmp_path, [])
    dossier = tmp_path / "docs/llms"
    dossier.mkdir()
    (dossier / "filemap.json").write_text('[{"path": "missing.py"}]')
    (dossier / "manifest.json").write_text(
        json.dumps({"enumerated": 2, "source_files": [], "emitted_files": []})
    )
    errors = checker.check_paths(tmp_path)
    assert any("census differs" in error for error in errors)
    assert any("source_files differ" in error for error in errors)


def test_dossier_rejects_malformed_sources_and_unlisted_outputs(tmp_path):
    _index(tmp_path, [])
    dossier = tmp_path / "docs/llms"
    dossier.mkdir()
    (dossier / "filemap.json").write_text("[]")
    (dossier / "manifest.json").write_text(
        json.dumps({"enumerated": 0, "source_files": [{}], "emitted_files": []})
    )
    errors = checker.check_paths(tmp_path)
    assert any("source_files differ" in error for error in errors)
    assert any("emitted_files differ from directory" in error for error in errors)


def _count_docs(root, count, rows):
    (root / "docs").mkdir(exist_ok=True)
    (root / "CLAUDE.md").write_text(f"# {count} tests, offline\n")
    (root / "docs/TESTING.md").write_text(f"{count} tests, offline\n")
    (root / "docs/codebase-overview.md").write_text(f"the count (`{count}`).\n")
    (root / "docs/SCRIPTS.md").write_text(f"{count} tests\n{rows}\n| **{count}** | **total** |\n")


def test_stale_total_and_missing_file_row_are_reported(tmp_path):
    _count_docs(tmp_path, 1, "| 1 | `test_old.py` |")
    errors = checker.check_test_counts(tmp_path, Counter({"test_new.py": 2}))
    assert any("published total 1; collection has 2" in error for error in errors)
    assert any("test_new.py has no row" in error for error in errors)
    assert any("test_old.py" in error for error in errors)


def test_collected_node_ids_drive_matching_totals_and_distribution(tmp_path):
    output = "tests/test_a.py::test_one[x]\ntests/test_a.py::test_one[y]\n2 tests collected\n"
    counts = checker.collected_counts(output)
    assert counts == Counter({"test_a.py": 2})
    _count_docs(tmp_path, 2, "| 2 | `test_a.py` |")
    assert checker.check_test_counts(tmp_path, counts) == []


def _git_fixture(root, monkeypatch):
    template = root / "empty-template"
    template.mkdir()
    for name in tuple(os.environ):
        if name.startswith("GIT_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
    subprocess.run(
        ["git", "init", "--template=" + str(template)], cwd=root, check=True, capture_output=True
    )
    hooks = subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-path", "hooks"],
        cwd=root,
        text=True,
    ).strip()
    if Path(hooks).exists():
        assert not list(Path(hooks).iterdir())
    (root / "netdnsmonitor").mkdir()
    (root / "netdnsmonitor/new.py").write_text("VALUE = 1\n")
    _index(root, ["netdnsmonitor/new.py"])
    (root / "docs/COMPONENTS.md").write_text("# Components\n")


def _dossier(root, paths):
    directory = root / "docs/llms"
    directory.mkdir()
    (directory / "filemap.json").write_text(json.dumps([{"path": path} for path in paths]))
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "enumerated": len(paths),
                "source_files": paths,
                "emitted_files": ["filemap.json", "manifest.json"],
            }
        )
    )


def test_mutually_consistent_old_dossier_cannot_omit_current_source(tmp_path, monkeypatch):
    _git_fixture(tmp_path, monkeypatch)
    _dossier(tmp_path, [])
    errors = checker.check_paths(tmp_path)
    assert "census missing current source: netdnsmonitor/new.py" in errors


def test_component_map_cannot_omit_a_current_runtime_module(tmp_path, monkeypatch):
    _git_fixture(tmp_path, monkeypatch)
    errors = checker.check_paths(tmp_path)
    assert "component map missing current module: netdnsmonitor/new.py" in errors


def test_ci_and_hook_ruff_versions_must_match(tmp_path, monkeypatch):
    _git_fixture(tmp_path, monkeypatch)
    (tmp_path / "requirements-dev.txt").write_text("ruff==0.16.10\n")
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.16.9\n"
    )
    assert (
        "Ruff hook version 0.16.9 differs from requirements-dev.txt 0.16.10"
        in checker.check_paths(tmp_path)
    )


def test_source_census_does_not_follow_a_replaced_parent_directory(tmp_path, monkeypatch):
    _git_fixture(tmp_path, monkeypatch)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    outside = tmp_path.parent / (tmp_path.name + "-synthetic-profile")
    outside.mkdir()
    (outside / "new.py").write_text("synthetic profile fixture\n")
    (tmp_path / "netdnsmonitor/new.py").unlink()
    (tmp_path / "netdnsmonitor").rmdir()
    (tmp_path / "netdnsmonitor").symlink_to(outside, target_is_directory=True)
    assert "netdnsmonitor/new.py" not in checker.census_paths(tmp_path)


def test_static_census_excludes_even_tracked_ignored_private_files(tmp_path, monkeypatch):
    _git_fixture(tmp_path, monkeypatch)
    (tmp_path / "docs/high_signal_file_index.json").write_text(
        json.dumps({"files": [{"path": "netdnsmonitor/new.py", "importance": "ordinary"}]})
    )
    (tmp_path / ".gitignore").write_text("private.txt\n")
    (tmp_path / "private.txt").write_text("synthetic fixture, not customer data\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "add", "--force", "private.txt"], cwd=tmp_path, check=True, capture_output=True
    )
    # Staged files are sufficient for the census; no fixture commit is needed.
    spec = importlib.util.spec_from_file_location(
        "fixture_dossier",
        Path(__file__).resolve().parent.parent / "scripts/generate_static_dossier.py",
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    monkeypatch.setattr(
        generator, "git", lambda *args: "synthetic" if args[0] == "rev-parse" else ""
    )
    monkeypatch.setattr(generator, "ROOT", tmp_path)
    monkeypatch.setattr(generator, "OUT", tmp_path / "docs/llms")
    generator.main()
    cards = json.loads((tmp_path / "docs/llms/filemap.json").read_text())
    assert "private.txt" not in {card["path"] for card in cards}
