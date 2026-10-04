"""Static documentation failures must name the broken artifact before it ships."""

import importlib.util
import json
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
