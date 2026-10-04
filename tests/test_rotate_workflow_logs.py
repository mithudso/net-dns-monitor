"""Journal rotation must never lose a section or rewrite a journal under an open editor."""

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "rotate_workflow_logs",
    Path(__file__).resolve().parent.parent / "scripts/rotate_workflow_logs.py",
)
rotator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rotator)

HEADER = "# Work Memory\n\nIntro.\n\n"


def _journal(path: Path, count: int) -> str:
    text = HEADER + "".join(
        f"## v{n} - 2026-10-0{n % 9 + 1} - entry {n}\n\nbody {n}\n\n" for n in range(1, count + 1)
    )
    path.write_text(text)
    return text


def test_under_threshold_is_unchanged(tmp_path):
    journal = tmp_path / "memory.md"
    text = _journal(journal, 8)
    outcome = rotator.rotate(journal, tmp_path / "docs/archive", max_bytes=10_000, keep=3)
    assert "unchanged" in outcome
    assert journal.read_text() == text
    assert not (tmp_path / "docs/archive").exists()


def test_rotation_keeps_header_and_newest_and_loses_nothing(tmp_path):
    journal = tmp_path / "memory.md"
    original = _journal(journal, 8)
    outcome = rotator.rotate(journal, tmp_path / "docs/archive", max_bytes=10, keep=3)
    assert "archived 5 sections" in outcome
    kept = journal.read_text()
    archived = (tmp_path / "docs/archive/memory-archive.md").read_text()
    assert kept.startswith(HEADER)
    assert [line for line in kept.splitlines() if line.startswith("## v")] == [
        line for line in original.splitlines() if line.startswith("## v")
    ][-3:]
    for n in range(1, 9):
        assert f"body {n}\n" in (archived if n <= 5 else kept)


def test_second_rotation_appends_to_archive(tmp_path):
    journal = tmp_path / "prompts.md"
    _journal(journal, 6)
    archive_dir = tmp_path / "docs/archive"
    rotator.rotate(journal, archive_dir, max_bytes=10, keep=4)
    with journal.open("a") as handle:
        handle.write("## v7 - 2026-10-05 - more\n\nbody 7\n\n")
    rotator.rotate(journal, archive_dir, max_bytes=10, keep=4)
    archived = (archive_dir / "prompts-archive.md").read_text()
    assert archived.count("# prompts.md archive") == 1
    assert [f"body {n}\n" in archived for n in range(1, 8)] == [True] * 3 + [False] * 4


def test_editor_swap_file_refuses(tmp_path):
    journal = tmp_path / "memory.md"
    text = _journal(journal, 8)
    (tmp_path / ".memory.md.swp").write_text("")
    outcome = rotator.rotate(journal, tmp_path / "docs/archive", max_bytes=10, keep=3)
    assert "refused" in outcome
    assert journal.read_text() == text


def test_dry_run_writes_nothing(tmp_path):
    journal = tmp_path / "memory.md"
    text = _journal(journal, 8)
    outcome = rotator.rotate(journal, tmp_path / "docs/archive", max_bytes=10, keep=3, dry_run=True)
    assert "would archive 5" in outcome
    assert journal.read_text() == text
    assert not (tmp_path / "docs/archive").exists()


def test_main_exits_nonzero_when_a_journal_is_locked(tmp_path, capsys):
    _journal(tmp_path / "memory.md", 4)
    (tmp_path / ".#prompts.md").symlink_to("nowhere")
    (tmp_path / "prompts.md").write_text(HEADER)
    assert rotator.main(["--root", str(tmp_path), "--max-bytes", "10"]) == 1
    assert "prompts.md: refused" in capsys.readouterr().out
