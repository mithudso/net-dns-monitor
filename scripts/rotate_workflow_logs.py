#!/usr/bin/env python3
"""Move old version sections of the append-forever work journals into docs/archive/.

`memory.md` and `prompts.md` gain a `## vN - date` section per work entry and are
never trimmed by hand. Once a journal crosses --max-bytes, this keeps its header
and the newest --keep sections and appends the rest to
`docs/archive/<name>-archive.md`. Below the threshold it changes nothing.
"""

import argparse
import fcntl
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from itertools import pairwise
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JOURNALS = ("memory.md", "prompts.md")
MAX_BYTES = 200_000
KEEP_SECTIONS = 5
SECTION = re.compile(r"^## v\d+\b", re.MULTILINE)


@contextmanager
def journal_lock(path: Path) -> Iterator[None]:
    """Journal writers must hold this same lock across their read/write cycle.

    Keep the lock inode in place: unlinking it would let later writers lock a
    different file while an earlier waiter still holds the original inode.
    """
    lock = path.with_name(f".{path.name}.rotate.lock")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir_durable(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(exist_ok=True)
        _fsync_directory(directory.parent)


def swap_files(path: Path) -> list[Path]:
    """Editor lock/swap files that mean someone has the journal open right now.

    Rewriting under an open editor loses data both ways: the editor's next save
    restores the rotated sections, or its buffer silently drops this rewrite.
    """
    candidates = [
        path.with_name(f".{path.name}.swp"),
        path.with_name(f".{path.name}.swo"),
        path.with_name(f".#{path.name}"),
        path.with_name(f"#{path.name}#"),
    ]
    return [p for p in candidates if p.exists() or p.is_symlink()]


def split_sections(text: str) -> tuple[str, list[str]]:
    starts = [m.start() for m in SECTION.finditer(text)]
    if not starts:
        return text, []
    bounds = starts + [len(text)]
    return text[: starts[0]], [text[a:b] for a, b in pairwise(bounds)]


def _write_atomic(path: Path, text: str, new_mode: int = 0o644) -> None:
    """Replace `path` with `text`, keeping its mode (or `new_mode` if it is new).

    mkstemp creates 0600, so a plain replace silently tightened a 0644 journal.
    The data is fsynced before the rename: without it a crash can leave the
    renamed file empty, and the archive-first ordering below would lose sections.
    """
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else new_mode
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_directory(path.parent)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def rotate(
    path: Path,
    archive_dir: Path,
    max_bytes: int = MAX_BYTES,
    keep: int = KEEP_SECTIONS,
    dry_run: bool = False,
) -> str:
    """Return a one-line outcome. Never raises for a missing or locked journal."""
    if not path.exists():
        return f"{path.name}: missing, skipped"
    with journal_lock(path):
        return _rotate(path, archive_dir, max_bytes, keep, dry_run)


def _rotate(path: Path, archive_dir: Path, max_bytes: int, keep: int, dry_run: bool) -> str:
    locks = swap_files(path)
    if locks:
        return f"{path.name}: refused, editor swap file present ({locks[0].name})"
    size = path.stat().st_size
    if size <= max_bytes:
        return f"{path.name}: {size} bytes, under {max_bytes}, unchanged"
    original = path.read_bytes()
    header, sections = split_sections(original.decode("utf-8"))
    old, recent = sections[: max(len(sections) - keep, 0)], sections[-keep:]
    if not old:
        return f"{path.name}: {size} bytes but only {len(sections)} sections, unchanged"
    if dry_run:
        return f"{path.name}: would archive {len(old)} sections"
    archive = archive_dir / f"{path.stem}-archive.md"
    _mkdir_durable(archive_dir)
    existing = (
        archive.read_text(encoding="utf-8")
        if archive.exists()
        else (f"# {path.name} archive\n\nOlder sections rotated out of `{path.name}`.\n\n")
    )
    # Archive first, journal second: a crash between the two duplicates the
    # rotated sections in both files instead of losing them.
    journal_mode = stat.S_IMODE(path.stat().st_mode)
    _write_atomic(
        archive,
        existing.rstrip("\n") + "\n\n" + "".join(old).strip("\n") + "\n",
        new_mode=journal_mode,
    )
    # Refuse a detected noncooperating writer. Full serialization requires
    # every writer to use journal_lock; atomic rename alone cannot provide it.
    if path.read_bytes() != original or swap_files(path):
        return f"{path.name}: refused, journal changed during rotation; archive retained"
    _write_atomic(path, header + "".join(recent))
    return f"{path.name}: archived {len(old)} sections to {archive}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    parser.add_argument("--keep", type=int, default=KEEP_SECTIONS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.keep < 1:
        parser.error("--keep must be at least 1")
    refused = False
    for name in JOURNALS:
        outcome = rotate(
            args.root / name, args.root / "docs/archive", args.max_bytes, args.keep, args.dry_run
        )
        print(outcome)
        refused |= "refused" in outcome
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
