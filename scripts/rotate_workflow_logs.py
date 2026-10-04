#!/usr/bin/env python3
"""Move old version sections of the append-forever work journals into docs/archive/.

`memory.md` and `prompts.md` gain a `## vN - date` section per work entry and are
never trimmed by hand. Once a journal crosses --max-bytes, this keeps its header
and the newest --keep sections and appends the rest to
`docs/archive/<name>-archive.md`. Below the threshold it changes nothing.
"""

import argparse
import os
import re
import sys
import tempfile
from itertools import pairwise
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JOURNALS = ("memory.md", "prompts.md")
MAX_BYTES = 200_000
KEEP_SECTIONS = 5
SECTION = re.compile(r"^## v\d+\b", re.MULTILINE)


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


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
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
    locks = swap_files(path)
    if locks:
        return f"{path.name}: refused, editor swap file present ({locks[0].name})"
    size = path.stat().st_size
    if size <= max_bytes:
        return f"{path.name}: {size} bytes, under {max_bytes}, unchanged"
    header, sections = split_sections(path.read_text(encoding="utf-8"))
    old, recent = sections[: max(len(sections) - keep, 0)], sections[-keep:]
    if not old:
        return f"{path.name}: {size} bytes but only {len(sections)} sections, unchanged"
    if dry_run:
        return f"{path.name}: would archive {len(old)} sections"
    archive = archive_dir / f"{path.stem}-archive.md"
    archive_dir.mkdir(parents=True, exist_ok=True)
    existing = (
        archive.read_text(encoding="utf-8")
        if archive.exists()
        else (f"# {path.name} archive\n\nOlder sections rotated out of `{path.name}`.\n\n")
    )
    # Archive first, journal second: a crash between the two duplicates the
    # rotated sections in both files instead of losing them.
    _write_atomic(archive, existing.rstrip("\n") + "\n\n" + "".join(old).strip("\n") + "\n")
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
