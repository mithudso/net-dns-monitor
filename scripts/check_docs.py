#!/usr/bin/env python3
"""Check static retrieval paths and published test counts without semantic queries.

Use --collect-tests to compare documentation with pytest collection. This starts
only the offline collector, never the app, Chroma, Ollama, or the file watcher.
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COUNT_DOCS = (
    "CLAUDE.md",
    "docs/TESTING.md",
    "docs/SCRIPTS.md",
    "docs/codebase-overview.md",
)


def _read_json(path: Path, errors: list[str]):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append(f"{path.name}: could not read JSON ({type(exc).__name__})")
        return None


def _paths(entries, name: str, errors: list[str]) -> list[str]:
    if not isinstance(entries, list):
        errors.append(f"{name}: expected a files array")
        return []
    paths = []
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path:
            errors.append(f"{name}: entry has no nonempty path")
        else:
            paths.append(path)
    if len(paths) != len(set(paths)):
        errors.append(f"{name}: duplicate file paths")
    return paths


def check_paths(root: Path) -> list[str]:
    errors: list[str] = []
    index_name = "docs/high_signal_file_index.json"
    index = _read_json(root / index_name, errors)
    if not isinstance(index, dict):
        if index is not None:
            errors.append(f"{index_name}: expected an object")
        return errors
    paths = _paths(index.get("files"), index_name, errors)
    dossier = root / "docs/llms"
    if dossier.exists():
        cards = _read_json(dossier / "filemap.json", errors)
        manifest = _read_json(dossier / "manifest.json", errors)
        card_paths = _paths(cards, "docs/llms/filemap.json", errors)
        paths.extend(card_paths)
        if isinstance(manifest, dict):
            if manifest.get("enumerated") != len(card_paths):
                errors.append("docs/llms/manifest.json: census differs from filemap count")
            sources = manifest.get("source_files")
            if (
                not isinstance(sources, list)
                or any(not isinstance(path, str) for path in sources)
                or len(sources) != len(set(sources))
                or set(sources) != set(card_paths)
            ):
                errors.append("docs/llms/manifest.json: source_files differ from filemap")
            emitted = manifest.get("emitted_files")
            if not isinstance(emitted, list) or any(not isinstance(p, str) for p in emitted):
                errors.append("docs/llms/manifest.json: expected emitted_files string array")
            else:
                paths.extend(f"docs/llms/{path}" for path in emitted)
                actual = {path.name for path in dossier.iterdir() if path.is_file()}
                if set(emitted) != actual or len(emitted) != len(set(emitted)):
                    errors.append("docs/llms/manifest.json: emitted_files differ from directory")
        elif manifest is not None:
            errors.append("docs/llms/manifest.json: expected an object")
    base = root.resolve()
    for relative in sorted(set(paths)):
        candidate = (root / relative).resolve()
        if Path(relative).is_absolute() or not candidate.is_relative_to(base):
            errors.append(f"index path escapes repository: {relative}")
        elif not candidate.is_file():
            errors.append(f"index path does not exist: {relative}")
    return errors


def collected_counts(output: str) -> Counter:
    """Count node IDs, rather than parse pytest's changing summary wording."""
    counts: Counter = Counter()
    for line in output.splitlines():
        if line.startswith("tests/") and "::" in line:
            counts[Path(line.split("::", 1)[0]).name] += 1
    return counts


def check_test_counts(root: Path, counts: Counter) -> list[str]:
    errors = []
    total = sum(counts.values())
    if not total:
        return ["pytest collection returned no test node IDs"]
    for relative in COUNT_DOCS:
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{relative}: could not read ({type(exc).__name__})")
            continue
        documented = re.findall(r"\b(\d+) (?:tests\b|passed\b)", text)
        if relative.endswith("codebase-overview.md"):
            documented += re.findall(r"the count \(`(\d+)`\)", text)
        if relative.endswith("SCRIPTS.md"):
            documented += re.findall(r"\| \*\*(\d+)\*\* \| \*\*total\*\* \|", text)
            rows = re.findall(r"\| (\d+) \| `(test_[^`]+\.py)` \|", text)
            published = {name: int(count) for count, name in rows}
            for name in sorted(set(published) | set(counts)):
                if published.get(name) != counts.get(name):
                    errors.append(
                        f"{relative}: {name} has {published.get(name, 'no row')}; "
                        f"collection has {counts.get(name, 'no tests')}"
                    )
        if not documented:
            errors.append(f"{relative}: no published test total found")
        for value in sorted(set(documented)):
            if int(value) != total:
                errors.append(f"{relative}: published total {value}; collection has {total}")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect-tests", action="store_true")
    args = parser.parse_args(argv)
    errors = check_paths(ROOT)
    if args.collect_tests:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        if result.returncode:
            errors.append("pytest collection failed; run python -m pytest --collect-only -q")
        else:
            errors.extend(check_test_counts(ROOT, collected_counts(result.stdout)))
    if errors:
        print("Documentation check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        print(
            "Correct the index paths or refresh counts from pytest collection. "
            "Regenerate the partial dossier with python scripts/generate_static_dossier.py.",
            file=sys.stderr,
        )
        return 1
    print("Documentation paths and requested test counts match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
