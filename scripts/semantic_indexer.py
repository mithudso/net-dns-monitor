#!/usr/bin/env python3
"""Index one file into the local Chroma collection, or remove it.

    python3 semantic_indexer.py <filepath>
    python3 semantic_indexer.py --remove <filepath>

The third-party imports live inside the functions that need them so the pure
helpers (`chunk_text`, `should_index`, the path rules) import without chromadb
installed -- which is what lets the offline test suite cover them.
"""

import fcntl
import hashlib
import os
import re
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager

# Anchored to this file, not the cwd: the watcher is started by launchd with
# whatever cwd it has, and a cwd-relative path there produced a second, empty
# database that the readers (which already anchored on __file__) never saw.
REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DB_PATH = os.path.join(REPO_ROOT, ".chroma_db")
COLLECTION = "codebase_index"
REQUIREMENTS_HINT = "install the indexer deps with: pip install -r requirements-index.txt"

EXTS = (".md", ".py", ".txt", ".sh", ".json")
# Directory names that never hold source worth serving to an agent, and
# several that hold things that must not be served at all: worktree checkouts
# with their own site-packages, caches, and .claude/ session state.
EXCLUDED = {
    ".git",
    ".venv",
    ".claude",
    ".chroma_db",
    ".semantic-index-locks",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "build",
    "node_modules",
    ".cdo-backup",
    ".remember",
    ".stele",
    ".mypy_cache",
    ".tox",
    "venv",
    "env",
    "htmlcov",
    ".hypothesis",
    "site-packages",
}
# Files that are likely to hold a credential. The index is served to agents
# over MCP and embedded by a model, so a name that suggests a secret is left
# out even when its extension qualifies. The match is deliberately broad, so it
# applies to data files only: source named after the thing it handles
# (credentials.py, test_credentials.py) is code, and the code is what agents
# search the index for.
SENSITIVE_NAME = re.compile(r"secret|credential|token|\.env", re.IGNORECASE)
SOURCE_SUFFIXES = (".py", ".sh", ".md")

CHUNK_SIZE = 1000
CHUNK_OVERLAP = 200


def source_key(filepath: str, root: str = None) -> str:
    """The one spelling of a path used for ids and the `source` metadata, so
    `./foo.py`, `foo.py` and an absolute path all address the same chunks."""
    return os.path.relpath(os.path.realpath(filepath), root or REPO_ROOT)


def should_index(path: str, root: str = None) -> bool:
    rel = source_key(path, root)
    return eligible_source(rel)


def eligible_source(rel: str) -> bool:
    """Apply privacy rules to the exact root-relative source used for reading."""
    if rel.startswith(os.pardir + os.sep) or rel == os.pardir:
        return False
    if not rel.endswith(EXTS):
        return False
    # Tested on the path relative to the root, not the absolute path: a
    # checkout that itself lives under a dot directory (.claude/worktrees/...)
    # would otherwise exclude every file it contains.
    name = os.path.basename(rel)
    if SENSITIVE_NAME.search(name) and not name.endswith(SOURCE_SUFFIXES):
        return False
    return not (set(rel.split(os.sep)[:-1]) & EXCLUDED)


def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    if size <= overlap:
        raise ValueError("chunk size must exceed the overlap")
    chunks = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + size])
        start += size - overlap
    return chunks


def open_collection(root: str = None):
    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except ImportError as exc:
        raise ImportError(f"{exc.name} is not installed; {REQUIREMENTS_HINT}") from exc
    database = DB_PATH if root is None else os.path.join(os.path.realpath(root), ".chroma_db")
    client = chromadb.PersistentClient(path=database)
    ollama_ef = embedding_functions.OllamaEmbeddingFunction(
        url="http://localhost:11434/api/embeddings", model_name="nomic-embed-text"
    )
    return client.get_or_create_collection(name=COLLECTION, embedding_function=ollama_ef)


@contextmanager
def source_lock(filepath: str, root: str = None, *, source: str = None) -> Iterator[None]:
    """Serialize reading and replacing one source's chunks across processes."""
    directory = os.path.join(root or REPO_ROOT, ".semantic-index-locks")
    os.makedirs(directory, exist_ok=True)
    key = hashlib.sha256(
        (source if source is not None else source_key(filepath, root)).encode("utf-8")
    ).hexdigest()
    fd = os.open(os.path.join(directory, key), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def remove_file(filepath: str, collection=None, root: str = None) -> None:
    with source_lock(filepath, root):
        _remove_file(filepath, collection, root)


def _remove_file(filepath: str, collection=None, root: str = None) -> None:
    src = source_key(filepath, root)
    collection = collection if collection is not None else open_collection(root)
    collection.delete(where={"source": src})
    print(f"Removed chunks for {src}")


def index_file(filepath: str, collection=None, root: str = None) -> None:
    root = os.path.realpath(root or REPO_ROOT)
    canonical = os.path.realpath(filepath)
    src = os.path.relpath(canonical, root)
    if not os.path.isfile(canonical) or not eligible_source(src):
        print(f"Skipping non-indexable file: {filepath}")
        return
    with source_lock(canonical, root, source=src):
        _index_file(canonical, collection, root, source=src)


def _index_file(filepath: str, collection=None, root: str = None, *, source: str = None) -> None:
    src = source if source is not None else source_key(filepath, root)
    if not os.path.isfile(filepath) or not eligible_source(src):
        print(f"Skipping non-indexable file: {filepath}")
        return
    print(f"Indexing: {src}")
    directory = os.open(root or REPO_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = src.split(os.sep)
        if os.pardir in parts or os.path.isabs(src):
            raise ValueError("source escaped root")
        for part in parts[:-1]:
            next_dir = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_dir
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, encoding="utf-8", errors="replace") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValueError("source is not a regular file")
            text = f.read()
    finally:
        os.close(directory)
    chunks = chunk_text(text)
    collection = collection if collection is not None else open_collection(root)
    ids = [f"{src}_chunk_{i}" for i in range(len(chunks))]
    # Upsert first, then delete only this source's ids that are no longer
    # produced. Delete-then-upsert left the file with no chunks at all if the
    # embedding call failed in between; a file that shrank from eight chunks to
    # five would otherwise keep serving chunks 5-7 from its old contents.
    if chunks:
        collection.upsert(
            documents=chunks,
            metadatas=[{"source": src} for _ in chunks],
            ids=ids,
        )
    existing = collection.get(where={"source": src}).get("ids") or []
    current_ids = set(ids)
    stale = [i for i in existing if i not in current_ids]
    if stale:
        collection.delete(ids=stale)
    if not chunks:
        return
    print(f"Successfully indexed {len(chunks)} chunks for {src}")


def reconcile_directory(path: str, collection=None, root: str = None) -> None:
    """Reconcile a directory event, including descendants absent from disk."""
    root = os.path.realpath(root or REPO_ROOT)
    path = os.path.realpath(path)
    rel = os.path.relpath(path, root)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return
    if set(rel.split(os.sep)) & EXCLUDED:
        return
    collection = collection if collection is not None else open_collection(root)
    prefix = "" if rel == "." else rel + os.sep
    metadata = collection.get(include=["metadatas"]).get("metadatas") or []
    sources = {
        item.get("source") for item in metadata if item and isinstance(item.get("source"), str)
    }
    for source in sorted(sources):
        candidate = os.path.join(root, source)
        if source.startswith(prefix) and eligible_source(source) and not os.path.isfile(candidate):
            remove_file(candidate, collection, root)
    for directory, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [
            d for d in dirs if d not in EXCLUDED and not os.path.islink(os.path.join(directory, d))
        ]
        for name in files:
            candidate = os.path.join(directory, name)
            if not os.path.islink(candidate):
                index_file(candidate, collection, root)


def main(argv: list[str]) -> int:
    root = None
    if len(argv) > 1 and argv[1] == "--root":
        if len(argv) < 4:
            return 2
        root = os.path.realpath(argv[2])
        argv = [argv[0], *argv[3:]]
    if len(argv) < 2:
        print("Usage: python3 semantic_indexer.py [--remove] <filepath>", file=sys.stderr)
        return 2
    try:
        if argv[1] == "--reconcile" and len(argv) == 3:
            reconcile_directory(argv[2], root=root)
        elif argv[1] == "--remove":
            if len(argv) < 3:
                print("Usage: python3 semantic_indexer.py --remove <filepath>", file=sys.stderr)
                return 2
            remove_file(argv[2], root=root)
        else:
            index_file(argv[1], root=root)
    except ImportError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
