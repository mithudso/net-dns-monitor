#!/usr/bin/env python3
"""Index one file into the local Chroma collection, or remove it.

    python3 semantic_indexer.py <filepath>
    python3 semantic_indexer.py --remove <filepath>

The third-party imports live inside the functions that need them so the pure
helpers (`chunk_text`, `should_index`, the path rules) import without chromadb
installed -- which is what lets the offline test suite cover them.
"""

import os
import sys

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
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "build",
    "node_modules",
    ".cdo-backup",
}

CHUNK_SIZE = 1000
CHUNK_OVERLAP = 200


def source_key(filepath: str, root: str = None) -> str:
    """The one spelling of a path used for ids and the `source` metadata, so
    `./foo.py`, `foo.py` and an absolute path all address the same chunks."""
    return os.path.relpath(os.path.realpath(filepath), root or REPO_ROOT)


def should_index(path: str, root: str = None) -> bool:
    rel = source_key(path, root)
    if rel.startswith(os.pardir + os.sep) or rel == os.pardir:
        return False
    if not rel.endswith(EXTS):
        return False
    # Tested on the path relative to the root, not the absolute path: a
    # checkout that itself lives under a dot directory (.claude/worktrees/...)
    # would otherwise exclude every file it contains.
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


def open_collection():
    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except ImportError as exc:
        raise ImportError(f"{exc.name} is not installed; {REQUIREMENTS_HINT}") from exc
    client = chromadb.PersistentClient(path=DB_PATH)
    ollama_ef = embedding_functions.OllamaEmbeddingFunction(
        url="http://localhost:11434/api/embeddings", model_name="nomic-embed-text"
    )
    return client.get_or_create_collection(name=COLLECTION, embedding_function=ollama_ef)


def remove_file(filepath: str, collection=None, root: str = None) -> None:
    src = source_key(filepath, root)
    collection = collection if collection is not None else open_collection()
    collection.delete(where={"source": src})
    print(f"Removed chunks for {src}")


def index_file(filepath: str, collection=None, root: str = None) -> None:
    if not os.path.isfile(filepath) or not should_index(filepath, root):
        print(f"Skipping non-indexable file: {filepath}")
        return

    src = source_key(filepath, root)
    print(f"Indexing: {src}")
    with open(filepath, encoding="utf-8", errors="replace") as f:
        text = f.read()
    chunks = chunk_text(text)
    if not chunks:
        return

    collection = collection if collection is not None else open_collection()
    # Upsert only overwrites ids that still exist. A file that shrank from
    # eight chunks to five kept serving chunks 5-7 from its old contents.
    collection.delete(where={"source": src})
    collection.upsert(
        documents=chunks,
        metadatas=[{"source": src} for _ in chunks],
        ids=[f"{src}_chunk_{i}" for i in range(len(chunks))],
    )
    print(f"Successfully indexed {len(chunks)} chunks for {src}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: python3 semantic_indexer.py [--remove] <filepath>", file=sys.stderr)
        return 2
    try:
        if argv[1] == "--remove":
            if len(argv) < 3:
                print("Usage: python3 semantic_indexer.py --remove <filepath>", file=sys.stderr)
                return 2
            remove_file(argv[2])
        else:
            index_file(argv[1])
    except ImportError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
