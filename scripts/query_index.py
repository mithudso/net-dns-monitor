#!/usr/bin/env python3
"""Ad-hoc query against the local index: python3 query_index.py 'question'."""

import sys

from semantic_indexer import open_collection


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: python3 query_index.py 'your question here'", file=sys.stderr)
        return 2

    query = " ".join(argv[1:])
    try:
        collection = open_collection()
    except ImportError as exc:
        print(exc, file=sys.stderr)
        return 1

    results = collection.query(query_texts=[query], n_results=3)
    print(f"\nResults for: '{query}'\n")
    for i in range(len(results["documents"][0])):
        print(f"Source: {results['metadatas'][0][i]['source']}")
        print(f"{results['documents'][0][i]}\n{'-' * 40}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
