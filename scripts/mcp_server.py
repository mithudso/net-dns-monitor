#!/usr/bin/env python3
"""A one-tool MCP server over stdio: semantic search of the local index built
by semantic_indexer.py. See docs/MCP.md.
"""

import sys

from semantic_indexer import REQUIREMENTS_HINT, open_collection

MAX_RESULTS = 20


def search(query: str, n_results: int, open_fn=open_collection) -> str:
    # A query with n_results <= 0 raises inside chroma; clamp rather than
    # let a tool argument take the server down.
    n_results = max(1, min(int(n_results), MAX_RESULTS))
    try:
        collection = open_fn()
    except Exception as e:  # noqa: BLE001 - a missing index is a finding, not a crash
        # Class name only: the exception text can carry the database path.
        return (
            f"Could not open the code index ({type(e).__name__}). "
            "If it has never been built, run scripts/semantic_indexer.py."
        )

    results = collection.query(query_texts=[query], n_results=n_results)
    if not results["documents"] or not results["documents"][0]:
        return "No relevant code found."

    output = []
    for i in range(len(results["documents"][0])):
        source = results["metadatas"][0][i]["source"]
        content = results["documents"][0][i]
        output.append(f"--- SOURCE: {source} ---\n{content}\n")
    return "\n".join(output)


def search_codebase(query: str, n_results: int = 3) -> str:
    """
    Search the local codebase semantically. Use this to find code snippets,
    architecture docs, or logic without reading entire files.
    """
    return search(query, n_results)


def main() -> int:
    try:
        # FastMCP is packaged separately from the low-level MCP SDK in current releases.
        from fastmcp import FastMCP
    except ImportError as exc:
        print(f"{exc.name} is not installed; {REQUIREMENTS_HINT}", file=sys.stderr)
        return 1
    mcp = FastMCP("Local Semantic Search")
    mcp.tool()(search_codebase)
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
