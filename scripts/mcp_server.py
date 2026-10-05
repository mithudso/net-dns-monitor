#!/usr/bin/env python3
"""A one-tool MCP server over stdio: semantic search of the local index built
by semantic_indexer.py. See docs/MCP.md.
"""

import argparse
import asyncio
import sys

from semantic_indexer import REQUIREMENTS_HINT, open_collection

MAX_RESULTS = 20
EXPECTED_TOOLS = frozenset({"search_codebase"})


def search(query: str, n_results: int, open_fn=open_collection) -> str:
    try:
        # A query with n_results <= 0 raises inside chroma; clamp rather than
        # let a tool argument take the server down. int() sits inside the try
        # because a client can send a non-numeric value.
        n_results = max(1, min(int(n_results), MAX_RESULTS))
        collection = open_fn()
        results = collection.query(query_texts=[query], n_results=n_results)
    except Exception as e:  # noqa: BLE001 - a missing index is a finding, not a crash
        # Class name only: the exception text can carry the database path, and
        # a failed Ollama embedding call can carry its URL.
        return (
            f"Code search failed ({type(e).__name__}). "
            "If the index has never been built, run scripts/semantic_indexer.py."
        )
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


def build_server(fastmcp_cls):
    mcp = fastmcp_cls("Local Semantic Search")
    mcp.tool()(search_codebase)
    return mcp


def self_test(mcp) -> int:
    """Check the registered tool set without serving, opening the index or
    contacting Ollama, so the check is safe while indexing is paused."""
    try:
        names = {tool.name for tool in asyncio.run(mcp.list_tools())}
    except Exception as e:  # noqa: BLE001 - report the failure as data
        print(f"self-test failed: could not list tools ({type(e).__name__})", file=sys.stderr)
        return 1
    if names != EXPECTED_TOOLS:
        print(
            f"self-test failed: tools {sorted(names)}, expected {sorted(EXPECTED_TOOLS)}",
            file=sys.stderr,
        )
        return 1
    print(f"self-test ok: {len(names)} tool(s): {', '.join(sorted(names))}")
    return 0


def main(argv: list[str] | None = None, fastmcp_cls=None) -> int:
    parser = argparse.ArgumentParser(description="Local semantic search MCP server (stdio).")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="build the server, verify its tool list and exit without serving",
    )
    args = parser.parse_args(argv)
    if fastmcp_cls is None:
        try:
            # FastMCP is packaged separately from the low-level MCP SDK in current releases.
            from fastmcp import FastMCP as fastmcp_cls
        except ImportError as exc:
            print(f"{exc.name} is not installed; {REQUIREMENTS_HINT}", file=sys.stderr)
            return 1
    mcp = build_server(fastmcp_cls)
    if args.self_test:
        return self_test(mcp)
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
