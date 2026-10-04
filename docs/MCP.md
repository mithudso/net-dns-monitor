# Developer semantic search

The optional developer index is separate from the menu bar app. It stores chunks
in `<checkout>/.chroma_db`, in collection `codebase_index`. The indexer uses the
local Ollama endpoint `http://localhost:11434/api/embeddings` with model
`nomic-embed-text`. Installing the application does not install these tools.

`scripts/semantic_indexer.py` indexes supported source/documentation files and
can index or remove one path. `scripts/watch_and_index.py` watches source changes
and invokes the indexer for each event. `scripts/install_indexer_daemon.sh` writes
and starts a per-user LaunchAgent; running it changes persistent host state.
Developer dependencies are pinned separately in `requirements-index.txt`.

`scripts/mcp_server.py` exposes one stdio MCP tool:

| Tool | Arguments | Result |
|---|---|---|
| `search_codebase` | `query: str`, `n_results: int = 3` (capped at 20) | Matching source chunks and their file paths, or an unavailable-index error. |

`python3 scripts/mcp_server.py --self-test` builds the server, checks that it
registers exactly that tool and exits 0, or exits 1 naming the mismatch. It does
not serve, open the index or contact Ollama, so it is safe while indexing is
paused. It still needs `fastmcp` from `requirements-index.txt`.

`scripts/query_index.py` is the shell counterpart. Both query paths generate an
embedding; they are not purely static reads. The server does not provide remote
HTTP authentication because its transport is local stdio. Configure access in
the MCP client that starts it.

If indexing or Ollama is paused, preserve that state. Use
`docs/high_signal_file_index.json`, `docs/llms/llms-filemap.txt`, and direct source
reads. Do not create an index, start Ollama, run a query, or install a watcher to
complete a documentation or code review.

`scripts/check_docs.py` verifies static retrieval paths without importing Chroma
or contacting Ollama. `scripts/generate_static_dossier.py` regenerates the
explicitly partial static dossier. These are safe alternatives for CI.
