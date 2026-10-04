"""The pure parts of the semantic-index scripts under `scripts/`.

Those files are not a package and their third-party imports (chromadb,
fastmcp, watchdog) are deliberately inside the functions that need them, so
this module can load them by path without any of that installed. The
collection is a fake; nothing here opens a database or spawns the indexer.
"""

import importlib
import os
import sys

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def load(name):
    # Through sys.modules, not spec_from_file_location: the scripts import
    # each other by bare name, and a module loaded twice is two objects.
    if SCRIPTS not in sys.path:
        sys.path.insert(0, SCRIPTS)
    return importlib.import_module(name)


indexer = load("semantic_indexer")
watcher = load("watch_and_index")
mcp_server = load("mcp_server")


class FakeCollection:
    def __init__(self):
        self.calls = []

    def delete(self, where):
        self.calls.append(("delete", where))

    def upsert(self, documents, metadatas, ids):
        self.calls.append(("upsert", ids, metadatas))

    def query(self, query_texts, n_results):
        return {"documents": [["chunk"]], "metadatas": [[{"source": "a.py"}]]}


# --- chunking ------------------------------------------------------------------


def test_chunks_overlap_and_cover_the_whole_text():
    chunks = indexer.chunk_text("abcdefghij", size=4, overlap=1)
    assert chunks == ["abcd", "defg", "ghij", "j"]


def test_empty_text_has_no_chunks():
    assert indexer.chunk_text("") == []


# --- what gets indexed ---------------------------------------------------------


def test_source_paths_and_caches_are_told_apart(tmp_path):
    root = str(tmp_path)
    assert indexer.should_index(str(tmp_path / "netdnsmonitor" / "app.py"), root)
    assert not indexer.should_index(str(tmp_path / "app.so"), root)
    assert not indexer.should_index(str(tmp_path / ".venv" / "lib" / "x.py"), root)
    assert not indexer.should_index(str(tmp_path / "dist" / "a" / "b.py"), root)
    assert not indexer.should_index(str(tmp_path / ".claude" / "notes.md"), root)
    assert not indexer.should_index(str(tmp_path / "__pycache__" / "m.py"), root)


def test_a_checkout_under_a_dot_directory_still_indexes_its_own_files(tmp_path):
    root = str(tmp_path / ".claude" / "worktrees" / "feature")
    assert indexer.should_index(os.path.join(root, "netdnsmonitor", "app.py"), root)


def test_files_outside_the_root_are_refused(tmp_path):
    assert not indexer.should_index(str(tmp_path.parent / "other.py"), str(tmp_path))


def test_the_same_file_has_one_source_key_however_it_is_spelled(tmp_path):
    root = str(tmp_path)
    target = tmp_path / "a" / "b.py"
    target.parent.mkdir()
    target.write_text("x")
    keys = {
        indexer.source_key(str(target), root),
        indexer.source_key(os.path.join(root, "a", "..", "a", "b.py"), root),
        indexer.source_key(os.path.join(root, ".", "a", "b.py"), root),
    }
    assert keys == {os.path.join("a", "b.py")}


# --- writing the collection ------------------------------------------------------


def test_index_deletes_old_chunks_before_upserting(tmp_path):
    f = tmp_path / "doc.md"
    f.write_text("hello")
    collection = FakeCollection()
    indexer.index_file(str(f), collection, root=str(tmp_path))
    assert collection.calls[0] == ("delete", {"source": "doc.md"})
    assert collection.calls[1][0] == "upsert"
    assert collection.calls[1][1] == ["doc.md_chunk_0"]
    assert collection.calls[1][2] == [{"source": "doc.md"}]


def test_remove_deletes_by_source(tmp_path):
    collection = FakeCollection()
    indexer.remove_file(str(tmp_path / "gone.py"), collection, root=str(tmp_path))
    assert collection.calls == [("delete", {"source": "gone.py"})]


def test_readers_and_writer_agree_on_the_database_path():
    assert os.path.join(indexer.REPO_ROOT, ".chroma_db") == indexer.DB_PATH
    assert os.path.isabs(indexer.DB_PATH)
    assert mcp_server.open_collection is indexer.open_collection


# --- the watcher ------------------------------------------------------------------


def test_watcher_spawns_the_running_interpreter_not_bare_python3(tmp_path):
    ran = []

    def run(argv, timeout, check):
        ran.append((argv, timeout))
        return type("P", (), {"returncode": 0})()

    src = str(tmp_path / "x.py")
    watcher.handle_event("modified", src, "", False, str(tmp_path), run)
    ((argv, timeout),) = ran
    assert argv[0] == sys.executable
    assert argv[1].endswith("semantic_indexer.py")
    assert argv[-1] == src
    assert timeout == watcher.INDEXER_TIMEOUT_SECONDS


def test_watcher_spawns_nothing_for_a_shared_object_or_a_directory(tmp_path):
    ran = []
    run = lambda argv, timeout, check: ran.append(argv)  # noqa: E731
    watcher.handle_event("modified", str(tmp_path / "m.so"), "", False, str(tmp_path), run)
    watcher.handle_event("created", str(tmp_path / "pkg"), "", True, str(tmp_path), run)
    watcher.handle_event("modified", str(tmp_path / "dist" / "a.py"), "", False, str(tmp_path), run)
    assert ran == []


def test_deleted_and_moved_files_leave_the_index(tmp_path):
    ran = []
    run = lambda argv, timeout, check: ran.append(argv) or type("P", (), {"returncode": 0})()  # noqa: E731
    old = str(tmp_path / "old.py")
    new = str(tmp_path / "new.py")
    watcher.handle_event("deleted", old, "", False, str(tmp_path), run)
    watcher.handle_event("moved", old, new, False, str(tmp_path), run)
    assert ran[0][-2:] == ["--remove", old]
    assert ran[1][-2:] == ["--remove", old]
    assert ran[2][-1] == new


def test_an_indexer_failure_is_reported_on_stderr(tmp_path, capsys):
    run = lambda argv, timeout, check: type("P", (), {"returncode": 3})()  # noqa: E731
    watcher.handle_event("modified", str(tmp_path / "x.py"), "", False, str(tmp_path), run)
    assert "indexer failed (3)" in capsys.readouterr().err


# --- the MCP tool -----------------------------------------------------------------


def test_an_unopenable_index_is_reported_by_class_name_without_the_path():
    def broken():
        raise FileNotFoundError("/Users/someone/secret/.chroma_db")

    out = mcp_server.search("q", 3, broken)
    assert "FileNotFoundError" in out
    assert "/Users/someone" not in out


def test_n_results_is_clamped_to_a_sane_range():
    seen = {}

    class C(FakeCollection):
        def query(self, query_texts, n_results):
            seen["n"] = n_results
            return super().query(query_texts, n_results)

    mcp_server.search("q", 0, C)
    assert seen["n"] == 1
    mcp_server.search("q", 999, C)
    assert seen["n"] == mcp_server.MAX_RESULTS


def test_results_are_rendered_with_their_source():
    assert "--- SOURCE: a.py ---" in mcp_server.search("q", 3, FakeCollection)


class FakeFastMCP:
    """Records registered tools; fails the test if anything tries to serve."""

    def __init__(self, name, tools=None):
        self.name = name
        self.tools = [] if tools is None else tools

    def tool(self):
        def register(fn):
            self.tools.append(fn)
            return fn

        return register

    async def list_tools(self):
        return [type("Tool", (), {"name": fn.__name__})() for fn in self.tools]

    def run(self):
        raise AssertionError("self-test must not start the server")


def test_self_test_lists_tools_without_serving(capsys):
    assert mcp_server.main(["--self-test"], fastmcp_cls=FakeFastMCP) == 0
    assert "self-test ok: 1 tool(s): search_codebase" in capsys.readouterr().out


def test_self_test_fails_on_an_unexpected_tool_set(capsys):
    class Extra(FakeFastMCP):
        def __init__(self, name):
            super().__init__(name, tools=[lambda: None])

    assert mcp_server.main(["--self-test"], fastmcp_cls=Extra) == 1
    assert "expected ['search_codebase']" in capsys.readouterr().err


def test_self_test_reports_a_listing_failure_by_class_name(capsys):
    class Broken(FakeFastMCP):
        async def list_tools(self):
            raise RuntimeError("/Users/someone/secret")

    assert mcp_server.main(["--self-test"], fastmcp_cls=Broken) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert "/Users/someone" not in err
