#!/usr/bin/env python3
"""Watch a checkout and re-index each changed file through semantic_indexer.py.

    python3 watch_and_index.py [root]

Installed as a LaunchAgent by install_indexer_daemon.sh. The event handling
is a plain function so it can be tested without watchdog installed.
"""

import os
import subprocess
import sys
import threading

from semantic_indexer import REQUIREMENTS_HINT, should_index

INDEXER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "semantic_indexer.py")
INDEXER_TIMEOUT_SECONDS = 300
# One editor save arrives as several events. Batch from the first event so
# continuing activity cannot postpone pending work indefinitely.
COALESCE_SECONDS = 1.0


def indexer_argv(event_type: str, src_path: str, dest_path: str, root: str) -> list[str] | None:
    """The command to run for one filesystem event, or None when nothing
    should run. `sys.executable`, never a bare `python3`: under launchd that
    resolves to /usr/bin/python3, which has none of the indexer's packages.
    """
    if event_type in ("modified", "created"):
        if not should_index(src_path, root):
            return None
        return [sys.executable, INDEXER_SCRIPT, "--root", root, src_path]
    if event_type == "deleted":
        if not should_index(src_path, root):
            return None
        return [sys.executable, INDEXER_SCRIPT, "--root", root, "--remove", src_path]
    if event_type == "moved":
        # Two halves, run separately: the old name leaves the index whether or
        # not the new name qualifies to enter it.
        return None
    return None


def moved_argvs(src_path: str, dest_path: str, root: str) -> list[list[str]]:
    argvs = []
    if should_index(src_path, root):
        argvs.append([sys.executable, INDEXER_SCRIPT, "--root", root, "--remove", src_path])
    if should_index(dest_path, root):
        argvs.append([sys.executable, INDEXER_SCRIPT, "--root", root, dest_path])
    return argvs


def run_indexer(argv: list[str], run_fn=subprocess.run) -> int:
    try:
        proc = run_fn(argv, timeout=INDEXER_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"indexer failed ({type(exc).__name__}) for {argv[-1]}", file=sys.stderr, flush=True)
        return 1
    if proc.returncode:
        print(f"indexer failed ({proc.returncode}) for {argv[-1]}", file=sys.stderr, flush=True)
    return proc.returncode


def handle_event(
    event_type: str,
    src_path: str,
    dest_path: str,
    is_directory: bool,
    root: str,
    run_fn=subprocess.run,
) -> list[list[str]]:
    """Returns the commands it ran, for the tests."""
    if is_directory:
        paths = [src_path, dest_path] if event_type == "moved" else [src_path]
        argvs = (
            [
                [sys.executable, INDEXER_SCRIPT, "--root", root, "--reconcile", path]
                for path in paths
                if directory_in_scope(path, root)
            ]
            if event_type in {"created", "deleted", "moved"}
            else []
        )
    elif event_type == "moved":
        argvs = moved_argvs(src_path, dest_path, root)
    else:
        argv = indexer_argv(event_type, src_path, dest_path, root)
        argvs = [argv] if argv else []
    for argv in argvs:
        print(f"Detected {event_type}: {argv[-1]}. Triggering indexer...", flush=True)
        run_indexer(argv, run_fn)
    return argvs


def directory_in_scope(path, root):
    from semantic_indexer import EXCLUDED

    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(root))
    return (
        rel != os.pardir
        and not rel.startswith(os.pardir + os.sep)
        and not (set(rel.split(os.sep)) & EXCLUDED)
    )


class EventCoalescer:
    """Batch a burst with one timer and run its latest events serially.

    Distinct move destinations survive coalescing. A running handler retains
    execution ownership; new events wait as data, without a thread per path.
    """

    def __init__(
        self, handle, delay: float = COALESCE_SECONDS, timer_factory=threading.Timer, root=None
    ):
        self._handle = handle
        self._root = root
        self._delay = delay
        self._timer_factory = timer_factory
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._pending: dict[tuple, tuple] = {}
        self._tokens: dict[tuple, object] = {}
        self._timer = None
        self._timer_token = None
        self._running = False

    def _schedule(self):
        if self._timer is not None:
            return
        token = object()
        self._timer_token = token
        self._timer = self._timer_factory(self._delay, self._flush, args=(token,))
        self._timer.daemon = True
        self._timer.start()

    def add(self, event_type: str, src_path: str, dest_path: str, is_directory: bool) -> None:
        if event_type not in {"created", "modified", "deleted", "moved"}:
            return
        if self._root is not None and not (
            (
                directory_in_scope(src_path, self._root)
                if is_directory
                else should_index(src_path, self._root)
            )
            or (
                event_type == "moved"
                and (
                    directory_in_scope(dest_path, self._root)
                    if is_directory
                    else should_index(dest_path, self._root)
                )
            )
        ):
            return
        if is_directory and event_type == "modified":
            return
        key = (True, src_path, dest_path) if event_type == "moved" else (False, src_path)
        with self._lock:
            self._pending[key] = (event_type, src_path, dest_path, is_directory)
            self._tokens[key] = object()
            if not self._running:
                self._schedule()

    def _flush(self, token: object) -> None:
        with self._lock:
            if self._timer_token is not token or self._running:
                return
            self._timer_token = None
            self._timer = None
            self._running = True
            batch = list(self._tokens.items())
        try:
            with self._run_lock:
                for key, generation in batch:
                    with self._lock:
                        # An event can be replaced while this callback waits
                        # for execution ownership or an earlier handler.
                        if self._tokens.get(key) is not generation:
                            continue
                        self._tokens.pop(key)
                        event = self._pending.pop(key)
                    try:
                        self._handle(*event)
                    except Exception as exc:  # noqa: BLE001 - keep watching after a bad event
                        print(
                            f"indexing {event[1]} failed ({type(exc).__name__})",
                            file=sys.stderr,
                            flush=True,
                        )
        finally:
            with self._lock:
                self._running = False
                if self._pending:
                    self._schedule()


def main(argv: list[str]) -> int:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        print(f"{exc.name} is not installed; {REQUIREMENTS_HINT}", file=sys.stderr)
        return 1

    root = os.path.realpath(argv[1] if len(argv) > 1 else ".")

    coalescer = EventCoalescer(
        lambda event_type, src, dest, is_dir: handle_event(event_type, src, dest, is_dir, root),
        root=root,
    )

    class IndexingEventHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            dest = getattr(event, "dest_path", "") or ""
            coalescer.add(event.event_type, event.src_path, dest, event.is_directory)

    observer = Observer()
    observer.schedule(IndexingEventHandler(), root, recursive=True)
    print(f"Watching {root} for changes to auto-index...", flush=True)
    observer.start()
    try:
        observer.join()
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
