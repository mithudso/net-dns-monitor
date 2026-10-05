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
# One editor save arrives as several events (create, modify, modify). Waiting
# this long after the last one runs the indexer once per path, not three times.
COALESCE_SECONDS = 1.0


def indexer_argv(event_type: str, src_path: str, dest_path: str, root: str) -> list[str] | None:
    """The command to run for one filesystem event, or None when nothing
    should run. `sys.executable`, never a bare `python3`: under launchd that
    resolves to /usr/bin/python3, which has none of the indexer's packages.
    """
    if event_type in ("modified", "created"):
        if not should_index(src_path, root):
            return None
        return [sys.executable, INDEXER_SCRIPT, src_path]
    if event_type == "deleted":
        if not should_index(src_path, root):
            return None
        return [sys.executable, INDEXER_SCRIPT, "--remove", src_path]
    if event_type == "moved":
        # Two halves, run separately: the old name leaves the index whether or
        # not the new name qualifies to enter it.
        return None
    return None


def moved_argvs(src_path: str, dest_path: str, root: str) -> list[list[str]]:
    argvs = []
    if should_index(src_path, root):
        argvs.append([sys.executable, INDEXER_SCRIPT, "--remove", src_path])
    if should_index(dest_path, root):
        argvs.append([sys.executable, INDEXER_SCRIPT, dest_path])
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
        return []
    if event_type == "moved":
        argvs = moved_argvs(src_path, dest_path, root)
    else:
        argv = indexer_argv(event_type, src_path, dest_path, root)
        argvs = [argv] if argv else []
    for argv in argvs:
        print(f"Detected {event_type}: {argv[-1]}. Triggering indexer...", flush=True)
        run_indexer(argv, run_fn)
    return argvs


class EventCoalescer:
    """Collapse a burst of events for one path into the last one.

    The timer factory is injected (threading.Timer-shaped: start(), cancel()) so
    the tests run without sleeping. Each new event for a path restarts that
    path's timer; when it fires, `handle` gets the newest event only. A move is
    kept apart from other events on the same path, because it is the only
    event that carries the destination. Handlers run one at a time: each timer
    fires on its own thread, and a branch switch would otherwise start one
    indexer process per file against the same Chroma store.
    """

    def __init__(self, handle, delay: float = COALESCE_SECONDS, timer_factory=threading.Timer):
        self._handle = handle
        self._delay = delay
        self._timer_factory = timer_factory
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._pending: dict[tuple, tuple] = {}
        self._timers: dict[tuple, object] = {}

    def add(self, event_type: str, src_path: str, dest_path: str, is_directory: bool) -> None:
        key = (event_type == "moved", src_path)
        with self._lock:
            old = self._timers.pop(key, None)
            if old is not None:
                old.cancel()
            self._pending[key] = (event_type, src_path, dest_path, is_directory)
            timer = self._timer_factory(self._delay, self._flush, args=(key,))
            timer.daemon = True
            self._timers[key] = timer
            timer.start()

    def _flush(self, key: tuple) -> None:
        with self._lock:
            event = self._pending.pop(key, None)
            self._timers.pop(key, None)
        if event is None:
            return
        with self._run_lock:
            try:
                self._handle(*event)
            except Exception as exc:  # noqa: BLE001 - one bad event must not stop the watcher
                print(
                    f"indexing {event[1]} failed ({type(exc).__name__})",
                    file=sys.stderr,
                    flush=True,
                )


def main(argv: list[str]) -> int:
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        print(f"{exc.name} is not installed; {REQUIREMENTS_HINT}", file=sys.stderr)
        return 1

    root = os.path.realpath(argv[1] if len(argv) > 1 else ".")

    coalescer = EventCoalescer(
        lambda event_type, src, dest, is_dir: handle_event(event_type, src, dest, is_dir, root)
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
