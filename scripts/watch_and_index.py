#!/usr/bin/env python3
import time
import subprocess
import os
import sys

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("Please install watchdog: pip install watchdog chromadb")
    sys.exit(1)

INDEXER_SCRIPT = os.path.join(os.path.dirname(__file__), "semantic_indexer.py")

class IndexingEventHandler(FileSystemEventHandler):
    def process(self, event):
        # Ignore directories and .git, .chroma_db, etc.
        if event.is_directory or "/." in event.src_path:
            return
        
        # We only care about modifications and creations
        if event.event_type in ('modified', 'created'):
            print(f"Detected change in {event.src_path}. Triggering indexer...")
            subprocess.run(["python3", INDEXER_SCRIPT, event.src_path])

    def on_modified(self, event):
        self.process(event)

    def on_created(self, event):
        self.process(event)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    event_handler = IndexingEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    
    print(f"Watching {os.path.abspath(path)} for changes to auto-index...")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
