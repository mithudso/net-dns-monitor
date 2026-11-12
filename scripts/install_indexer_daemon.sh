#!/usr/bin/env bash
# Install (or reinstall) the semantic-indexer watcher as a per-user LaunchAgent.
# Deps: pip install -r requirements-index.txt into .venv first.
set -euo pipefail

LABEL="com.local.semantic_indexer"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# ~/Library/Logs, not /tmp: a fixed name in a world-writable directory can be
# pre-planted as a symlink, and launchd opens it without checking.
LOG_DIR="$HOME/Library/Logs"

# A plist pointing at a missing interpreter loads fine and then fails every
# 10s under KeepAlive, so refuse before writing anything.
[ -x "$REPO_ROOT/.venv/bin/python3" ] \
    || { echo "error: $REPO_ROOT/.venv/bin/python3 not found -- create the venv and install requirements-index.txt first" >&2; exit 1; }

mkdir -p "$LOG_DIR" "$(dirname "$PLIST_PATH")"

# Reject overlapping installs rather than interleaving bootout/bootstrap.
INSTALL_LOCK="$PLIST_PATH.install.lock"
mkdir "$INSTALL_LOCK" 2>/dev/null \
    || { echo "error: another indexer install owns $INSTALL_LOCK" >&2; exit 1; }
STAGED_PLIST=""
cleanup() {
    [[ -z "$STAGED_PLIST" ]] || rm -f "$STAGED_PLIST"
    rmdir "$INSTALL_LOCK"
}
trap cleanup EXIT

# Every invocation owns its staging inode. Serialize values as data so valid
# filesystem names containing XML metacharacters survive unchanged.
STAGED_PLIST="$(mktemp "$PLIST_PATH.XXXXXX")"
"$REPO_ROOT/.venv/bin/python3" - "$STAGED_PLIST" "$LABEL" "$REPO_ROOT" "$SCRIPT_DIR" "$LOG_DIR" <<'PYEOF'
import plistlib
import sys
from pathlib import Path

path, label, root, scripts, logs = sys.argv[1:]
Path(path).write_bytes(plistlib.dumps({
    "Label": label,
    "ProgramArguments": [str(Path(root) / ".venv/bin/python3"),
                         str(Path(scripts) / "watch_and_index.py"), root],
    "RunAtLoad": True,
    "KeepAlive": True,
    "StandardOutPath": str(Path(logs) / "semantic_indexer.log"),
    "StandardErrorPath": str(Path(logs) / "semantic_indexer.err"),
}))
PYEOF
plutil -lint "$STAGED_PLIST" >/dev/null \
    || { rm -f "$STAGED_PLIST"; echo "error: generated plist is malformed; $PLIST_PATH was not changed" >&2; exit 1; }
mv -f "$STAGED_PLIST" "$PLIST_PATH"

# `launchctl load -w` is a silent no-op when the label is already loaded, so a
# reinstall kept running the old command line. bootout then bootstrap replaces it.
launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
echo "Loaded ${LABEL}; logs in ${LOG_DIR}/semantic_indexer.{log,err}"
