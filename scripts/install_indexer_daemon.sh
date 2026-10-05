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

# Written beside the target and linted before the move so a bad file never
# replaces the working one.
STAGED_PLIST="$PLIST_PATH.new"
cat <<EOF > "$STAGED_PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${REPO_ROOT}/.venv/bin/python3</string>
        <string>${SCRIPT_DIR}/watch_and_index.py</string>
        <string>${REPO_ROOT}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/semantic_indexer.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/semantic_indexer.err</string>
</dict>
</plist>
EOF
plutil -lint "$STAGED_PLIST" >/dev/null \
    || { rm -f "$STAGED_PLIST"; echo "error: generated plist is malformed; $PLIST_PATH was not changed" >&2; exit 1; }
mv -f "$STAGED_PLIST" "$PLIST_PATH"

# `launchctl load -w` is a silent no-op when the label is already loaded, so a
# reinstall kept running the old command line. bootout then bootstrap replaces it.
launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
echo "Loaded ${LABEL}; logs in ${LOG_DIR}/semantic_indexer.{log,err}"
