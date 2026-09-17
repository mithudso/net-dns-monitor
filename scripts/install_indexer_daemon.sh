#!/usr/bin/env bash

PLIST_PATH="$HOME/Library/LaunchAgents/com.local.semantic_indexer.plist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.semantic_indexer</string>
    <key>ProgramArguments</key>
    <array>
        <string>${SCRIPT_DIR}/../.venv/bin/python3</string>
        <string>${SCRIPT_DIR}/watch_and_index.py</string>
        <string>${SCRIPT_DIR}/..</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/semantic_indexer.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/semantic_indexer.err</string>
</dict>
</plist>
EOF

launchctl load -w "$PLIST_PATH"
echo "Loaded semantic indexer watcher daemon into launchctl."
