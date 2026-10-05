#!/bin/bash
#
# install.sh -- set up net-dns-monitor on a fresh Mac, start to finish.
#
#   git clone <repo> net-dns-monitor
#   cd net-dns-monitor
#   ./scripts/install.sh
#
# Does everything: preflight checks, virtualenv, dependencies, freezes the .app
# bundle with py2app, installs the LaunchAgent so the app starts at login and is
# restarted if it dies, materialises a default config, and verifies the result.
#
# Safe to re-run. Every step is idempotent -- use it to upgrade an existing
# install after a `git pull` as well as for a first install.
#
# ---------------------------------------------------------------------------
# Why this exists separately from scripts/start.sh and net-dns-monitor-service
#
# start.sh launches the app in the foreground for development. net-dns-monitor-
# service owns supervision, but it installs *from an already-built bundle*. Its
# default source is the bundle path it recorded at the last install, then the
# dist/ of the checkout the script sits in -- and the installed copy in
# ~/.local/bin sits in no checkout. This script is the missing piece: it builds
# the bundle first and then hands the service script an explicit
# NDM_SOURCE_BUNDLE pointing into this checkout, which the service script then
# records for later `update` runs.
#
# "Starts on boot" precisely: a LaunchAgent, not a LaunchDaemon, so it starts at
# *login* rather than at boot. That is deliberate and not a shortcut -- this is a
# menu bar app; it needs a logged-in user's GUI session to draw a status item at
# all. See the comments in net-dns-monitor-service.
# ---------------------------------------------------------------------------

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BUNDLE="$REPO_DIR/dist/Net-DNS-Monitor.app"
SERVICE_SRC="$REPO_DIR/scripts/net-dns-monitor-service"
SERVICE_DST="$HOME/.local/bin/net-dns-monitor-service"
CONFIG_DIR="$HOME/.config/net-dns-monitor"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
LABEL="com.mitchhudson.net-dns-monitor"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
CONSTRAINTS="$REPO_DIR/constraints.txt"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# 3.13: the version CLAUDE.md names, the only one CI runs, and the one
# constraints.txt was frozen from, so it is the only dependency set anyone has
# tested. The pins' own technical floor is 3.10 (pyobjc 12 and pytest 9 refuse
# anything older). The old check here accepted 3.9, which passed this preflight
# and then failed inside pip. scripts/start.sh enforces the same floor.
MIN_PYTHON_MINOR=13

step()  { printf '\n==> %s\n' "$*"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    ok: %s\n' "$*"; }
warn()  { printf '    warning: %s\n' "$*" >&2; }
die()   { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# --- 1. preflight ----------------------------------------------------------

step "Checking this machine"

[ "$(uname -s)" = "Darwin" ] || die "macOS only -- this uses log show, scutil, dscacheutil and AppKit."
ok "macOS $(sw_vers -productVersion)"

PYTHON_HINT="install Python 3.$MIN_PYTHON_MINOR (python.org, or: brew install python@3.$MIN_PYTHON_MINOR), then re-run with PYTHON_BIN=python3.$MIN_PYTHON_MINOR if it is not first on PATH"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "$PYTHON_BIN not found. $PYTHON_HINT"
"$PYTHON_BIN" -c "import sys; sys.exit(0 if sys.version_info >= (3, $MIN_PYTHON_MINOR) else 1)" \
    || die "need Python 3.$MIN_PYTHON_MINOR+, found $("$PYTHON_BIN" -c 'import platform; print(platform.python_version())'). $PYTHON_HINT"
ok "$PYTHON_BIN $("$PYTHON_BIN" -c 'import platform; print(platform.python_version())')"

# Every external tool the app shells out to. Checked here rather than
# discovered at runtime, when the failure would be a string in a report.
for tool in /sbin/ping /usr/sbin/netstat /sbin/ifconfig /usr/bin/log /usr/sbin/scutil \
            /usr/bin/dscacheutil /usr/bin/killall /usr/bin/open /usr/bin/osascript; do
    [ -x "$tool" ] || die "missing required system tool: $tool"
done
ok "all required system tools present"

[ -f "$REPO_DIR/setup.py" ] || die "run this from inside the repo -- $REPO_DIR/setup.py not found"

# --- 2. virtualenv and dependencies ---------------------------------------

step "Setting up the virtualenv"

if [ ! -x "$VENV_DIR/bin/python" ]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    ok "created $VENV_DIR"
else
    ok "reusing $VENV_DIR"
fi

PY="$VENV_DIR/bin/python"
# A reused venv keeps the interpreter it was created with, which the preflight
# above never looked at. Without this, a venv left over from an older Python
# fails later inside pip with a resolver error that does not name the cause.
"$PY" -c "import sys; sys.exit(0 if sys.version_info >= (3, $MIN_PYTHON_MINOR) else 1)" \
    || die "$VENV_DIR was created with Python older than 3.$MIN_PYTHON_MINOR -- remove it and re-run: rm -rf $VENV_DIR"
"$PY" -m pip install --quiet -r "$REPO_DIR/requirements.txt" -c "$CONSTRAINTS"
ok "installed runtime dependencies"

# py2app is in neither requirements file on purpose: it is a build tool, not a
# runtime dependency, and end users of a prebuilt bundle never need it. Its
# version is pinned in constraints.txt like everything else, and installed
# unconditionally so an older py2app already in the venv is moved to that pin
# rather than silently kept.
"$PY" -m pip install --quiet py2app -c "$CONSTRAINTS"
ok "py2app $("$PY" -c 'from importlib.metadata import version; print(version("py2app"))')"

# --- 3. config -------------------------------------------------------------

step "Config"

mkdir -p "$CONFIG_DIR"
if [ -f "$CONFIG_FILE" ]; then
    ok "keeping your existing $CONFIG_FILE"
else
    cp "$REPO_DIR/config.yaml" "$CONFIG_FILE"
    ok "created $CONFIG_FILE from the repo's default config.yaml"
    warn "add the sites you care about to 'domains' in that file. Until then the DNS"
    warn "check resolves only control_domain and any name learned from the system log,"
    warn "so a DNS fault that spares control_domain can go unnoticed."
fi

# Fail loudly here rather than after installing a LaunchAgent that cannot start.
"$PY" - <<PYEOF || die "the config at $CONFIG_FILE could not be loaded -- fix it and re-run"
import sys
sys.path.insert(0, "$REPO_DIR")
from netdnsmonitor.config import load_config
load_config("$CONFIG_FILE")
PYEOF
ok "config loads"

# --- 4. build the bundle ---------------------------------------------------

step "Building the app bundle (this is the slow part)"

# py2app's build/ staging directory is not safe to reuse across runs -- a second
# invocation against a stale one fails with "[Errno 66] Directory not empty".
rm -rf "$REPO_DIR/build"
( cd "$REPO_DIR" && "$PY" setup.py py2app >/dev/null 2>&1 ) \
    || die "py2app build failed. Re-run it directly to see why:
    cd $REPO_DIR && $PY setup.py py2app"
[ -x "$BUNDLE/Contents/MacOS/Net-DNS-Monitor" ] || die "build produced no executable at $BUNDLE"
ok "built $BUNDLE"

# Confirm the app's own modules actually made it in. py2app's dependency
# analysis is static, so a module reached only dynamically can silently vanish.
for module in app dashboard forensic_log peers peer_net ping net_stats history graphs settings_window mini_window; do
    [ -f "$BUNDLE/Contents/Resources/lib/python3."*"/netdnsmonitor/$module.py" ] \
        || warn "netdnsmonitor/$module.py is not in the bundle"
done
ok "bundle contents verified"

# --- 5. install the supervised LaunchAgent --------------------------------

step "Installing the LaunchAgent (starts at login, restarts if it dies)"

mkdir -p "$HOME/.local/bin"
install -m 0755 "$SERVICE_SRC" "$SERVICE_DST"
ok "installed $SERVICE_DST"

# The service script copies the bundle out to ~/Applications and writes the
# plist. NDM_SOURCE_BUNDLE is explicit here because the installed script's own
# default (a recorded path, then its checkout's dist/) cannot know this build yet.
NDM_SOURCE_BUNDLE="$BUNDLE" "$SERVICE_DST" install

# --- 6. verify -------------------------------------------------------------

step "Verifying"

[ -f "$PLIST" ] || die "no LaunchAgent plist at $PLIST"
PROGRAM="$(plutil -extract ProgramArguments.0 raw -o - "$PLIST" 2>/dev/null || echo '?')"
EXPECTED="$HOME/Applications/Net-DNS-Monitor.app/Contents/MacOS/Net-DNS-Monitor"
[ "$PROGRAM" = "$EXPECTED" ] || die "the LaunchAgent points at '$PROGRAM', expected '$EXPECTED'"
ok "LaunchAgent runs $PROGRAM"

# KeepAlive with a PathState condition is what both starts it at login and
# restarts it on crash; without it, "starts on boot" would not be true.
plutil -extract KeepAlive.PathState raw -o - "$PLIST" >/dev/null 2>&1 \
    || warn "no KeepAlive condition in the plist -- login startup may not work"
ok "supervision configured"

if launchctl list "$LABEL" >/dev/null 2>&1; then
    ok "job is loaded"
else
    warn "job is not loaded -- try: $SERVICE_DST start"
fi

printf '\n'
"$SERVICE_DST" status || true

# `launchctl kickstart` returns when launchd accepts the request, not when a
# process exists, so give it a few seconds. "Installed" below is only said when
# launchd reports a pid; anything else is a failure the caller must see.
INSTALL_PID=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    INSTALL_PID="$(launchctl print "gui/$(id -u)/$LABEL" 2>/dev/null | awk '$1 == "pid" && $2 == "=" { print $3; exit }')" || INSTALL_PID=""
    [ -n "$INSTALL_PID" ] && break
    sleep 1
done
if [ -z "$INSTALL_PID" ]; then
    die "the LaunchAgent is installed but the app is not running. Check: $SERVICE_DST status ; $SERVICE_DST logs ; then try: $SERVICE_DST start"
fi

cat <<'DONE'

==> Installed.

The app is running and will start again at every login. A window should be
open; if not, click the Dock icon, or pick Open Dashboard from either the
"Net-DNS-Monitor" menu at the top-left or the status item at the top-right.

  net-dns-monitor-service status     is it running, is it ticking
  net-dns-monitor-service logs       recent output
  net-dns-monitor-service stop       deliberately off, stays off across login
  net-dns-monitor-service start      back on
  net-dns-monitor-service uninstall  remove the LaunchAgent

Settings are editable in the app (Open Settings) or by hand in
~/.config/net-dns-monitor/config.yaml. Anything read once at startup -- timer
intervals, alert thresholds -- needs a restart to take effect:

  net-dns-monitor-service restart

Two things worth knowing on a new machine:

  * Peer discovery is ON by default and broadcasts this machine's hostname and
    network health to the local network. Set peer_discovery_enabled: false to
    turn it off.
  * Reading the system log may prompt for permission the first time.
DONE
