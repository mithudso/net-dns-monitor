#!/usr/bin/env bash
# Check the install, verify every netdnsmonitor component, apply the
# recommended config if none exists yet, then start the app.
#
# The app takes no CLI flags (see netdnsmonitor/app.py main()) -- the
# "recommended options" are the shipped config.yaml defaults, so
# "start with recommended options" means: make sure a config exists, then
# launch it.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
CONFIG_DIR="$HOME/.config/net-dns-monitor"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
PYTHON_BIN="${PYTHON_BIN:-python3}"

ok()   { echo "OK   $1"; }
info() { echo "..   $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

echo "== net-dns-monitor: checking install =="

[[ "$(uname)" == "Darwin" ]] || fail "macOS required (the app shells out to log/scutil/dscacheutil)"
ok "running on macOS"

command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "$PYTHON_BIN not found on PATH"
PY_OK=$("$PYTHON_BIN" -c 'import sys; print(int(sys.version_info >= (3, 9)))')
PY_VER=$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
[[ "$PY_OK" == "1" ]] || fail "python 3.9+ required, found $PY_VER"
ok "python $PY_VER"

for bin in log scutil dscacheutil killall netstat; do
    command -v "$bin" >/dev/null 2>&1 || fail "required system tool '$bin' not found"
done
ok "system tools present (log, scutil, dscacheutil, killall, netstat)"

if [[ ! -d "$VENV_DIR" ]]; then
    info "no venv at $VENV_DIR -- creating it"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
[[ -f "$VENV_DIR/bin/activate" ]] \
    || fail "venv at $VENV_DIR looks incomplete (no bin/activate, likely an interrupted 'python -m venv') -- remove it and re-run: rm -rf $VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
[[ "$(command -v python)" == "$VENV_DIR/bin/python" ]] \
    || fail "venv at $VENV_DIR looks broken (activation didn't put its python on PATH) -- remove it and re-run: rm -rf $VENV_DIR"
pip install -q -r "$REPO_DIR/requirements.txt"
ok "venv ready, dependencies installed"

echo "== verifying components =="

python - "$CONFIG_FILE" <<'PYEOF'
import importlib
import sys

config_file = sys.argv[1]

modules = [
    "netdnsmonitor.config", "netdnsmonitor.classifier", "netdnsmonitor.flap_gate",
    "netdnsmonitor.ladder", "netdnsmonitor.repair_executor", "netdnsmonitor.dns_query",
    "netdnsmonitor.prober", "netdnsmonitor.log_watcher", "netdnsmonitor.query_log",
    "netdnsmonitor.resolution_prober", "netdnsmonitor.resolution_log",
    "netdnsmonitor.stall_log",
    "netdnsmonitor.escalation", "netdnsmonitor.anthropic_escalator",
    "netdnsmonitor.report", "netdnsmonitor.report_storage", "netdnsmonitor.status",
    "netdnsmonitor.state_machine", "netdnsmonitor.dock_icon", "netdnsmonitor.app",
]
for name in modules:
    importlib.import_module(name)
print(f"OK   {len(modules)} components import cleanly")

from netdnsmonitor.config import load_config

try:
    config = load_config(config_file)
except Exception as exc:
    print(f"FAIL config at {config_file} failed to load: {exc}", file=sys.stderr)
    sys.exit(1)
print(
    "OK   config loaded: poll_interval_seconds={poll_interval_seconds}s, "
    "resolution_interval_seconds={resolution_interval_seconds}s, "
    "resolution_stall_seconds={resolution_stall_seconds}s, "
    "resolution_batch_deadline_seconds={resolution_batch_deadline_seconds}s".format(**config)
)
if config["resolution_batch_deadline_seconds"] >= config["resolution_interval_seconds"]:
    print(
        "WARN resolution_batch_deadline_seconds >= resolution_interval_seconds -- a batch "
        "can still be running when the next cycle is due. The overlapping cycle is skipped "
        "rather than stacked, so this costs coverage, not stability. Lower the deadline."
    )

# The retry list is read from the resolution log, and the only writer of that
# log is the job that consumes the list -- so an absent log cannot bootstrap
# itself. Worth saying at launch rather than leaving the user to wonder why
# nothing is ever appended. See HOWTO.md "The monitor needs a seeded log".
from netdnsmonitor.stall_log import select_stalled_domains

stalled = select_stalled_domains(
    config["resolution_log_path"], stall_seconds=config["resolution_stall_seconds"]
)
if stalled:
    print(f"OK   resolution monitor will re-check {len(stalled)} ever-stalled domain(s)")
else:
    print(
        "WARN no stalled domains found in "
        f"{config['resolution_log_path']} -- the resolution monitor will be a no-op. "
        "It reads that log to decide what to retry, and it is also the only thing that "
        "writes it, so an empty log stays empty. See HOWTO.md "
        '"The monitor needs a seeded log".'
    )
if not config["domains"]:
    print(
        "WARN domains: is empty -- dns_ok will always be unknown, classify() will "
        "return unclassified (never healthy), and the status icon will latch to a "
        "false incident it can never clear. Add at least one real domain to "
        f"{config_file} (see HOWTO.md Troubleshooting)."
    )
PYEOF

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cp "$REPO_DIR/config.yaml" "$CONFIG_FILE"
    echo "..   wrote recommended defaults to $CONFIG_FILE -- edit 'domains:' before relying on health status"
fi
ok "config present at $CONFIG_FILE"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    info "ANTHROPIC_API_KEY not set -- Claude escalation will be skipped (reports still saved)"
else
    ok "ANTHROPIC_API_KEY set, escalation enabled"
fi

APP_BUNDLE="$REPO_DIR/dist/Net-DNS-Monitor.app"
APP_EXECUTABLE="$APP_BUNDLE/Contents/MacOS/Net-DNS-Monitor"

# A bare `python3 -m ...` process shares Apple's framework Python runtime,
# which re-execs itself into its own bundled Python.app the instant rumps
# creates an NSApplication -- that stub's Info.plist says "Python" and wins
# regardless of any wrapper .app around the outer script (confirmed
# empirically via `ps aux`: the running binary was
# .../Python.framework/.../Resources/Python.app/Contents/MacOS/Python, not
# anything of ours). py2app embeds a private interpreter copy that never
# touches that shared re-exec path -- confirmed empirically too: the
# embedded interpreter's own NSBundle.mainBundle() resolves to this
# project's bundle path and CFBundleName, not Python.framework's.
#
# Rebuilt only when missing or stale (py2app freezes the whole interpreter
# + dependencies, so it's much slower than a plain launch) -- stale means
# any tracked source file changed since the last build.
NEEDS_BUILD=0
if [[ ! -x "$APP_EXECUTABLE" ]]; then
    NEEDS_BUILD=1
elif [[ -n "$(find "$REPO_DIR/netdnsmonitor" "$REPO_DIR/setup.py" "$REPO_DIR/requirements.txt" \
        -name '__pycache__' -prune -o -newer "$APP_EXECUTABLE" -print 2>/dev/null)" ]]; then
    NEEDS_BUILD=1
fi

if [[ "$NEEDS_BUILD" == "1" ]]; then
    info "building $APP_BUNDLE (py2app) -- this is slower than a plain launch, only happens when the bundle is missing or source has changed"
    python -c "import py2app" >/dev/null 2>&1 || pip install -q "py2app>=0.28"
    # py2app's intermediate build/ staging dir isn't safe to reuse across
    # runs (confirmed empirically: a second py2app invocation failed with
    # "[Errno 66] Directory not empty" against a stale one) -- clear it,
    # not dist/, so a failed rebuild doesn't destroy the last-known-good app.
    rm -rf "$REPO_DIR/build"
    (cd "$REPO_DIR" && python setup.py py2app >/dev/null)
    [[ -x "$APP_EXECUTABLE" ]] || fail "py2app build did not produce $APP_EXECUTABLE"
    ok "built $APP_BUNDLE"
else
    ok "$APP_BUNDLE is up to date, skipping rebuild"
fi

LOG_FILE="$REPO_DIR/net-dns-monitor.log"

echo "== starting net-dns-monitor =="
info "launching as a .app bundle so the Dock/Force-Quit/Cmd-Tab name reads"
info "'Net-DNS-Monitor' instead of 'Python' -- this terminal is no longer"
info "attached to the app once launched. Output goes to: $LOG_FILE"
info "Quit it from the menu bar's Quit item (or: pkill -f Net-DNS-Monitor)"
open -n "$APP_BUNDLE" --stdout "$LOG_FILE" --stderr "$LOG_FILE"
