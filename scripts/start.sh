#!/usr/bin/env bash
# Check the install, verify every netdnsmonitor component, apply the
# recommended config if none exists yet, then start the app.
#
# The app takes no CLI flags (see netdnsmonitor/app.py main()) -- the
# "recommended options" are the shipped config.example.yaml defaults, so
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
    "netdnsmonitor.escalation", "netdnsmonitor.anthropic_escalator",
    "netdnsmonitor.report", "netdnsmonitor.report_storage", "netdnsmonitor.status",
    "netdnsmonitor.state_machine", "netdnsmonitor.app",
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
    "resolution_top_n={resolution_top_n}".format(**config)
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
    cp "$REPO_DIR/config.example.yaml" "$CONFIG_FILE"
    echo "..   wrote recommended defaults to $CONFIG_FILE -- edit 'domains:' before relying on health status"
fi
ok "config present at $CONFIG_FILE"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    info "ANTHROPIC_API_KEY not set -- Claude escalation will be skipped (reports still saved)"
else
    ok "ANTHROPIC_API_KEY set, escalation enabled"
fi

echo "== starting net-dns-monitor =="
exec python -m netdnsmonitor.app
