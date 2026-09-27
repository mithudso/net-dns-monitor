"""Measure what works inside the App Sandbox, from inside it.

Built into an ad-hoc bundle only (`build_appstore.py adhoc --with-probe`) and
run directly:

  build/appstore/adhoc/dist/Net-DNS-Monitor.app/Contents/MacOS/sandbox_probe

The sandbox is applied from the executable's own entitlements at launch, so a
probe started from Terminal is confined exactly like the app. Each check
records what happened; nothing is inferred. A check that could not run is
"not probed", never a pass or a fail.

Every check is read-only. Nothing here changes network settings, flushes a
cache, sends a notification or writes outside the container, apart from one
throwaway Keychain item that is deleted again, and one file in the container.

Results print as JSON and are also written to
~/Library/Application Support/net-dns-monitor/sandbox-probe.json, which inside
the sandbox resolves to the app's container.
"""

import json
import os
import pwd
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

READ_ONLY_COMMANDS = {
    "ping": ["/sbin/ping", "-c", "1", "-t", "3", "1.1.1.1"],
    "networksetup_list_order": ["/usr/sbin/networksetup", "-listnetworkserviceorder"],
    "scutil_nwi": ["/usr/sbin/scutil", "--nwi"],
    "scutil_dns": ["/usr/sbin/scutil", "--dns"],
    "netstat_interfaces": ["/usr/sbin/netstat", "-ibn"],
    "netstat_routes": ["/usr/sbin/netstat", "-rn", "-f", "inet"],
    "ifconfig": ["/sbin/ifconfig"],
    "route_default": ["/sbin/route", "-n", "get", "default"],
    "log_show": [
        "/usr/bin/log",
        "show",
        "--last",
        "1m",
        "--style",
        "compact",
        "--predicate",
        'eventMessage CONTAINS "network"',
    ],
}


def timed(fn):
    started = time.monotonic()
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the probe records every failure as data
        result = {"ok": False, "error": type(exc).__name__}
    result["seconds"] = round(time.monotonic() - started, 3)
    return result


def run_command(argv):
    def check():
        done = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=20)
        stderr = done.stderr.strip().splitlines()
        return {
            "ok": done.returncode == 0,
            "returncode": done.returncode,
            "stdout_lines": len(done.stdout.splitlines()),
            "stderr_first_line": stderr[0][:200] if stderr else "",
        }

    return timed(check)


def tcp_connect():
    with socket.create_connection(("1.1.1.1", 443), timeout=5):
        return {"ok": True}


def getaddrinfo():
    infos = socket.getaddrinfo("api.anthropic.com", 443, proto=socket.IPPROTO_TCP)
    return {"ok": bool(infos), "addresses": len(infos)}


def udp_dns():
    from netdnsmonitor.dns_query import query_public_dns

    answer = query_public_dns("example.com")
    return {"ok": answer is True, "answer": answer}


def https_request():
    try:
        with urllib.request.urlopen("https://api.anthropic.com/", timeout=8) as response:
            return {"ok": True, "status": response.status}
    except urllib.error.HTTPError as exc:
        # Any HTTP status proves TLS and the network path worked.
        return {"ok": True, "status": exc.code}


def default_route_interface():
    try:
        done = subprocess.run(
            ["/sbin/route", "-n", "get", "default"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in done.stdout.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "interface":
            return value.strip() or None
    return None


def interface_bound_connect():
    # The default-route interface goes first: an idle Thunderbolt or USB port
    # reads False with or without a sandbox, so a probe that never tries the
    # interface carrying traffic proves nothing about IP_BOUND_IF.
    names = sorted(name for _index, name in socket.if_nameindex() if name.startswith("en"))
    primary = default_route_interface()
    if primary in names:
        names.remove(primary)
        names.insert(0, primary)
    if not names:
        return {"ok": None, "note": "no en* interface present; not probed"}
    from netdnsmonitor.interface_probe import make_interface_prober

    prober = make_interface_prober([("1.1.1.1", 443)], timeout=4)
    results = {name: prober(name) for name in names[:8]}
    return {
        "ok": results.get(primary) if primary in results else None,
        "default_route_interface": primary,
        "per_interface": results,
    }


def udp_bind():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 0))
        return {"ok": True, "port": sock.getsockname()[1]}
    finally:
        sock.close()


def container_write():
    directory = os.path.expanduser("~/Library/Application Support/net-dns-monitor")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "sandbox-probe-write-test.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("ok")
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    os.remove(path)
    return {"ok": content == "ok", "directory": directory}


def read_real_home_config():
    real_home = pwd.getpwuid(os.getuid()).pw_dir
    path = os.path.join(real_home, ".config", "net-dns-monitor", "config.yaml")
    if not os.path.lexists(path):
        return {"ok": None, "note": "no config at the real home path; not probed"}
    try:
        with open(path, encoding="utf-8") as handle:
            handle.read(1)
        return {"ok": True, "note": "readable (sandbox did not block it)"}
    except PermissionError:
        return {"ok": False, "note": "blocked by the sandbox, as expected"}


def keychain_round_trip():
    from netdnsmonitor.credentials import make_keychain_backend

    backend = make_keychain_backend(service="com.net-dns-monitor.sandbox-probe")
    account = "probe"
    backend.delete(account)
    added = backend.add(account, b"probe-value")
    status, value = backend.read(account)
    deleted = backend.delete(account)
    return {
        "ok": added == 0 and status == 0 and value == b"probe-value" and deleted == 0,
        "add_status": added,
        "read_status": status,
        "delete_status": deleted,
    }


def main() -> int:
    from netdnsmonitor.distribution import detect

    caps = detect()
    results = {
        "environment": {
            "sandboxed": caps.sandboxed,
            "distribution": caps.distribution,
            "home": os.path.expanduser("~"),
            "python": sys.version.split()[0],
        },
        "checks": {
            "container_write": timed(container_write),
            "read_real_home_config": timed(read_real_home_config),
            "tcp_connect": timed(tcp_connect),
            "getaddrinfo": timed(getaddrinfo),
            "udp_dns": timed(udp_dns),
            "https_request": timed(https_request),
            "interface_bound_connect": timed(interface_bound_connect),
            "udp_bind": timed(udp_bind),
            "keychain_round_trip": timed(keychain_round_trip),
        },
    }
    for name, argv in READ_ONLY_COMMANDS.items():
        results["checks"][f"exec_{name}"] = run_command(argv)

    text = json.dumps(results, indent=2, sort_keys=True)
    print(text)
    try:
        out_dir = os.path.expanduser("~/Library/Application Support/net-dns-monitor")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "sandbox-probe.json"), "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        print(f"could not write results file: {type(exc).__name__}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
