"""A bootpd-based replacement for macOS Internet Sharing: pf NAT out of the WAN
interface plus Apple's own DHCP server (bootpd) on the LAN interface, driven
from the Router window.

This is one of two router stacks in the repo, and they are mutually exclusive.
The other is `router/` + `unbound/`: dnsmasq for DHCP and unbound for DoT DNS
on 192.168.4.1, installed by `router/scripts/`. Both want UDP port 67, so
`start()` refuses while dnsmasq is running instead of fighting it for the port.
Clients here are handed the LAN IP as their DNS server, which is only useful
once something answers on it -- this stack does not run a resolver of its own.

Every OS side effect goes through `run_fn`, and the private working directory
through `tmp_dir`, so the script text, the validation in front of it and the
status strings are all testable offline. Outcomes are reported as strings --
`"ok"`, `"NEEDS_PRIVILEGE"`, `"failed: ..."` -- because the caller is a window
that has to say what happened, and an admin dialog the user cancelled is not a
router that started.
"""

import ipaddress
import os
import plistlib
import re
import shlex
import subprocess
import tempfile
from typing import Callable, Optional

PF_ANCHOR = "com.apple/custom_nat"

# Long enough for the password dialog to sit unanswered for a while; short
# enough that a dialog nobody is looking at does not pin the worker forever.
ADMIN_TIMEOUT_SECONDS = 120

# BSD interface names: en0, bridge100, utun5. Anything else is refused before
# it can be placed in a script that runs as root.
_IFACE_RE = re.compile(r"[a-z][a-z0-9]{1,14}")

# Config keys -> constructor arguments. The single place the mapping lives, so
# the window and the app build the same object from the same config.
CONFIG_ARGS = {
    "wan_interface": "wan_if",
    "lan_interface": "lan_if",
    "lan_ip": "lan_ip",
    "lan_netmask": "lan_netmask",
    "dhcp_start": "dhcp_start",
    "dhcp_end": "dhcp_end",
}


def default_run(argv: list[str], timeout: float) -> object:
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


def validate_settings(
    wan_if: str, lan_if: str, lan_ip: str, lan_netmask: str, dhcp_start: str, dhcp_end: str
) -> Optional[str]:
    """None when every value is safe to place in a root shell script, else
    `"failed: invalid <field>"` naming the first bad one.

    These values arrive from config.yaml and from text fields in the window,
    and the script they end up in runs under `with administrator privileges`.
    Quoting alone would keep the shell honest, but bootpd and pf read the same
    values from files, so the only defensible rule is that each one parses as
    what it claims to be.
    """
    for name, value in (("wan_if", wan_if), ("lan_if", lan_if)):
        if not isinstance(value, str) or not _IFACE_RE.fullmatch(value):
            return f"failed: invalid {name}"
    try:
        ip = ipaddress.IPv4Address(lan_ip)
    except (ValueError, TypeError):
        return "failed: invalid lan_ip"
    try:
        network = ipaddress.IPv4Interface(f"{ip}/{lan_netmask}").network
    except (ValueError, TypeError):
        return "failed: invalid lan_netmask"
    for name, value in (("dhcp_start", dhcp_start), ("dhcp_end", dhcp_end)):
        try:
            if ipaddress.IPv4Address(value) not in network:
                return f"failed: invalid {name}"
        except (ValueError, TypeError):
            return f"failed: invalid {name}"
    return None


def _write_private(path: str, data: bytes) -> None:
    # O_EXCL: the file must not already exist, so a symlink planted at this
    # name -- the classic /tmp trick against a script that root will run --
    # fails here as OSError instead of being followed.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class Router:
    def __init__(
        self,
        wan_if: str,
        lan_if: str,
        lan_ip: str,
        lan_netmask: str,
        dhcp_start: str,
        dhcp_end: str,
        *,
        run_fn: Callable[[list[str], float], object] = default_run,
        tmp_dir: Optional[str] = None,
    ):
        self.wan_if = wan_if
        self.lan_if = lan_if
        self.lan_ip = lan_ip
        self.lan_netmask = lan_netmask
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end
        self.run_fn = run_fn
        # None means a fresh mode-0700 directory per call. A fixed directory
        # exists for tests, which need to read back what would be handed to root.
        self.tmp_dir = tmp_dir

    @classmethod
    def from_config(cls, config: dict, **seams) -> "Router":
        return cls(**{arg: config[key] for key, arg in CONFIG_ARGS.items()}, **seams)

    # --- public --------------------------------------------------------------

    def start(self) -> str:
        error = validate_settings(
            self.wan_if, self.lan_if, self.lan_ip, self.lan_netmask, self.dhcp_start, self.dhcp_end
        )
        if error is not None:
            return error
        dnsmasq = self._dnsmasq_active()
        if dnsmasq is not None:
            return dnsmasq

        network = ipaddress.IPv4Interface(f"{self.lan_ip}/{self.lan_netmask}").network
        plist_data = {
            "Subnets": [
                {
                    "allocate": True,
                    "lease_max": 86400,
                    "lease_min": 86400,
                    "name": "LAN",
                    "net_address": str(network.network_address),
                    "net_mask": str(network.netmask),
                    "net_range": [self.dhcp_start, self.dhcp_end],
                    "dhcp_router": self.lan_ip,
                    "dhcp_domain_name_server": [self.lan_ip],
                }
            ],
            "bootp_enabled": False,
            "dhcp_enabled": [self.lan_if],
        }
        pf_rule = f"nat on {self.wan_if} from {self.lan_if}:network to any -> ({self.wan_if})\n"

        try:
            workdir = self._workdir()
            plist_path = os.path.join(workdir, "bootpd.plist")
            pf_path = os.path.join(workdir, "pf_nat.conf")
            _write_private(plist_path, plistlib.dumps(plist_data))
            _write_private(pf_path, pf_rule.encode("utf-8"))
        except OSError:
            return "failed: OSError"

        q = shlex.quote
        # `pfctl -e` exits 1 when pf is already enabled, which under `set -e`
        # would abort the script after the rules were loaded but before
        # bootpd was configured.
        script = (
            "#!/bin/sh\n"
            "set -e\n"
            f"ifconfig {q(self.lan_if)} {q(self.lan_ip)} netmask {q(self.lan_netmask)}\n"
            "sysctl -w net.inet.ip.forwarding=1\n"
            f"pfctl -a {PF_ANCHOR} -f {q(pf_path)}\n"
            "pfctl -e 2>/dev/null || true\n"
            f"mv {q(plist_path)} /etc/bootpd.plist\n"
            "/bin/launchctl unload -w /System/Library/LaunchDaemons/bootps.plist || true\n"
            "/bin/launchctl load -w /System/Library/LaunchDaemons/bootps.plist\n"
        )
        return self._run_admin(workdir, script)

    def stop(self) -> str:
        script = (
            "#!/bin/sh\n"
            "set -e\n"
            f"pfctl -a {PF_ANCHOR} -F all\n"
            "sysctl -w net.inet.ip.forwarding=0\n"
            "/bin/launchctl unload -w /System/Library/LaunchDaemons/bootps.plist || true\n"
        )
        try:
            workdir = self._workdir()
        except OSError:
            return "failed: OSError"
        return self._run_admin(workdir, script)

    # --- internals -----------------------------------------------------------

    def _workdir(self) -> str:
        if self.tmp_dir is not None:
            return self.tmp_dir
        return tempfile.mkdtemp(prefix="netdns-router-")

    def _dnsmasq_active(self) -> Optional[str]:
        try:
            proc = self.run_fn(["pgrep", "-x", "dnsmasq"], 10)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"failed: pgrep {type(exc).__name__}"
        if proc.returncode == 0:
            return "failed: dnsmasq stack active"
        return None

    def _run_admin(self, workdir: str, script: str) -> str:
        script_path = os.path.join(workdir, "router.sh")
        try:
            _write_private(script_path, script.encode("utf-8"))
        except OSError:
            return "failed: OSError"
        applescript = (
            f'do shell script "/bin/sh {shlex.quote(script_path)}" with administrator privileges'
        )
        try:
            proc = self.run_fn(["osascript", "-e", applescript], ADMIN_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"failed: {type(exc).__name__}"
        if proc.returncode == 0:
            return "ok"
        stderr = proc.stderr or b""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        # osascript exits 1 both for a cancelled dialog and for a script that
        # ran and failed; only the stderr text tells them apart.
        if "User canceled" in stderr:
            return "NEEDS_PRIVILEGE"
        return f"failed: osascript rc={proc.returncode}"
