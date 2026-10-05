"""The app's own router mode: bootpd DHCP on a LAN interface plus pf NAT out a WAN.

This is a separate implementation from the `router/` stack (dnsmasq + unbound
on 192.168.4.0/24, NAT in the `com.apple/custom_nat` anchor, installed as the
`com.custom.router.nat` LaunchDaemon). The two conflict -- both want UDP 67 and
both own `net.inet.ip.forwarding` -- so this class refuses to touch the machine
while that LaunchDaemon is installed. Which stack is canonical is an owner
decision; neither is deleted here.

Every value that reaches the root script is validated first. The script runs
as root, and an interface name or address typed into a window is otherwise a
shell command waiting to happen (`lan_ip = "1.1.1.1; id"`).
"""

import base64
import ipaddress
import logging
import os
import plistlib
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from netdnsmonitor.privileges import _CANCELLED_RE, _osascript_admin

log = logging.getLogger(__name__)

RunFn = Callable[..., object]

# The app's defaults, in one place so the window and the menu agree.
DEFAULTS = {
    "wan_interface": "en3",
    "lan_interface": "en0",
    "lan_ip": "192.168.10.1",
    "lan_netmask": "255.255.255.0",
    "dhcp_start": "192.168.10.100",
    "dhcp_end": "192.168.10.200",
}

# Apple's /etc/pf.conf evaluates `nat-anchor "com.apple/*"`, so a rule loaded
# here takes effect without replacing the main ruleset. `pfctl -f` on the main
# ruleset would drop every other anchor's rules, including the router/ stack's.
PF_ANCHOR = "com.apple/netdnsmonitor_nat"
BOOTPD_PLIST = "/etc/bootpd.plist"
BOOTPS_DAEMON = "/System/Library/LaunchDaemons/bootps.plist"
BOOTPD_LABEL = "com.apple.bootpd"
ROUTER_STACK_DAEMON = "/Library/LaunchDaemons/com.custom.router.nat.plist"
# The token `pfctl -E` prints for the pf enable reference this app holds. pf
# stays enabled while any reference is outstanding, so stop can release only
# the one start took. /var/run is root-only and cleared at boot, which is also
# when the kernel forgets every reference.
PF_TOKEN_FILE = "/var/run/netdnsmonitor_pf.token"
# net.inet.ip.forwarding as it stood before the first start, so stop can put it
# back instead of forcing 0 on a Mac that was forwarding for another reason
# (VPN, internet sharing). Same lifetime reasoning as the token file.
FORWARDING_FILE = "/var/run/netdnsmonitor_forwarding.prior"

# Long enough for a human to answer the authentication dialog; the script itself
# takes seconds. Unbounded, a caller on the main thread freezes the menu bar and
# the monitoring timers for as long as the dialog sits unanswered.
DEFAULT_TIMEOUT_SECONDS = 180.0

# /31 and /32 have no host range for a DHCP pool; below /8 is not a LAN.
MIN_PREFIX = 8
MAX_PREFIX = 30

_INTERFACE_RE = re.compile(r"[a-z]+[0-9]+")

# Markers the stop script's read-backs print to stderr before exiting 5 or 6.
# Matched by marker, not by exit code: `set -e` exits with whatever code the
# failing step returned, and 5 is an ordinary one (launchctl's I/O error).
_READBACK_FAILURES = {
    "NDM_START_PF_TOKEN": "pfctl -E gave no enable token, so pf may not be enabled",
    "NDM_START_NAT_NOT_LOADED": f"no NAT rule is loaded in {PF_ANCHOR} after the load",
    "NDM_START_BOOTPD_NOT_LOADED": "the bootpd launchd job is not loaded after the load",
    "NDM_NAT_STILL_LOADED": f"NAT rules are still loaded in {PF_ANCHOR} after the flush",
    "NDM_BOOTPD_STILL_LOADED": "the bootpd launchd job is still loaded after the unload",
}
# `do shell script` makes osascript exit 1 whatever the script returned; the
# script's own code survives only as the trailing "(5)" of the error text.
_SCRIPT_EXIT_RE = re.compile(r"\((\d+)\)\s*$")

CONFLICT_MESSAGE = (
    "refused: the router/ NAT LaunchDaemon (com.custom.router.nat) is installed; "
    "the app's bootpd router would conflict with it"
)

BUSY_MESSAGE = "refused: another router start or stop is still running"


@dataclass(frozen=True)
class RouterSettings:
    wan_if: str
    lan_if: str
    lan_ip: str
    netmask: str
    network: str
    dhcp_start: str
    dhcp_end: str


def _contiguous_netmask(text) -> bool:
    """`ipaddress` reads `0.0.0.255` as a hostmask and quietly turns it into
    /24, so a dotted value is checked to be ones-then-zeros before it is trusted.
    """
    text = str(text)
    if "." not in text:
        return True
    try:
        inverted = ~int(ipaddress.IPv4Address(text)) & 0xFFFFFFFF
    except ValueError:
        return False
    return inverted & (inverted + 1) == 0


def validate(wan_if, lan_if, lan_ip, lan_netmask, dhcp_start, dhcp_end) -> RouterSettings:
    """Return normalised settings, or raise ValueError naming the bad field."""
    for field, value in (("wan_interface", wan_if), ("lan_interface", lan_if)):
        if not isinstance(value, str) or not _INTERFACE_RE.fullmatch(value):
            raise ValueError(f"{field} {value!r} is not an interface name like en0")
    if wan_if == lan_if:
        raise ValueError("WAN and LAN are the same interface")
    addresses = {}
    for field, value in (("lan_ip", lan_ip), ("dhcp_start", dhcp_start), ("dhcp_end", dhcp_end)):
        try:
            addresses[field] = ipaddress.IPv4Address(str(value))
        except ValueError:
            raise ValueError(f"{field} {value!r} is not an IPv4 address") from None
    if not _contiguous_netmask(lan_netmask):
        raise ValueError(f"lan_netmask {lan_netmask!r} is not a netmask")
    try:
        interface = ipaddress.IPv4Interface(f"{addresses['lan_ip']}/{lan_netmask}")
    except ValueError:
        raise ValueError(f"lan_netmask {lan_netmask!r} is not a netmask") from None
    network = interface.network
    lan = addresses["lan_ip"]
    # The script runs `ifconfig <lan_if> <lan_ip>` as root and hands out leases
    # on it; a loopback, link-local, public or /0 network is never a LAN.
    if not lan.is_private or lan.is_loopback or lan.is_link_local or lan.is_unspecified:
        raise ValueError(f"lan_ip {lan} is not a private LAN address")
    if not MIN_PREFIX <= network.prefixlen <= MAX_PREFIX:
        raise ValueError(
            f"lan_netmask /{network.prefixlen} is outside /{MIN_PREFIX} to /{MAX_PREFIX}"
        )
    reserved = {network.network_address, network.broadcast_address}
    if addresses["lan_ip"] in reserved:
        raise ValueError("lan_ip is a network or broadcast address")
    for field in ("dhcp_start", "dhcp_end"):
        if addresses[field] not in network:
            raise ValueError(f"{field} {addresses[field]} is outside {network}")
        if addresses[field] in reserved:
            raise ValueError(f"{field} is a network or broadcast address")
    if addresses["dhcp_start"] > addresses["dhcp_end"]:
        raise ValueError("dhcp_start is after dhcp_end")
    if addresses["dhcp_start"] <= addresses["lan_ip"] <= addresses["dhcp_end"]:
        raise ValueError("DHCP pool includes lan_ip")
    return RouterSettings(
        wan_if=wan_if,
        lan_if=lan_if,
        lan_ip=str(addresses["lan_ip"]),
        netmask=str(network.netmask),
        network=str(network.network_address),
        dhcp_start=str(addresses["dhcp_start"]),
        dhcp_end=str(addresses["dhcp_end"]),
    )


def bootpd_plist(settings: RouterSettings) -> dict:
    return {
        "Subnets": [
            {
                "allocate": True,
                "lease_max": 86400,
                "lease_min": 86400,
                "name": "LAN",
                # bootpd requires net_mask applied to net_range to yield
                # net_address, so this is derived rather than assumed to be a /24.
                "net_address": settings.network,
                "net_mask": settings.netmask,
                "net_range": [settings.dhcp_start, settings.dhcp_end],
                # `dhcp_router` is the key bootpd(8) reads for option 3; the
                # `routers` key this used to write was silently ignored.
                "dhcp_router": settings.lan_ip,
                "dhcp_domain_name_server": ["8.8.8.8", "1.1.1.1"],
            }
        ],
        "bootp_enabled": False,
        "dhcp_enabled": [settings.lan_if],
    }


def pf_rule(settings: RouterSettings) -> str:
    return (
        f"nat on {settings.wan_if} from {settings.lan_if}:network to any -> ({settings.wan_if})\n"
    )


def _b64(data: bytes) -> str:
    # Alphanumeric plus `+/=`, so file contents cannot close a quote or start a
    # second command on the way through AppleScript and then sh -- the same
    # reason privileges._install_script encodes the sudoers body.
    return base64.b64encode(data).decode("ascii")


def start_script(settings: RouterSettings) -> str:
    """One newline-free root script. No file is staged anywhere a user can write:
    a script left in /tmp can be swapped while the password dialog is open.
    """
    plist = _b64(plistlib.dumps(bootpd_plist(settings)))
    rule = _b64(pf_rule(settings).encode("utf-8"))
    return "; ".join(
        [
            "set -e",
            f"/sbin/ifconfig {settings.lan_if} {settings.lan_ip} netmask {settings.netmask}",
            f"echo {rule} | /usr/bin/base64 -D | /sbin/pfctl -a {PF_ANCHOR} -f -",
            # -E, not -e: `-e` exits non-zero when pf is already enabled, which
            # under `set -e` would abort a start on any machine with pf on. But
            # each -E adds a reference that only its token releases, so a second
            # start while this app already holds one takes none. A token with pf
            # disabled is void (`pfctl -d` drops every reference), so it is
            # replaced rather than trusted.
            f"if [ ! -s {PF_TOKEN_FILE} ] || "
            "! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q 'Status: Enabled'; then "
            f"/sbin/pfctl -E 2>&1 | /usr/bin/sed -n 's/^Token : //p' > {PF_TOKEN_FILE}; fi",
            # The pipeline's status is sed's, so a failed enable shows up here
            # as a missing token rather than being passed over.
            f"[ -s {PF_TOKEN_FILE} ] || {{ echo NDM_START_PF_TOKEN >&2; exit 7; }}",
            # Staged inside /etc (root-only) and renamed into place.
            "tmp=$(/usr/bin/mktemp /etc/.bootpd.plist.XXXXXX)",
            f'echo {plist} | /usr/bin/base64 -D > "$tmp"',
            '/usr/sbin/chown root:wheel "$tmp"',
            '/bin/chmod 644 "$tmp"',
            f'/bin/mv -f "$tmp" {BOOTPD_PLIST}',
            # DHCP is opt-in. `load -w` wrote an enabled override, after which
            # bootpd answered DHCP on every boot whether or not the router was
            # on. `-F` loads it for this session only; Stop's `unload -w`
            # writes the disabled override back.
            f"/bin/launchctl unload {BOOTPS_DAEMON} || true",
            f"/bin/launchctl load -F {BOOTPS_DAEMON}",
            # Read back before anything is reported as started: `launchctl load`
            # can exit 0 without loading, and an anchor can be loaded empty.
            f"/sbin/pfctl -a {PF_ANCHOR} -s nat 2>/dev/null | /usr/bin/grep -q 'nat on' "
            "|| { echo NDM_START_NAT_NOT_LOADED >&2; exit 5; }",
            f"/bin/launchctl print system/{BOOTPD_LABEL} >/dev/null 2>&1 "
            "|| { echo NDM_START_BOOTPD_NOT_LOADED >&2; exit 6; }",
            # Only the first start records it: a restart would otherwise record
            # the 1 this app set and restore that on stop.
            f"if [ ! -s {FORWARDING_FILE} ]; then "
            f"/usr/sbin/sysctl -n net.inet.ip.forwarding > {FORWARDING_FILE}; fi",
            # Last, so a step that fails above never leaves the Mac forwarding
            # packets with no NAT or DHCP behind it.
            "/usr/sbin/sysctl -w net.inet.ip.forwarding=1",
        ]
    )


def stop_script() -> str:
    return "; ".join(
        [
            "set -e",
            # Only this app's anchor. `pfctl -F all -d` flushed every ruleset and
            # disabled pf for everything else on the machine.
            # `|| true`: the read-back below decides, not this exit code, which
            # may be non-zero for an anchor that was never loaded.
            f"/sbin/pfctl -a {PF_ANCHOR} -F all || true",
            # Restores the recorded value; with no record, forwarding is left
            # as found rather than guessed. Only 0 or 1 is ever written back.
            f"if [ -s {FORWARDING_FILE} ]; then prior=$(/bin/cat {FORWARDING_FILE}); "
            'case "$prior" in 0|1) /usr/sbin/sysctl -w net.inet.ip.forwarding="$prior";; esac; '
            f"/bin/rm -f {FORWARDING_FILE}; fi",
            # Releases only the reference start took; pf stays on if anything
            # else on the machine still holds one. `|| true`: a token from
            # before a `pfctl -d` is already void, and must not block the stop.
            f"if [ -s {PF_TOKEN_FILE} ]; then "
            f'/sbin/pfctl -X "$(/bin/cat {PF_TOKEN_FILE})" || true; /bin/rm -f {PF_TOKEN_FILE}; fi',
            f"/bin/launchctl unload -w {BOOTPS_DAEMON} || true",
            # `set -e` does not fire on a negated test, hence the explicit exits.
            # The marker names the read-back; see _READBACK_FAILURES.
            f"if /sbin/pfctl -a {PF_ANCHOR} -s nat 2>/dev/null | /usr/bin/grep -q 'nat on'; "
            "then echo NDM_NAT_STILL_LOADED >&2; exit 5; fi",
            f"if /bin/launchctl print system/{BOOTPD_LABEL} >/dev/null 2>&1; "
            "then echo NDM_BOOTPD_STILL_LOADED >&2; exit 6; fi",
        ]
    )


def _path_present(path: str) -> bool:
    """False only when the path is known to be absent. `os.path.exists` turns
    every OSError (a permission error included) into False, which would read as
    "the router/ daemon is not installed" and let the two stacks collide.
    """
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


class Router:
    def __init__(
        self,
        wan_if=DEFAULTS["wan_interface"],
        lan_if=DEFAULTS["lan_interface"],
        lan_ip=DEFAULTS["lan_ip"],
        lan_netmask=DEFAULTS["lan_netmask"],
        dhcp_start=DEFAULTS["dhcp_start"],
        dhcp_end=DEFAULTS["dhcp_end"],
        run_fn: RunFn = subprocess.run,
        exists_fn: Callable[[str], bool] = _path_present,
        timeout: Optional[float] = DEFAULT_TIMEOUT_SECONDS,
        primary_interface_fn: Callable[[], Optional[str]] = lambda: None,
    ):
        # Not validated here: the app constructs this at launch, and a bad config
        # value must not crash the app. `start` validates, and so catches values
        # assigned to these attributes after construction too.
        self.wan_if = wan_if
        self.lan_if = lan_if
        self.lan_ip = lan_ip
        self.lan_netmask = lan_netmask
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end
        self.run_fn = run_fn
        self.exists_fn = exists_fn
        self.timeout = timeout
        self.primary_interface_fn = primary_interface_fn
        # The menu and the router window each run start/stop on their own
        # worker; two root scripts interleaving on pf and bootpd is worse than
        # either one. Non-blocking: a second caller is told, not queued behind a
        # password dialog that may never be answered.
        self._lock = threading.Lock()

    def settings(self) -> RouterSettings:
        return validate(
            self.wan_if,
            self.lan_if,
            self.lan_ip,
            self.lan_netmask,
            self.dhcp_start,
            self.dhcp_end,
        )

    def _conflict(self) -> bool:
        try:
            return bool(self.exists_fn(ROUTER_STACK_DAEMON))
        except OSError:
            # Unknown is not "absent": refusing is the safe answer.
            return True

    def start(self) -> str:
        """Returns an outcome string: `ok:`, `cancelled:`, `refused:` or `failed:`."""
        if not self._lock.acquire(blocking=False):
            return BUSY_MESSAGE
        try:
            return self._start()
        finally:
            self._lock.release()

    def _start(self) -> str:
        if self._conflict():
            return CONFLICT_MESSAGE
        try:
            settings = self.settings()
        except ValueError as exc:
            return f"refused: {exc}"
        # `ifconfig <lan_if> <lan_ip>` replaces the interface's address, so a LAN
        # interface that carries the default route would cut this Mac off. None
        # means unknown (no route, a VPN, a failed lookup) and does not refuse.
        try:
            primary = self.primary_interface_fn()
        except Exception as exc:  # noqa: BLE001 - a failed lookup must not stop or crash a start
            log.warning("primary interface lookup failed (%s)", type(exc).__name__)
            primary = None
        if primary is not None and primary == settings.lan_if:
            return f"refused: lan_interface {settings.lan_if} carries this Mac's default route"
        log.info("Starting router/DHCP: WAN=%s, LAN=%s", settings.wan_if, settings.lan_if)
        outcome = self._run_admin(start_script(settings))
        if outcome.startswith("ok"):
            return (
                f"ok: router started (read back: NAT {settings.lan_if} -> {settings.wan_if} "
                f"in {PF_ANCHOR}, bootpd job loaded for {settings.lan_if})"
            )
        return outcome

    def stop(self) -> str:
        if not self._lock.acquire(blocking=False):
            return BUSY_MESSAGE
        try:
            return self._stop()
        finally:
            self._lock.release()

    def _stop(self) -> str:
        # The stop script sets forwarding to 0, which would cut off every client
        # of the router/ stack; the same guard as start applies.
        if self._conflict():
            return CONFLICT_MESSAGE
        log.info("Stopping router/DHCP")
        outcome = self._run_admin(stop_script())
        if outcome.startswith("ok"):
            return (
                f"ok: router stopped (read back: {PF_ANCHOR} empty, bootpd job unloaded); "
                "the LAN interface address set at start is not restored"
            )
        return outcome

    def _run_admin(self, script: str) -> str:
        try:
            result = self.run_fn(
                _osascript_admin(script),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return (
                f"failed: no answer after {self.timeout}s; if the password was "
                "entered, the script may have partly run"
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            return f"failed: could not run osascript ({type(exc).__name__})"
        rc = getattr(result, "returncode", 1)
        if rc == 0:
            return "ok"
        stderr = getattr(result, "stderr", "") or ""
        if _CANCELLED_RE.search(stderr):
            return "cancelled: nothing was changed"
        # The exit code and a fixed description only: stderr from an
        # authorisation failure is not echoed. `set -e` stops at the first
        # failing step, so earlier steps may stand.
        code = _SCRIPT_EXIT_RE.search(stderr)
        if code is not None:
            rc = int(code.group(1))
        detail = next(
            (text for marker, text in _READBACK_FAILURES.items() if marker in stderr),
            "steps before the failing one may have taken effect",
        )
        return f"failed: exit {rc}; {detail}"
