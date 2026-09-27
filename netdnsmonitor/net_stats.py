"""Current throughput, read from the kernel's per-interface byte counters.

Measurement only -- the formatting of these numbers for the menu bar lives in
status.py, the same split the rest of this project uses.

Why shell out to netstat rather than use a library: the alternative is psutil,
a new runtime dependency that would have to be frozen into the py2app bundle,
and the bundling of this app has been fragile enough already (see setup.py).
`netstat -ibn` is in the base system and costs one short-lived subprocess per
tick. Absolute path for the same reason as /sbin/ping in ping.py: explicitness, not
necessity -- launchd's PATH does contain /usr/sbin, so a bare `netstat` would
resolve. See ping.py for the full rationale.

Parsing, and the two traps in it:

1. Only `<Link#N>` rows carry an interface's totals. The per-address rows
   underneath repeat the same numbers, so summing every row multiplies the
   total by the number of addresses the interface happens to have.

2. Those rows have a *variable* field count -- 11 when the interface has a MAC
   address, 10 when the Address column is blank (lo0, utun*, gif0). Both shapes
   appear in one netstat run on this machine, so a left-anchored index reads
   Ibytes on some interfaces and Opkts on others, and the result still looks
   like a plausible number. The trailing seven columns are always
   `Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll`, so this parses from the right.

Which interfaces count: `en*` only, i.e. Wi-Fi and Ethernet. Deliberately not
`utun*`, because VPN traffic is also carried over en0 and is therefore already
in that total -- adding both roughly doubles the reported rate whenever a
tunnel is up. Also excluded: `lo0` (loopback isn't network traffic), `awdl0` /
`llw0` (AirDrop and friends), `bridge*` / `ap1` (internet sharing).
"""

import subprocess
import time
from typing import Callable, Optional

RunFn = Callable[..., object]

NETSTAT_BIN = "/usr/sbin/netstat"

INTERFACE_PREFIXES = ("en",)

# Offsets from the END of a Link row: ... Ibytes Opkts Oerrs Obytes Coll
IBYTES_FROM_END = -5
OBYTES_FROM_END = -2
MIN_LINK_ROW_FIELDS = 10


def parse_interface_counters(
    netstat_output: Optional[str],
    prefixes: tuple[str, ...] = INTERFACE_PREFIXES,
) -> Optional[tuple[int, int]]:
    """Total (bytes in, bytes out) across the physical interfaces.

    None when no matching link row parsed. Summing nothing to (0, 0) would
    reach ThroughputMeter as a real reading, so a netstat format change or a
    sandbox that hides interfaces would render "measured, idle" on every tick.
    """
    total_in = total_out = 0
    matched = False
    for line in (netstat_output or "").splitlines():
        fields = line.split()
        if len(fields) < MIN_LINK_ROW_FIELDS:
            continue
        # The totals live on the link-layer row only; see trap 1 above.
        if not fields[2].startswith("<Link#"):
            continue
        # A trailing `*` means the interface is currently down. Its accumulated
        # bytes still belong in the total: dropping them the moment Wi-Fi goes
        # away would look like a large negative delta, i.e. a counter reset.
        name = fields[0].rstrip("*")
        if not name.startswith(prefixes):
            continue
        try:
            row_in = int(fields[IBYTES_FROM_END])
            row_out = int(fields[OBYTES_FROM_END])
        except ValueError:
            # One unexpected line must not take down a heartbeat that runs
            # every 5 seconds for the life of the process.
            continue
        total_in += row_in
        total_out += row_out
        matched = True
    return (total_in, total_out) if matched else None


def read_interface_counters(run_fn: RunFn = subprocess.run) -> Optional[tuple[int, int]]:
    """Run netstat and parse it. None on any failure, including output with no
    matching interface row -- the caller renders a blank throughput reading
    rather than dying, since this is display data.
    """
    try:
        result = run_fn(
            [NETSTAT_BIN, "-ibn"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return None
    if result.returncode != 0:
        return None
    return parse_interface_counters(result.stdout)


class ThroughputMeter:
    """Turns successive cumulative counter readings into a bits-per-second rate.

    Bits, not bytes, because the unit people read a network rate in is Mbps.
    """

    def __init__(self):
        self._last: Optional[tuple[int, int]] = None
        self._last_at: Optional[float] = None

    def sample(
        self,
        counters: Optional[tuple[int, int]],
        now: Optional[float] = None,
    ) -> tuple[Optional[float], Optional[float]]:
        """Record a reading and return (down_bps, up_bps), or (None, None) when
        no rate can be derived yet.

        (None, None) and (0.0, 0.0) are deliberately different: the first means
        "not measured", the second means "measured, idle", and the title renders
        them differently.
        """
        if now is None:
            now = time.monotonic()
        if counters is None:
            # A failed netstat read leaves the baseline alone rather than
            # clearing it, so one blip doesn't cost two cycles of throughput.
            return None, None

        previous, previous_at = self._last, self._last_at
        self._last, self._last_at = counters, now

        if previous is None or previous_at is None:
            return None, None

        elapsed = now - previous_at
        if elapsed <= 0:
            return None, None

        delta_in = counters[0] - previous[0]
        delta_out = counters[1] - previous[1]
        # Not handled, deliberately: the mirror case, where an interface
        # *appears*. Plugging in a dock adds en9 with its accumulated total
        # already in the gigabytes, and that shows up here as one enormous
        # positive delta -- a single cycle rendering something like "1.8G↓".
        # Detecting it would mean tracking counters per interface rather than as
        # a total, which is a lot of machinery for one wrong cosmetic reading
        # that corrects itself on the next cadence.
        if delta_in < 0 or delta_out < 0:
            # Totals can go down: a reboot, a sleep/wake that re-creates
            # interfaces, or an unplugged dock Ethernet whose row leaves
            # netstat. The baseline has already been rebound above, so the next
            # sample produces a real rate instead of wedging on None forever.
            return None, None

        return delta_in * 8 / elapsed, delta_out * 8 / elapsed
