"""The ping heartbeat's parsing and failure handling. The subprocess is
injected, so none of this touches a real network -- the empirical facts these
tests encode (exit 2 on no reply, exit 68 on an unresolvable name, `-t` as the
flag that actually bounds the call) were measured against /sbin/ping on this
machine and are recorded in ping.py's docstring.
"""

import subprocess
from types import SimpleNamespace

from netdnsmonitor.ping import PING_BIN, ping_once

REPLY = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=61.366 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 61.366/61.366/61.366/0.000 ms
"""

NO_REPLY = """PING 192.0.2.1 (192.0.2.1): 56 data bytes

--- 192.0.2.1 ping statistics ---
1 packets transmitted, 0 packets received, 100.0% packet loss
"""


def fake_run_factory(returncode=0, stdout=REPLY, stderr=""):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return fake_run, calls


def test_successful_ping_reports_ok_and_the_round_trip_time():
    run_fn, _ = fake_run_factory(returncode=0, stdout=REPLY)
    result = ping_once("8.8.8.8", run_fn=run_fn)
    assert result["ok"] is True
    assert result["rtt_ms"] == 61.366
    assert result["error"] is None


def test_uses_the_absolute_ping_path_not_a_bare_name():
    """launchd starts the app with a minimal PATH. A bare `ping` resolves in an
    interactive shell and not in the installed bundle, so the heartbeat would
    fail only in production -- exactly the class of bug this project already
    hit with locale encoding.
    """
    run_fn, calls = fake_run_factory()
    ping_once("8.8.8.8", run_fn=run_fn)
    assert calls[0][0][0] == PING_BIN
    assert PING_BIN.startswith("/")


def test_sends_exactly_one_echo_request_and_bounds_the_run():
    """Asserting the full argv, not `"-c" in args`: this is polled every 5
    seconds, so dropping `-c 1` turns each tick into an unbounded ping that
    never exits, and dropping `-t` removes the only ceiling that keeps a
    failed ping inside its own cadence (measured 3.08s with -t 3).
    """
    run_fn, calls = fake_run_factory()
    ping_once("8.8.8.8", timeout_seconds=3.0, run_fn=run_fn)
    args = calls[0][0]
    assert args == [PING_BIN, "-c", "1", "-W", "3000", "-t", "3", "8.8.8.8"]


def test_sub_second_timeout_still_gets_at_least_one_second_of_t():
    """`-t 0` means "no timeout" to BSD ping -- the opposite of a short one --
    so a fractional timeout must round up, not truncate.
    """
    run_fn, calls = fake_run_factory()
    ping_once("8.8.8.8", timeout_seconds=0.4, run_fn=run_fn)
    args = calls[0][0]
    assert args[args.index("-t") + 1] == "1"
    assert args[args.index("-W") + 1] == "400"


def test_no_reply_reports_failure():
    # Measured: /sbin/ping -c 1 -W 2000 -t 3 192.0.2.1 exits 2.
    run_fn, _ = fake_run_factory(returncode=2, stdout=NO_REPLY)
    result = ping_once("192.0.2.1", run_fn=run_fn)
    assert result["ok"] is False
    assert result["rtt_ms"] is None
    assert "no reply" in result["error"].lower()


def test_unresolvable_host_reports_the_resolver_error():
    # Measured: exit 68, message on stderr.
    run_fn, _ = fake_run_factory(
        returncode=68, stdout="", stderr="ping: cannot resolve nope.invalid: Unknown host\n"
    )
    result = ping_once("nope.invalid", run_fn=run_fn)
    assert result["ok"] is False
    assert "cannot resolve" in result["error"]


def test_a_reply_with_no_parsable_time_is_still_a_success():
    """rtt is for display only. Treating an unparsable time as a failed ping
    would fire the network-failed alert on a network that answered.
    """
    run_fn, _ = fake_run_factory(returncode=0, stdout="64 bytes from 8.8.8.8: icmp_seq=0 ttl=117\n")
    result = ping_once("8.8.8.8", run_fn=run_fn)
    assert result["ok"] is True
    assert result["rtt_ms"] is None


def test_time_reported_with_a_less_than_sign_is_parsed():
    """A sub-millisecond reply on a LAN prints `time<1 ms` rather than
    `time=0.5 ms`, which an `=`-only pattern silently drops.
    """
    run_fn, _ = fake_run_factory(
        returncode=0, stdout="64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time<1 ms\n"
    )
    result = ping_once("192.168.1.1", run_fn=run_fn)
    assert result["ok"] is True
    assert result["rtt_ms"] == 1.0


def test_requests_explicit_utf8_decoding_instead_of_relying_on_locale():
    """launchd gives the app no LANG at all, which makes the frozen bundle's
    locale encoding US-ASCII. That already caused 0-byte incident reports in
    this repo; an unencoded read here would raise on any non-ASCII byte.
    """
    run_fn, calls = fake_run_factory()
    ping_once("8.8.8.8", run_fn=run_fn)
    kwargs = calls[0][1]
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"


def test_subprocess_timeout_is_reported_as_a_failed_ping_not_raised():
    """This runs on a worker thread whose only caller is a rumps timer. An
    escaping exception kills the heartbeat for the rest of the process life.
    """

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=3)

    result = ping_once("8.8.8.8", run_fn=timing_out)
    assert result["ok"] is False
    assert result["rtt_ms"] is None
    assert result["error"]


def test_missing_ping_binary_is_reported_as_a_failed_ping_not_raised():
    def missing(args, **kwargs):
        raise FileNotFoundError(f"no such file: {args[0]}")

    result = ping_once("8.8.8.8", run_fn=missing)
    assert result["ok"] is False
    assert "no such file" in result["error"].lower()


def test_unicode_decode_error_is_reported_not_raised():
    def bad_decode(args, **kwargs):
        raise UnicodeDecodeError("ascii", b"\xe2", 0, 1, "ordinal not in range(128)")

    result = ping_once("8.8.8.8", run_fn=bad_decode)
    assert result["ok"] is False
    assert result["error"]
