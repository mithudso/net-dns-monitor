#!/usr/bin/env python3
"""Helper script to record and transcode an App Store review demonstration video.

Usage:
    .venv/bin/python scripts/appstore/record_demo.py start
    .venv/bin/python scripts/appstore/record_demo.py stop
    .venv/bin/python scripts/appstore/record_demo.py process
"""

from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

REPO = Path(__file__).resolve().parents[2]
DEMO_DIR = REPO / "build" / "appstore" / "demo"
PID_FILE = DEMO_DIR / "screencapture.pid"
RAW_VIDEO = DEMO_DIR / "demo_raw.mov"
FINAL_VIDEO = DEMO_DIR / "app-review-demo.mp4"
START_POLL_SECONDS = 1.0


def process_command(pid: int) -> str | None:
    """The command name of `pid`, or None if no such process (or ps failed)."""
    try:
        done = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return None
    name = done.stdout.strip()
    return name if done.returncode == 0 and name else None


def is_screencapture(pid: int, ps_fn=process_command) -> bool | None:
    """A recycled PID belongs to some other program; never signal it."""
    name = ps_fn(pid)
    if name is None:
        return None
    return bool(name) and name.rsplit("/", 1)[-1] == "screencapture"


def recording_identity(pid: int) -> str | None:
    """Creation time and full command distinguish another capture using this PID."""
    try:
        done = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "lstart=", "-o", "args="],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = done.stdout.strip()
    return value if done.returncode == 0 and value else None


@contextmanager
def lifecycle_lock():
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(DEMO_DIR / ".lifecycle.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Recording lifecycle operation already in progress") from None
        yield
    finally:
        os.close(fd)


class CaptureCleanupUnconfirmed(SystemExit):
    """Keep the reservation when the owned child could not be reaped."""


def start() -> None:
    with lifecycle_lock():
        _start()


def _start() -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    try:
        reservation = PID_FILE.open("x", encoding="utf-8")
    except FileExistsError:
        print(f"Recording already active (PID file exists: {PID_FILE})", file=sys.stderr)
        sys.exit(1)

    try:
        with reservation:
            _start_recording(reservation)
    except BaseException as exc:
        # An empty reservation means capture never started. Once a PID was
        # recorded, keep it until exit is confirmed so the operator can retry.
        if (
            not isinstance(exc, CaptureCleanupUnconfirmed)
            and PID_FILE.exists()
            and not PID_FILE.read_text().strip()
        ):
            PID_FILE.unlink()
        raise


def _start_recording(reservation: TextIO) -> None:
    if RAW_VIDEO.exists() or RAW_VIDEO.is_symlink():
        RAW_VIDEO.unlink()

    print("Starting screen capture with /usr/sbin/screencapture...")
    print("Execute the following flow:")
    print("  1. Launch Net-DNS-Monitor.app (check menu bar icon and Dock badge).")
    print("  2. Click menu bar item -> Open dashboard.")
    print("  3. Click 'Run full diagnosis' in dashboard.")
    print("  4. Click menu bar item -> Toggle mini window.")
    print("  5. Click menu bar item -> Test network alert.")
    print("  6. Click menu bar item -> Allow Claude diagnosis... (show consent dialog).")
    print("  7. Click menu bar item -> Privacy Policy (opens browser).")
    print("\nRun '.venv/bin/python scripts/appstore/record_demo.py stop' when finished.")

    proc = subprocess.Popen(
        ["/usr/sbin/screencapture", "-v", str(RAW_VIDEO)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        reservation.write(str(proc.pid))
        reservation.flush()
    except BaseException:
        # This Popen object establishes ownership even if no PID could be saved.
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            raise CaptureCleanupUnconfirmed(
                "Capture cleanup unconfirmed after PID persistence failure"
            ) from None
        raise
    # screencapture exits at once when Screen Recording permission is missing or
    # the path is unwritable; a PID file alone would claim a recording that
    # never started.
    time.sleep(START_POLL_SECONDS)
    if proc.poll() is not None:
        PID_FILE.unlink(missing_ok=True)
        print(
            f"screencapture exited immediately (code {proc.returncode}); nothing is recording. "
            "Check Screen Recording permission for this terminal.",
            file=sys.stderr,
        )
        sys.exit(1)
    identity = recording_identity(proc.pid)
    if identity is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            raise CaptureCleanupUnconfirmed(
                "Capture identity unavailable; cleanup unconfirmed, PID retained"
            ) from None
        raise SystemExit("Capture identity unavailable; owned capture stopped, PID retained")
    try:
        reservation.seek(0)
        reservation.write(json.dumps({"pid": proc.pid, "identity": identity}))
        reservation.truncate()
        reservation.flush()
    except BaseException:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=10)
        except (OSError, subprocess.SubprocessError):
            raise CaptureCleanupUnconfirmed(
                "Capture cleanup unconfirmed after identity persistence failure"
            ) from None
        raise
    print(f"Recording running in background (PID {proc.pid}).")


def stop() -> None:
    with lifecycle_lock():
        _stop()


def _stop() -> None:
    if not PID_FILE.exists():
        print("No active recording found (no PID file).", file=sys.stderr)
        sys.exit(1)

    pid_str = PID_FILE.read_text().strip()
    try:
        record = json.loads(pid_str)
        pid = int(record["pid"]) if isinstance(record, dict) else int(record)
        identity = is_screencapture(pid) if pid > 0 else False
        if identity is None:
            raise OSError("process identity unknown; preserving PID file")
        if not identity:
            PID_FILE.unlink()
            print(
                f"PID {pid} is not a screencapture process (stale PID file); "
                "nothing was signalled and the PID file was removed.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not isinstance(record, dict) or not record.get("identity"):
            raise OSError("legacy PID has no verified recording identity; preserving PID file")
        current = recording_identity(pid)
        if current is None or current != record["identity"]:
            raise OSError("recording identity changed or unavailable; preserving PID file")
        os.kill(pid, signal.SIGINT)
        print(f"Sent SIGINT to process {pid}. Waiting for file finalize...")
        # screencapture writes the moov atom on exit; a fixed sleep let ffmpeg
        # read a half-written .mov after a long recording. Wait for the exit.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.25)
        else:
            print(
                f"Process {pid} still running after 60s; the .mov may be incomplete.",
                file=sys.stderr,
            )
            sys.exit(1)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Process shutdown unconfirmed ({type(exc).__name__}): {exc}", file=sys.stderr)
        sys.exit(1)

    PID_FILE.unlink()

    if RAW_VIDEO.exists() and RAW_VIDEO.stat().st_size > 0:
        print(f"Raw recording saved: {RAW_VIDEO} ({RAW_VIDEO.stat().st_size // 1024} KB)")
        _process()
    else:
        print("Raw recording file empty or missing.", file=sys.stderr)
        sys.exit(1)


def process() -> None:
    with lifecycle_lock():
        _process()


def _process() -> None:
    if PID_FILE.exists():
        raise SystemExit("Recording may still be active; stop it before transcoding")
    if not RAW_VIDEO.exists():
        print(f"File not found: {RAW_VIDEO}", file=sys.stderr)
        sys.exit(1)

    ffmpeg_bin = (
        "/opt/homebrew/bin/ffmpeg" if Path("/opt/homebrew/bin/ffmpeg").exists() else "ffmpeg"
    )
    cmd = [
        ffmpeg_bin,
        "-y",
        "-i",
        str(RAW_VIDEO),
        "-c:v",
        "libx264",
        "-profile:v",
        "high",
        "-pix_fmt",
        "yuv420p",
        "-crf",
        "22",
        "-preset",
        "fast",
        "-c:a",
        "aac",
        "-b:a",
        "128k",
        str(FINAL_VIDEO),
    ]

    print(f"Transcoding {RAW_VIDEO.name} -> {FINAL_VIDEO.name}...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FFmpeg error: {res.stderr}", file=sys.stderr)
        sys.exit(res.returncode)

    print(
        f"Final App Store Connect video ready: {FINAL_VIDEO} ({FINAL_VIDEO.stat().st_size // 1024} KB)"
    )


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("start", "stop", "process"):
        print(__doc__)
        sys.exit(1)

    action = sys.argv[1]
    if action == "start":
        start()
    elif action == "stop":
        stop()
    elif action == "process":
        process()


if __name__ == "__main__":
    main()
