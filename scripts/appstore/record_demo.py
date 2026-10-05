#!/usr/bin/env python3
"""Helper script to record and transcode an App Store review demonstration video.

Usage:
    .venv/bin/python scripts/appstore/record_demo.py start
    .venv/bin/python scripts/appstore/record_demo.py stop
    .venv/bin/python scripts/appstore/record_demo.py process
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

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


def is_screencapture(pid: int, ps_fn=process_command) -> bool:
    """A recycled PID belongs to some other program; never signal it."""
    name = ps_fn(pid)
    return bool(name) and name.rsplit("/", 1)[-1] == "screencapture"


def start() -> None:
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    if PID_FILE.exists():
        print(f"Recording already active (PID file exists: {PID_FILE})", file=sys.stderr)
        sys.exit(1)

    if RAW_VIDEO.exists():
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
    PID_FILE.write_text(str(proc.pid))
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
    print(f"Recording running in background (PID {proc.pid}).")


def stop() -> None:
    if not PID_FILE.exists():
        print("No active recording found (no PID file).", file=sys.stderr)
        sys.exit(1)

    pid_str = PID_FILE.read_text().strip()
    PID_FILE.unlink()

    try:
        pid = int(pid_str)
        if not is_screencapture(pid):
            print(
                f"PID {pid} is not a screencapture process (stale PID file); "
                "nothing was signalled and the PID file was removed.",
                file=sys.stderr,
            )
            sys.exit(1)
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
    except (OSError, ValueError) as e:
        print(f"Process {pid_str} termination note: {e}")

    if RAW_VIDEO.exists() and RAW_VIDEO.stat().st_size > 0:
        print(f"Raw recording saved: {RAW_VIDEO} ({RAW_VIDEO.stat().st_size // 1024} KB)")
        process()
    else:
        print("Raw recording file empty or missing.", file=sys.stderr)
        sys.exit(1)


def process() -> None:
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
