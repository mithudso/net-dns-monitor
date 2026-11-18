#!/usr/bin/env python3
"""Assemble the two direct-download source packages for local macOS setup."""

import argparse
import ast
import hashlib
import stat
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]

RELEASE_FILES = (
    "LICENSE",
    "HOWTO.md",
    "constraints.txt",
    "requirements.txt",
    "setup.py",
    "scripts/install.sh",
    "scripts/net-dns-monitor-service",
    "scripts/start.sh",
    "docs/INSTALLATION.md",
    "docs/PRIVACY_POLICY.md",
)
EDITION_FILE = "netdnsmonitor/_direct_edition.py"
INSTALL = """# Net DNS Monitor {name} {version}

This download contains the source package. The setup script builds the macOS
app on your Mac and launches it when the build is ready.

Requirements: Apple silicon Mac, Python 3.13, and internet access for the
first setup. Get the macOS installer from https://www.python.org/downloads/macos/
or use Homebrew's `python@3.13`.

1. Unzip the download and open Terminal.
2. Type `cd ` followed by a space, drag the extracted folder into Terminal,
   then press Return.
3. Run `PYTHON_BIN=python3.13 /bin/bash ./scripts/start.sh`. If Python 3.13
   isn't on your PATH after installation, open a fresh Terminal window.
4. Open **Net/DNS** in the menu bar and choose **Open dashboard**. The app
   starts collecting DNS and connection evidence while it runs.

{edition_description}

To reopen the app, use the same setup command from this folder. The first run
builds the app and installs pinned Python dependencies into the folder. Later
runs reuse the build if the inputs match. If you already run another edition,
quit it before starting this one. Existing monitoring settings and saved
reports are stored separately from the extracted folder.

For product help, visit https://netdnsmonitor.com or see HOWTO.md in this
download. The source package includes the MIT license in LICENSE.
"""
EDITIONS = {
    "Free": """Free runs read-only diagnostics and keeps automatic monitoring,
local incident reports and available unified-log evidence. Network repairs,
system network changes and the arbitrary shell console require Premium.""",
    "Premium": """Premium can attempt built-in repairs when it diagnoses a fault.
Some repairs require elevated permissions. Backup failover requires configured
network services and is off by default. Read HOWTO.md before enabling failover
or granting elevated permissions.""",
}


def source_paths() -> list[str]:
    # Git supplies the allowlist, so local logs, bytecode, settings and secrets
    # beside the app source never enter the customer archive.
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "netdnsmonitor/"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode()
    files = set(tracked.split("\0")) - {"", EDITION_FILE}
    return sorted({*RELEASE_FILES, *files})


def read_source(path: str) -> tuple[bytes, int]:
    source = ROOT / path
    if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(ROOT):
        raise ValueError(f"Release input must be a regular file in the checkout: {path}")
    mode = 0o755 if source.stat().st_mode & stat.S_IXUSR else 0o644
    return source.read_bytes(), mode


def release_version(setup_source: bytes) -> str:
    for node in ast.parse(setup_source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "PLIST" for target in node.targets
        ):
            return ast.literal_eval(node.value)["CFBundleShortVersionString"]
    raise ValueError("setup.py has no direct-build PLIST")


def write_entry(archive: ZipFile, path: str, data: bytes, mode: int = 0o644) -> None:
    info = ZipInfo(path)
    info.create_system = 3  # Preserve the launch script's executable bit on macOS.
    info.external_attr = (stat.S_IFREG | mode) << 16
    archive.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)


def build(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    inputs = {path: read_source(path) for path in source_paths()}
    version = release_version(inputs["setup.py"][0])
    # A pristine buyer should receive the documented sample instead of any
    # live configuration from the machine that built the download.
    inputs["config.yaml"] = read_source("config.example.yaml")
    for name, edition_description in EDITIONS.items():
        stem = f"Net-DNS-Monitor-{name}-{version}"
        path = output / f"{stem}.zip"
        edition = "free" if name == "Free" else "direct"
        with ZipFile(path, "x") as archive:
            for filename, (data, mode) in inputs.items():
                write_entry(archive, f"{stem}/{filename}", data, mode)
            write_entry(
                archive,
                f"{stem}/{EDITION_FILE}",
                f"EDITION = {edition!r}\n".encode(),
            )
            write_entry(
                archive,
                f"{stem}/START-HERE.md",
                INSTALL.format(
                    name=name, version=version, edition_description=edition_description
                ).encode(),
            )
        print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    build(parser.parse_args().output_directory.resolve())
