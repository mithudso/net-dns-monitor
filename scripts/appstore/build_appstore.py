#!/usr/bin/env python3
"""Build, sign and package Net-DNS-Monitor for the Mac App Store.

Two modes:

  adhoc    Build and sign with the ad-hoc identity ("-") and the real sandbox
           entitlements. Needs Xcode, no Apple account. The result runs inside
           the App Sandbox exactly like the store build, so this is how to learn
           what works in the sandbox before paying for a review cycle.
           --with-probe adds the `sandbox_probe` executable (never packaged).

  release  Build, sign with your Apple Distribution identity, embed the
           provisioning profile, and write a signed .pkg ready for
           `xcrun altool --upload-package`.

Everything py2app cannot do is here, in order:

1. Rebuild py2app's launcher stubs against the installed SDK. py2app 0.28 ships
   prebuilt stubs stamped with the macOS 11.3 SDK. Apple does not currently
   publish a macOS SDK floor for uploads, but the launcher is the binary App
   Store Connect inspects first, so it should not be five SDKs behind the
   interpreter it loads.
2. Remove the literal "itms-services" from the bundled urllib/parse.pyc. App
   Review rejected Python apps for that string under Guideline 2.5.2
   (python/cpython#120522). CPython's --with-app-store-compliance applies the
   same one-line change at build time; Homebrew and python.org builds do not.
   The whole bundle, zip members included, is then scanned, and the build stops
   if the string is anywhere else.
3. Refuse any Mach-O that links a library outside the bundle or the OS (a
   Homebrew dylib would work on this Mac and crash on every other one).
4. Set LSMinimumSystemVersion to the highest `minos` of any bundled binary.
   Guessing lower produces an app that installs on a Mac it cannot launch on.
5. Strip extended attributes (uploads must not carry com.apple.quarantine).
6. Sign inside-out: libraries without entitlements, then frameworks, then
   helper executables with the inherit entitlements, then the app. No --deep,
   per Apple's signing guidance.
7. Verify the signature, and in release mode build and check the installer
   package.

Run from the repository root with the project venv that has py2app installed:

  .venv/bin/python scripts/appstore/build_appstore.py adhoc --with-probe
  .venv/bin/python scripts/appstore/build_appstore.py release \\
      --team-id ABCDE12345 --bundle-id com.example.netdnsmonitor \\
      --version 1.0 --build-number 1 \\
      --app-identity "Apple Distribution: Jane Doe (ABCDE12345)" \\
      --installer-identity "3rd Party Mac Developer Installer: Jane Doe (ABCDE12345)" \\
      --profile ~/Downloads/NetDNSMonitor_AppStore.provisionprofile
"""

from __future__ import annotations

import argparse
import os
import plistlib
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Iterable, Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGING = REPO / "packaging" / "appstore"
BUILD_ROOT = REPO / "build" / "appstore"
APP_NAME = "Net-DNS-Monitor"
PROBE_NAME = "sandbox_probe"

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}

ALLOWED_LIBRARY_PREFIXES = (
    "/System/Library/",
    "/usr/lib/",
    "@executable_path/",
    "@loader_path/",
    "@rpath/",
)

FORBIDDEN_STRING = b"itms-services"


# --- pure helpers (tested in tests/test_appstore_build.py) -----------------


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.strip().split("."))


def format_version(parts: Sequence[int]) -> str:
    parts = list(parts)
    while len(parts) < 2:
        parts.append(0)
    return ".".join(str(p) for p in parts)


def parse_minos(vtool_output: str) -> list[tuple[int, ...]]:
    """Every `minos X.Y` in `vtool -show-build` output (one per architecture)."""
    return [version_tuple(m) for m in re.findall(r"^\s*minos\s+([0-9.]+)\s*$", vtool_output, re.M)]


def parse_otool_libraries(otool_output: str) -> list[str]:
    """Install names from `otool -L`, skipping the per-architecture header lines."""
    libraries = []
    for line in otool_output.splitlines():
        if not line.startswith(("\t", " ")):
            continue
        name = line.strip().split(" (compatibility", 1)[0].strip()
        if name:
            libraries.append(name)
    return libraries


def disallowed_libraries(libraries: Iterable[str], own_install_name: str = "") -> list[str]:
    offenders = []
    for name in libraries:
        if name == own_install_name:
            continue
        if not name.startswith(ALLOWED_LIBRARY_PREFIXES):
            offenders.append(name)
    return offenders


def remove_itms_services(source: str) -> str:
    """Apply CPython's app-store-compliance change to urllib/parse.py source.

    Removes the scheme from `uses_netloc` and nothing else. Raises if the
    string is still present afterwards, because a silent partial patch would
    ship exactly the bytes review rejects.
    """
    patched = re.sub(r",\s*'itms-services'", "", source)
    patched = re.sub(r"'itms-services'\s*,\s*", "", patched)
    if "itms-services" in patched:
        raise ValueError("itms-services is still present after patching urllib/parse.py")
    return patched


def entitlements(base: dict, team_id: str | None, bundle_id: str | None) -> dict:
    result = dict(base)
    if team_id:
        if not re.fullmatch(r"[A-Z0-9]{10}", team_id):
            raise ValueError(f"team id {team_id!r} is not a 10-character Apple Team ID")
        if not bundle_id:
            raise ValueError("a release build needs --bundle-id alongside --team-id")
        result["com.apple.application-identifier"] = f"{team_id}.{bundle_id}"
        result["com.apple.developer.team-identifier"] = team_id
    return result


def framework_roots(paths: Iterable[Path]) -> list[Path]:
    """The `X.framework/Versions/N` directories that contain any of `paths`."""
    roots = set()
    for path in paths:
        parts = path.parts
        for i, part in enumerate(parts):
            if part.endswith(".framework") and i + 2 < len(parts) and parts[i + 1] == "Versions":
                roots.add(Path(*parts[: i + 3]))
                break
    return sorted(roots)


def sign_plan(
    app: Path, macho_paths: Iterable[Path], main_executable: Path
) -> list[tuple[Path, str]]:
    """Inside-out signing order: (path, kind) where kind is library, framework,
    helper or app.

    Deepest paths first within each kind, so a nested item is always signed
    before whatever contains it.
    """
    macho_paths = sorted(set(macho_paths))
    frameworks = framework_roots(macho_paths)
    macos_dir = app / "Contents" / "MacOS"
    libraries, helpers = [], []
    for path in macho_paths:
        if path == main_executable:
            continue
        if path.parent == macos_dir:
            helpers.append(path)
        else:
            libraries.append(path)
    by_depth = lambda p: (-len(p.parts), str(p))  # noqa: E731 - sort key
    plan = [(p, "library") for p in sorted(libraries, key=by_depth)]
    plan += [(p, "framework") for p in sorted(frameworks, key=by_depth)]
    plan += [(p, "helper") for p in sorted(helpers, key=by_depth)]
    plan.append((app, "app"))
    return plan


def privacy_policy_problem(url: str, mode: str) -> str | None:
    """Why this URL cannot ship, or None.

    Guideline 5.1.1(i) requires the policy link in App Store Connect and inside
    the app, so a release build without one would be rejected after upload.
    """
    if not url:
        return "a release build needs --privacy-policy-url" if mode == "release" else None
    if not re.fullmatch(r"https://[^\s/$.?#][^\s]*", url):
        return f"privacy policy URL must be an https:// URL, got {url!r}"
    if "<" in url or "PLACEHOLDER" in url.upper():
        return "privacy policy URL still contains a placeholder"
    return None


def probe_identifier(bundle_id: str) -> str:
    return f"{bundle_id}.sandbox-probe"


def embedded_info_plist(identifier: str, app_info: dict) -> dict:
    """The app's Info.plist with the probe's own identity.

    The py2app launcher reads PyRuntimeLocations and friends from whatever
    NSBundle.mainBundle reports, and an embedded __info_plist becomes that
    dictionary for a bare executable. A minimal plist therefore starts the
    sandbox and then fails to find Python.
    """
    info = dict(app_info)
    info.update(
        {
            "CFBundleIdentifier": identifier,
            "CFBundleName": PROBE_NAME,
            "CFBundleExecutable": PROBE_NAME,
        }
    )
    return info


def scan_bytes_for(data: bytes, needle: bytes = FORBIDDEN_STRING) -> bool:
    return needle in data


def upload_commands(pkg: Path) -> list[str]:
    return [
        f'xcrun altool --validate-app "{pkg}" --api-key <KEY_ID> --api-issuer <ISSUER_ID>',
        f'xcrun altool --upload-package "{pkg}" --api-key <KEY_ID> --api-issuer <ISSUER_ID> --wait',
    ]


# --- side-effecting steps ---------------------------------------------------


def run(cmd: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=True, **kwargs)


def capture(cmd: Sequence[str]) -> str:
    return subprocess.run([str(c) for c in cmd], check=True, capture_output=True, text=True).stdout


def is_macho(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) in MACHO_MAGICS
    except OSError:
        return False


def macho_files(app: Path) -> list[Path]:
    found = []
    for root, _dirs, files in os.walk(app):
        for name in files:
            path = Path(root) / name
            if not path.is_symlink() and path.is_file() and is_macho(path):
                found.append(path)
    return found


def py2app_build(args, dist: Path, bdist: Path, icon: Path | None) -> Path:
    env = dict(os.environ)
    env.update(
        {
            "NETDNS_BUILD": "appstore",
            "NETDNS_BUNDLE_ID": args.bundle_id,
            "NETDNS_VERSION": args.version,
            "NETDNS_BUILD_NUMBER": args.build_number,
            "NETDNS_COPYRIGHT": args.copyright,
            "NETDNS_WITH_PROBE": "1" if getattr(args, "with_probe", False) else "0",
            "NETDNS_PRIVACY_POLICY_URL": args.privacy_policy_url or "",
        }
    )
    if icon is not None:
        env["NETDNS_ICON"] = str(icon)
    run(
        [sys.executable, "setup.py", "py2app", "--dist-dir", dist, "--bdist-base", bdist],
        cwd=REPO,
        env=env,
    )
    app = dist / f"{APP_NAME}.app"
    if not app.is_dir():
        raise SystemExit(f"py2app did not produce {app}")
    return app


def rebuild_launchers(app: Path, min_version: str) -> None:
    import py2app.apptemplate

    source = Path(py2app.apptemplate.__file__).parent / "src" / "main.c"
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    macos = app / "Contents" / "MacOS"
    main = macos / info["CFBundleExecutable"]
    python_binary = next(
        (app / "Contents" / "Frameworks").glob("Python.framework/Versions/*/Python")
    )
    archs = capture(["lipo", "-archs", python_binary]).split()
    arch_flags = [flag for arch in archs for flag in ("-arch", arch)]
    targets = [(main, [], None)]
    probe = macos / PROBE_NAME
    if probe.exists():
        targets.append(
            (probe, ["-DPY2APP_SECONDARY"], probe_identifier(info["CFBundleIdentifier"]))
        )
    for target, defines, embedded_identifier in targets:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "stub"
            if embedded_identifier:
                # A sandboxed executable outside the main bundle slot has no
                # Info.plist of its own, and secinit kills it at launch:
                # "Info.plist from code signature information has no value for
                # kCFBundleIdentifierKey". Linking one into __TEXT,__info_plist
                # gives the signature a bundle identifier to build a container
                # from. Only the probe needs this; `python` uses `inherit`.
                embedded = Path(tmp) / "Info.plist"
                embedded.write_bytes(plistlib.dumps(embedded_info_plist(embedded_identifier, info)))
                defines = [*defines, "-sectcreate", "__TEXT", "__info_plist", str(embedded)]
            run(
                [
                    "xcrun",
                    "--sdk",
                    "macosx",
                    "clang",
                    "-Os",
                    *arch_flags,
                    f"-mmacosx-version-min={min_version}",
                    "-w",
                    *defines,
                    "-o",
                    out,
                    source,
                    "-framework",
                    "Cocoa",
                ],
                env={**os.environ, "MACOSX_DEPLOYMENT_TARGET": min_version},
            )
            mode = target.stat().st_mode
            shutil.copyfile(out, target)
            os.chmod(target, mode)


def patch_stdlib_zip(app: Path) -> list[str]:
    """Replace urllib/parse.pyc in the bundled stdlib zip; return remaining hits."""
    zips = list((app / "Contents" / "Resources" / "lib").glob("python3*.zip"))
    if len(zips) != 1:
        raise SystemExit(f"expected one bundled stdlib zip, found {zips}")
    stdlib_zip = zips[0]
    bundled = stdlib_zip.stem.replace("python", "")
    running = f"{sys.version_info.major}{sys.version_info.minor}"
    if bundled != running:
        raise SystemExit(
            f"bundled Python is {bundled} but this build runs {running}; the patched "
            "bytecode would not load. Run the build with the same interpreter py2app bundled."
        )
    import sysconfig

    source_path = Path(sysconfig.get_paths()["stdlib"]) / "urllib" / "parse.py"
    patched_source = remove_itms_services(source_path.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        src = tmp / "parse.py"
        src.write_text(patched_source, encoding="utf-8")
        pyc = tmp / "parse.pyc"
        py_compile.compile(str(src), cfile=str(pyc), dfile="urllib/parse.py", doraise=True)
        rebuilt = tmp / stdlib_zip.name
        with zipfile.ZipFile(stdlib_zip) as old, zipfile.ZipFile(rebuilt, "w") as new:
            for item in old.infolist():
                data = pyc.read_bytes() if item.filename == "urllib/parse.pyc" else old.read(item)
                new.writestr(item, data)
        shutil.copyfile(rebuilt, stdlib_zip)
    return find_forbidden_string(app)


def find_forbidden_string(app: Path) -> list[str]:
    hits = []
    for root, _dirs, files in os.walk(app):
        for name in files:
            path = Path(root) / name
            if path.is_symlink():
                continue
            if path.suffix == ".zip":
                with zipfile.ZipFile(path) as archive:
                    hits += [
                        f"{path}!{member}"
                        for member in archive.namelist()
                        if scan_bytes_for(archive.read(member))
                    ]
            elif scan_bytes_for(path.read_bytes()):
                hits.append(str(path))
    return hits


def check_linkage(app: Path, binaries: Iterable[Path]) -> list[str]:
    problems = []
    for binary in binaries:
        libraries = parse_otool_libraries(capture(["otool", "-L", binary]))
        own = ""
        id_output = capture(["otool", "-D", binary]).splitlines()
        if len(id_output) > 1:
            own = id_output[-1].strip()
        for name in disallowed_libraries(libraries, own):
            problems.append(f"{binary.relative_to(app)} links {name}")
    return problems


def highest_minos(binaries: Iterable[Path]) -> tuple[int, ...]:
    best: tuple[int, ...] = (11, 0)
    for binary in binaries:
        for minos in parse_minos(capture(["vtool", "-show-build", binary])):
            best = max(best, minos)
    return best


def set_info_plist(app: Path, updates: dict) -> None:
    path = app / "Contents" / "Info.plist"
    info = plistlib.loads(path.read_bytes())
    info.update(updates)
    path.write_bytes(plistlib.dumps(info))


def profile_application_identifier(profile: Path) -> str:
    decoded = subprocess.run(
        ["security", "cms", "-D", "-i", str(profile)], check=True, capture_output=True
    ).stdout
    data = plistlib.loads(decoded)
    ents = data.get("Entitlements", {})
    return ents.get("com.apple.application-identifier") or ents.get("application-identifier", "")


def codesign(
    path: Path, identity: str, entitlements_file: Path | None, identifier: str | None = None
) -> None:
    cmd = ["codesign", "--force", "--sign", identity]
    if identifier:
        cmd += ["--identifier", identifier]
    if entitlements_file is not None:
        cmd += ["--entitlements", entitlements_file]
    run([*cmd, path])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("adhoc", "release"):
        p = sub.add_parser(name)
        p.add_argument("--bundle-id", default="com.net-dns-monitor.app")
        p.add_argument("--version", default="1.0")
        p.add_argument("--build-number", default="1")
        p.add_argument("--copyright", default="")
        p.add_argument("--declare-exempt-encryption", action="store_true")
        p.add_argument(
            "--privacy-policy-url",
            default="",
            help="public https URL of the hosted privacy policy (required for release)",
        )
        if name == "adhoc":
            p.add_argument("--with-probe", action="store_true")
        else:
            p.add_argument("--team-id", required=True)
            p.add_argument("--app-identity", required=True)
            p.add_argument("--installer-identity", required=True)
            p.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args(argv)

    if sys.platform != "darwin":
        raise SystemExit("App Store builds need macOS and Xcode")
    problem = privacy_policy_problem(args.privacy_policy_url, args.mode)
    if problem:
        raise SystemExit(problem)

    out = BUILD_ROOT / args.mode
    if out.exists():
        shutil.rmtree(out)
    dist, bdist = out / "dist", out / "py2app"

    icon = out / "AppIcon.icns"
    out.mkdir(parents=True)
    run([sys.executable, REPO / "scripts" / "appstore" / "make_icon.py", icon])

    app = py2app_build(args, dist, bdist, icon)
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    main_executable = app / "Contents" / "MacOS" / info["CFBundleExecutable"]

    if args.mode == "release" and (app / "Contents" / "MacOS" / PROBE_NAME).exists():
        raise SystemExit("refusing to package a bundle that contains the sandbox probe")

    min_os = format_version(highest_minos(macho_files(app)))
    rebuild_launchers(app, min_os)

    remaining = patch_stdlib_zip(app)
    if remaining:
        raise SystemExit("itms-services is still present in:\n  " + "\n  ".join(remaining))

    binaries = macho_files(app)
    problems = check_linkage(app, binaries)
    if problems:
        raise SystemExit("libraries outside the bundle or the OS:\n  " + "\n  ".join(problems))

    min_os = format_version(highest_minos(binaries))
    plist_updates = {"LSMinimumSystemVersion": min_os}
    if args.declare_exempt_encryption:
        plist_updates["ITSAppUsesNonExemptEncryption"] = False
    set_info_plist(app, plist_updates)

    base = plistlib.loads((PACKAGING / "entitlements.plist").read_bytes())
    team_id = getattr(args, "team_id", None)
    app_entitlements = out / "app.entitlements"
    app_entitlements.write_bytes(plistlib.dumps(entitlements(base, team_id, args.bundle_id)))
    helper_entitlements = PACKAGING / "entitlements-helper.plist"

    if args.mode == "release":
        expected = f"{team_id}.{args.bundle_id}"
        found = profile_application_identifier(args.profile)
        if found != expected:
            raise SystemExit(f"provisioning profile is for {found!r}, this build is {expected!r}")
        shutil.copyfile(args.profile, app / "Contents" / "embedded.provisionprofile")
        identity = args.app_identity
    else:
        identity = "-"

    run(["xattr", "-cr", app])

    for path, kind in sign_plan(app, binaries, main_executable):
        if kind == "helper" and path.name == PROBE_NAME:
            codesign(path, identity, app_entitlements, probe_identifier(args.bundle_id))
        elif kind == "helper":
            codesign(path, identity, helper_entitlements)
        elif kind == "app":
            codesign(path, identity, app_entitlements)
        else:
            codesign(path, identity, None)

    run(["codesign", "--verify", "--strict", "--deep", "--verbose=2", app])
    run(["codesign", "--display", "--entitlements", "-", "--xml", app])

    print(f"\nApp: {app}\nMinimum macOS: {min_os}")
    if args.mode == "release":
        pkg = out / f"{APP_NAME}-{args.version}-{args.build_number}.pkg"
        run(
            [
                "productbuild",
                "--component",
                app,
                "/Applications",
                "--sign",
                args.installer_identity,
                pkg,
            ]
        )
        run(["pkgutil", "--check-signature", pkg])
        print(f"Package: {pkg}\n\nNext:")
        for line in upload_commands(pkg):
            print(f"  {line}")
    else:
        print("\nAd-hoc build: sandboxed like the store build, not uploadable.")
        if getattr(args, "with_probe", False):
            print(f"Probe: {app / 'Contents' / 'MacOS' / PROBE_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
