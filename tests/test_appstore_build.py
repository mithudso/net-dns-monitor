"""The App Store build script's decisions, tested without building anything.

build_appstore.py lives under scripts/ (it must never be bundled into the app),
so it is loaded by path. Only the pure helpers are exercised here; the steps
that call py2app, clang, codesign and productbuild are exercised by running the
ad-hoc build, which docs/APP_STORE_SUBMISSION.md describes.
"""

import ast
import importlib.util
import plistlib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_appstore", ROOT / "scripts" / "appstore" / "build_appstore.py"
)
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def test_parse_minos_reads_every_architecture():
    output = (
        "Foo (architecture x86_64):\nLoad command 9\n      cmd LC_BUILD_VERSION\n"
        "  platform MACOS\n    minos 10.13\n      sdk 14.0\n"
        "Foo (architecture arm64):\n  platform MACOS\n    minos 11.0\n      sdk 26.5\n"
    )
    assert build.parse_minos(output) == [(10, 13), (11, 0)]


def test_format_version_always_has_a_minor_component():
    assert build.format_version((26,)) == "26.0"
    assert build.format_version((10, 15, 7)) == "10.15.7"


def test_otool_parsing_skips_architecture_headers():
    output = (
        "/x/Python (architecture arm64):\n"
        "\t@rpath/Python.framework/Versions/3.13/Python (compatibility version 3.13.0, current 3.13.0)\n"
        "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1356.0.0)\n"
        "/x/Python (architecture x86_64):\n"
        "\t/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib (compatibility version 3.0.0)\n"
    )
    assert build.parse_otool_libraries(output) == [
        "@rpath/Python.framework/Versions/3.13/Python",
        "/usr/lib/libSystem.B.dylib",
        "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
    ]


def test_a_homebrew_library_is_refused_and_system_and_bundle_paths_are_not():
    libraries = [
        "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa",
        "/usr/lib/libz.1.dylib",
        "@executable_path/../Frameworks/libssl.3.dylib",
        "@loader_path/libcrypto.3.dylib",
        "/opt/homebrew/lib/libffi.8.dylib",
        "/usr/local/lib/libintl.8.dylib",
    ]
    assert build.disallowed_libraries(libraries) == [
        "/opt/homebrew/lib/libffi.8.dylib",
        "/usr/local/lib/libintl.8.dylib",
    ]


def test_a_library_is_allowed_to_name_its_own_install_path():
    own = "/opt/homebrew/opt/python@3.13/Frameworks/Python.framework/Versions/3.13/Python"
    assert build.disallowed_libraries([own], own_install_name=own) == []


def test_itms_services_is_removed_from_uses_netloc_and_nothing_else():
    source = (
        "uses_netloc = ['', 'ftp', 'http', 'gopher', 'nntp', 'telnet',\n"
        "               'imap', 'wais', 'file', 'mms', 'https', 'shttp',\n"
        "               'snews', 'prospero', 'rtsp', 'rtsps', 'rtspu', 'rsync',\n"
        "               'svn', 'svn+ssh', 'sftp', 'nfs', 'git', 'git+ssh',\n"
        "               'ws', 'wss', 'itms-services']\n"
        "uses_query = ['', 'http']\n"
    )
    patched = build.remove_itms_services(source)
    assert "itms-services" not in patched
    assert "'ws', 'wss']" in patched
    assert "uses_query = ['', 'http']" in patched


def test_the_real_stdlib_source_patches_cleanly():
    import sysconfig

    source = (Path(sysconfig.get_paths()["stdlib"]) / "urllib" / "parse.py").read_text()
    patched = build.remove_itms_services(source)
    assert "itms-services" not in patched
    compile(patched, "urllib/parse.py", "exec")


def test_a_patch_that_leaves_the_string_behind_is_an_error():
    with pytest.raises(ValueError):
        build.remove_itms_services("# see itms-services in a comment\n")


def test_release_entitlements_carry_the_team_and_application_identifier():
    base = {"com.apple.security.app-sandbox": True}
    result = build.entitlements(base, "ABCDE12345", "com.example.ndm")
    assert result["com.apple.application-identifier"] == "ABCDE12345.com.example.ndm"
    assert result["com.apple.developer.team-identifier"] == "ABCDE12345"
    assert result["com.apple.security.app-sandbox"] is True
    assert base == {"com.apple.security.app-sandbox": True}


def test_adhoc_entitlements_claim_no_team():
    assert build.entitlements({"a": True}, None, "com.example.ndm") == {"a": True}


@pytest.mark.parametrize("team", ["abcde12345", "ABC", "ABCDE123456", "ABCDE-2345"])
def test_a_malformed_team_id_is_refused(team):
    with pytest.raises(ValueError):
        build.entitlements({}, team, "com.example.ndm")


def test_the_shipped_entitlements_are_exactly_sandbox_and_network():
    base = plistlib.loads((ROOT / "packaging" / "appstore" / "entitlements.plist").read_bytes())
    assert base == {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.client": True,
        "com.apple.security.network.server": True,
    }


def test_the_helper_entitlements_are_exactly_sandbox_and_inherit():
    helper = plistlib.loads(
        (ROOT / "packaging" / "appstore" / "entitlements-helper.plist").read_bytes()
    )
    assert helper == {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True}


def test_signing_goes_inside_out_and_ends_with_the_app():
    app = Path("/b/Net-DNS-Monitor.app")
    contents = app / "Contents"
    main = contents / "MacOS" / "Net-DNS-Monitor"
    python = contents / "MacOS" / "python"
    framework_binary = contents / "Frameworks" / "Python.framework" / "Versions" / "3.13" / "Python"
    dylib = contents / "Frameworks" / "libssl.3.dylib"
    extension = contents / "Resources" / "lib" / "python3.13" / "lib-dynload" / "_ssl.so"
    plan = build.sign_plan(app, [main, python, framework_binary, dylib, extension], main)
    kinds = [kind for _path, kind in plan]
    paths = [path for path, _kind in plan]

    assert plan[-1] == (app, "app")
    assert (contents / "Frameworks" / "Python.framework" / "Versions" / "3.13", "framework") in plan
    assert (python, "helper") in plan
    assert main not in paths
    last_library = max(i for i, k in enumerate(kinds) if k == "library")
    first_framework = kinds.index("framework")
    first_helper = kinds.index("helper")
    assert last_library < first_framework < first_helper


def test_is_macho_recognises_thin_and_fat_binaries(tmp_path):
    thin = tmp_path / "thin"
    thin.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 12)
    fat = tmp_path / "fat"
    fat.write_bytes(b"\xca\xfe\xba\xbe" + b"\0" * 12)
    text = tmp_path / "text.py"
    text.write_text("print('hi')\n")
    assert build.is_macho(thin)
    assert build.is_macho(fat)
    assert not build.is_macho(text)
    assert not build.is_macho(tmp_path / "missing")


def test_the_forbidden_string_is_found_inside_zip_members(tmp_path):
    app = tmp_path / "X.app"
    lib = app / "Contents" / "Resources" / "lib"
    lib.mkdir(parents=True)
    with zipfile.ZipFile(lib / "python313.zip", "w") as archive:
        archive.writestr("urllib/parse.pyc", b"....itms-services....")
        archive.writestr("os.pyc", b"clean")
    (app / "Contents" / "Resources" / "clean.txt").write_text("nothing here")
    hits = build.find_forbidden_string(app)
    assert hits == [f"{lib / 'python313.zip'}!urllib/parse.pyc"]


def test_upload_commands_use_api_key_authentication():
    commands = build.upload_commands(Path("/out/App.pkg"))
    assert commands[0].startswith('xcrun altool --validate-app "/out/App.pkg"')
    assert "--upload-package" in commands[1]
    assert "--wait" in commands[1]
    assert all("--api-key" in c and "--api-issuer" in c for c in commands)


def test_the_probe_keeps_the_app_runtime_keys_under_its_own_identity():
    app_info = {
        "CFBundleIdentifier": "com.example.ndm",
        "CFBundleExecutable": "Net-DNS-Monitor",
        "PyRuntimeLocations": [
            "@executable_path/../Frameworks/Python.framework/Versions/3.13/Python"
        ],
    }
    info = build.embedded_info_plist(build.probe_identifier("com.example.ndm"), app_info)
    assert info["CFBundleIdentifier"] == "com.example.ndm.sandbox-probe"
    assert info["CFBundleExecutable"] == build.PROBE_NAME
    assert info["PyRuntimeLocations"] == app_info["PyRuntimeLocations"]
    assert app_info["CFBundleIdentifier"] == "com.example.ndm"


def test_a_release_build_requires_a_real_https_privacy_policy_url():
    assert build.privacy_policy_problem("", "release")
    assert build.privacy_policy_problem("http://example.com/privacy", "release")
    assert build.privacy_policy_problem("https://<your-site>/privacy", "release")
    assert build.privacy_policy_problem("https://example.com/PLACEHOLDER", "release")
    assert build.privacy_policy_problem("https://example.com/privacy", "release") is None


def test_an_adhoc_build_does_not_need_a_privacy_policy_url():
    assert build.privacy_policy_problem("", "adhoc") is None


OTOOL_L_SAMPLE = """Load command 12
          cmd LC_RPATH
      cmdsize 32
         path /opt/homebrew/lib (offset 12)
Load command 13
          cmd LC_RPATH
      cmdsize 40
         path @loader_path/../Frameworks (offset 12)
Load command 14
          cmd LC_LOAD_DYLIB
      cmdsize 56
         name /usr/lib/libSystem.B.dylib (offset 24)
"""


def test_rpaths_are_parsed_in_load_command_order():
    assert build.parse_rpaths(OTOOL_L_SAMPLE) == ["/opt/homebrew/lib", "@loader_path/../Frameworks"]


def test_an_absolute_rpath_is_external_and_a_bundle_relative_one_is_not():
    rpaths = ["/opt/homebrew/lib", "@loader_path/../lib", "@executable_path/../Frameworks"]
    assert build.external_rpaths(rpaths) == ["/opt/homebrew/lib"]


def test_an_rpath_library_resolves_only_to_a_file_inside_the_bundle(tmp_path):
    app = tmp_path / "X.app"
    binary = app / "Contents" / "Resources" / "lib" / "_ssl.so"
    lib = app / "Contents" / "Frameworks" / "libssl.3.dylib"
    lib.parent.mkdir(parents=True)
    lib.write_bytes(b"x")
    binary.parent.mkdir(parents=True)
    rpaths = ["@loader_path/../../Frameworks"]
    found = build.resolve_rpath_library(binary, "@rpath/libssl.3.dylib", rpaths, app)
    assert found == lib
    assert build.resolve_rpath_library(binary, "@rpath/libffi.8.dylib", rpaths, app) is None
    # An absolute rpath never counts, even if the file exists on this Mac.
    outside = ["/opt/homebrew/lib"]
    assert build.resolve_rpath_library(binary, "@rpath/libssl.3.dylib", outside, app) is None


def test_an_rpath_that_climbs_out_of_the_bundle_does_not_resolve(tmp_path):
    app = tmp_path / "X.app"
    binary = app / "Contents" / "MacOS" / "python"
    (tmp_path / "libevil.dylib").write_bytes(b"x")
    binary.parent.mkdir(parents=True)
    rpaths = ["@loader_path/../../.."]
    assert build.resolve_rpath_library(binary, "@rpath/libevil.dylib", rpaths, app) is None


def test_missing_plist_keys_reports_absent_and_empty_values_in_order():
    info = {
        "CFBundleIdentifier": "com.example.app",
        "CFBundleShortVersionString": "",
        "CFBundleVersion": "1",
        "LSMinimumSystemVersion": "26.0",
    }
    assert build.missing_plist_keys(info) == [
        "CFBundleShortVersionString",
        "LSApplicationCategoryType",
        "NSLocalNetworkUsageDescription",
    ]
    assert build.missing_plist_keys(info, required=("CFBundleVersion",)) == []


def _setup_py_plist() -> dict:
    """The PLIST literal from setup.py, without importing it (import runs setup())."""
    tree = ast.parse((ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            getattr(target, "id", None) == "PLIST" for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("setup.py defines no PLIST literal")


def test_setup_py_declares_local_network_use_for_both_builds():
    # macOS 15+ shows this string in the local-network permission prompt that
    # the peer broadcast and the gateway probe trigger; it belongs to every
    # build, not only the store one, so it lives in the base PLIST.
    plist = _setup_py_plist()
    text = plist["NSLocalNetworkUsageDescription"]
    assert text.strip() and "local network" in text.lower()
    # The keys the App Store build adds from the build script's arguments.
    store = {
        **plist,
        "LSApplicationCategoryType": "public.app-category.utilities",
        "LSMinimumSystemVersion": "26.0",
    }
    assert build.missing_plist_keys(store) == []


def _icns(*elements: tuple[bytes, bytes]) -> bytes:
    body = b"".join(
        kind + (len(payload) + 8).to_bytes(4, "big") + payload for kind, payload in elements
    )
    return b"icns" + (len(body) + 8).to_bytes(4, "big") + body


def test_icns_types_walks_the_container():
    data = _icns((b"TOC ", b"\0" * 16), (b"ic09", b"png1"), (b"ic10", b"png2"))
    assert build.icns_types(data) == {"TOC ", "ic09", "ic10"}


def test_icns_types_rejects_non_icns_and_corrupt_elements():
    with pytest.raises(ValueError):
        build.icns_types(b"PNG\r\n\x1a\n\0")
    with pytest.raises(ValueError):
        build.icns_types(b"icns" + (16).to_bytes(4, "big") + b"ic09" + (2).to_bytes(4, "big"))


def test_icon_problem_names_the_missing_512_sizes():
    only_small = _icns((b"ic07", b"x"), (b"ic08", b"x"))
    problem = build.icon_problem(Path("/x/AppIcon.icns"), read=lambda p: only_small)
    assert problem is not None and "ic09, ic10" in problem
    complete = _icns((b"ic09", b"x"), (b"ic10", b"x"))
    assert build.icon_problem(Path("/x/AppIcon.icns"), read=lambda p: complete) is None


def test_icon_problem_requires_icns_suffix_and_readable_file():
    assert "must be an .icns" in build.icon_problem(Path("/x/icon.png"), read=lambda p: b"")

    def missing(_p):
        raise FileNotFoundError("no such file")

    assert "no such file" in build.icon_problem(Path("/x/AppIcon.icns"), read=missing)


# --- release preflight, timestamp, failure reporting -------------------------


def _args(**kw):
    import argparse

    base = {"bundle_id": "com.example.app", "version": "1.2", "build_number": "7"}
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.mark.parametrize("value", ["1", "1.0", "1.2.3"])
def test_version_problem_accepts_store_versions(value):
    assert build.version_problem(value, "--version") is None


@pytest.mark.parametrize("value", ["", "1.2.3.4", "v1", "1.x", "1..2", "1.0-beta"])
def test_version_problem_rejects_others(value):
    assert "--version" in build.version_problem(value, "--version")


def test_release_requires_explicit_bundle_id():
    assert "--bundle-id" in build.release_input_problem(_args(bundle_id=None))
    assert build.release_input_problem(_args()) is None


def test_release_rejects_bad_build_number():
    assert "--build-number" in build.release_input_problem(_args(build_number="1.2.3.4"))


def test_profile_mismatch_is_reported():
    assert build.profile_problem("ABCDE12345.com.x", "ABCDE12345", "com.x") is None
    message = build.profile_problem("ABCDE12345.com.y", "ABCDE12345", "com.x")
    assert "com.y" in message and "ABCDE12345.com.x" in message


def test_release_checks_run_before_the_build(monkeypatch, tmp_path):
    monkeypatch.setattr(build.sys, "platform", "darwin")
    monkeypatch.setattr(build, "BUILD_ROOT", tmp_path)
    monkeypatch.setattr(build, "profile_application_identifier", lambda p: "WRONG.id")
    built = []
    monkeypatch.setattr(build, "py2app_build", lambda *a, **k: built.append(1))
    monkeypatch.setattr(build, "run", lambda *a, **k: built.append("run"))
    argv = [
        "release", "--bundle-id", "com.x", "--team-id", "ABCDE12345",
        "--app-identity", "A", "--installer-identity", "I", "--profile", "p",
        "--privacy-policy-url", "https://example.com/p",
    ]  # fmt: skip
    with pytest.raises(SystemExit, match="provisioning profile"):
        build.main(argv)
    assert built == []


@pytest.mark.parametrize(
    ("kind", "name", "expected"),
    [
        ("library", "x.dylib", (None, None)),
        ("framework", "X.framework", (None, None)),
        ("helper", "helper", ("H", None)),
        ("helper", build.PROBE_NAME, ("A", build.probe_identifier("com.x"))),
        ("app", "App.app", ("A", None)),
    ],
)
def test_codesign_args_dispatch(kind, name, expected):
    got = build.codesign_args(kind, Path(name), "com.x", Path("A"), Path("H"))
    want = (Path(expected[0]) if expected[0] else None, expected[1])
    assert got == want


def test_codesign_adds_timestamp_only_for_real_identity(monkeypatch):
    seen = []
    monkeypatch.setattr(build, "run", lambda cmd, **k: seen.append(list(cmd)))
    build.codesign(Path("/x"), "Developer ID", None)
    build.codesign(Path("/x"), "-", None)
    assert "--timestamp" in seen[0]
    assert "--timestamp" not in seen[1]


def test_capture_failure_carries_tool_stderr():
    import sys

    cmd = [sys.executable, "-c", "import sys; sys.stderr.write('boom text'); sys.exit(3)"]
    with pytest.raises(SystemExit, match="boom text"):
        build.capture(cmd)
