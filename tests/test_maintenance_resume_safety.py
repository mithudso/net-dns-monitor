"""Process isolation and callback ownership regressions."""

import ast
from pathlib import Path
from types import SimpleNamespace

from netdnsmonitor import router_window


def test_router_save_callback_queues_captured_values():
    # Execute the actual thin selector body without constructing an NSWindow.
    tree = ast.parse(Path(router_window.__file__).read_text())
    node = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "onSaveConfig_"
    )
    namespace = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<router callback>", "exec"), namespace)
    jobs, saved, lines = [], [], []
    values = {"wan_interface": "en3", "lan_interface": "en0"}
    ctrl = router_window.RouterWindowController(spawn=jobs.append, post=lambda fn, *args: fn(*args))
    ctrl._form_values = lambda: dict(values)
    ctrl._save = lambda captured: (saved.append(captured) or True, "saved")
    ctrl.append_log = lines.append
    namespace["onSaveConfig_"](SimpleNamespace(_controller=ctrl), None)
    assert saved == []
    assert len(jobs) == 1
    values["wan_interface"] = "en9"
    jobs.pop()()
    assert saved == [{"wan_interface": "en3", "lan_interface": "en0"}]
    assert lines[-1].endswith("saved")
    assert ctrl._busy is False


def test_fresh_collection_cannot_reach_inherited_credentials_or_native_defaults(tmp_path):
    import os
    import subprocess
    import sys

    script = r"""
import importlib.util
import os
from pathlib import Path
import sys
import objc
from netdnsmonitor import credentials, user_notify

attempts = []
original = objc.loadBundle
def guarded_bundle(name, namespace, *args, **kwargs):
    target = str(name) + str(kwargs)
    if "Security" in target or "UserNotifications" in target:
        attempts.append(target)
        raise RuntimeError("synthetic native boundary denied")
    return original(name, namespace, *args, **kwargs)
objc.loadBundle = guarded_bundle
for name in credentials.NAMES:
    os.environ[name] = "synthetic-parent-sentinel"
spec = importlib.util.spec_from_file_location("fresh_test_setup", Path("tests/conftest.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
assert all(name not in os.environ for name in credentials.NAMES)
store = credentials.CredentialStore(env={})
backend = store._keychain()
assert backend is not None
assert all(store.get(name) is None for name in credentials.NAMES)
assert user_notify.post.__defaults__[0]() is None
assert user_notify.post("synthetic", "", "synthetic") == user_notify.STATUS_NO_BUNDLE
assert attempts == [], attempts
"""
    env = dict(os.environ, HOME=str(tmp_path / "home"), TMPDIR=str(tmp_path))
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
