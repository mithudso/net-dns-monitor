"""Where the app's three credentials come from.

The direct-download build reads ANTHROPIC_API_KEY, SLACK_WEBHOOK_URL and
SMTP_PASSWORD from the environment, because scripts/start.sh launches it from a
shell that exports them. A Mac App Store build is launched by LaunchServices
inside the App Sandbox and never sees that shell, so the same lookup finds
nothing and every credentialed feature quietly turns off. The Keychain is the
place a sandboxed app is allowed to keep a secret.

Lookup order is environment first, then Keychain. Environment first keeps the
direct build exactly as it was: someone who exports a variable gets that value,
and a stale Keychain entry never overrides what they just set in a shell.

No secret leaves this module except through `get`. Errors carry the OSStatus
number only, and `describe` reports where a value was found, never the value,
so a status pane can show "set (Keychain)" without holding the secret.

The Security framework is reached through PyObjC's generic bundle loader rather
than pyobjc-framework-Security, so the four-runtime-dependency rule in
requirements.txt still holds. The loader import happens inside
`make_keychain_backend`, which keeps this module importable in tests and on a
machine without PyObjC.
"""

import os
from collections.abc import Mapping
from typing import Callable, Optional, Protocol

NAMES = ("ANTHROPIC_API_KEY", "SLACK_WEBHOOK_URL", "SMTP_PASSWORD")

# One Keychain service for the app; the credential name is the account.
SERVICE = "com.net-dns-monitor.credentials"

ERR_SEC_ITEM_NOT_FOUND = -25300
ERR_SEC_DUPLICATE_ITEM = -25299


class KeychainBackend(Protocol):
    def read(self, account: str) -> tuple[int, Optional[bytes]]: ...

    def add(self, account: str, value: bytes) -> int: ...

    def update(self, account: str, value: bytes) -> int: ...

    def delete(self, account: str) -> int: ...


def make_keychain_backend(service: str = SERVICE) -> KeychainBackend:
    """The real Keychain, via SecItem* loaded from Security.framework."""
    import objc
    from Foundation import NSBundle, NSData

    bundle = NSBundle.bundleWithPath_("/System/Library/Frameworks/Security.framework")
    fns: dict = {}
    objc.loadBundleFunctions(
        bundle,
        fns,
        [
            ("SecItemCopyMatching", b"i@o^@"),
            ("SecItemAdd", b"i@o^@"),
            ("SecItemUpdate", b"i@@"),
            ("SecItemDelete", b"i@"),
        ],
    )
    objc.loadBundleVariables(
        bundle,
        fns,
        [
            (name, b"@")
            for name in (
                "kSecClass",
                "kSecClassGenericPassword",
                "kSecAttrService",
                "kSecAttrAccount",
                "kSecValueData",
                "kSecReturnData",
                "kSecMatchLimit",
                "kSecMatchLimitOne",
            )
        ],
    )

    def query(account: str) -> dict:
        return {
            fns["kSecClass"]: fns["kSecClassGenericPassword"],
            fns["kSecAttrService"]: service,
            fns["kSecAttrAccount"]: account,
        }

    def data(value: bytes):
        return NSData.dataWithBytes_length_(value, len(value))

    class _Backend:
        def read(self, account: str) -> tuple[int, Optional[bytes]]:
            request = query(account)
            request[fns["kSecReturnData"]] = True
            request[fns["kSecMatchLimit"]] = fns["kSecMatchLimitOne"]
            status, result = fns["SecItemCopyMatching"](request, None)
            return int(status), (bytes(result) if status == 0 and result is not None else None)

        def add(self, account: str, value: bytes) -> int:
            request = query(account)
            request[fns["kSecValueData"]] = data(value)
            status, _ = fns["SecItemAdd"](request, None)
            return int(status)

        def update(self, account: str, value: bytes) -> int:
            return int(fns["SecItemUpdate"](query(account), {fns["kSecValueData"]: data(value)}))

        def delete(self, account: str) -> int:
            return int(fns["SecItemDelete"](query(account)))

    return _Backend()


class CredentialStore:
    def __init__(
        self,
        env: Optional[Mapping[str, str]] = None,
        backend_factory: Optional[Callable[[], KeychainBackend]] = make_keychain_backend,
    ):
        self._env = os.environ if env is None else env
        self._factory = backend_factory
        self._backend: Optional[KeychainBackend] = None
        self._backend_failed = False

    def _keychain(self) -> Optional[KeychainBackend]:
        # Built lazily and once: loading the Security bundle costs a few ms, and
        # a machine where it cannot load (no PyObjC) should degrade to
        # environment-only rather than fail every lookup with the same error.
        if self._backend is None and not self._backend_failed and self._factory is not None:
            try:
                self._backend = self._factory()
            except Exception:  # noqa: BLE001 - no Keychain means env-only, never a crash
                self._backend_failed = True
        return self._backend

    def _check(self, name: str) -> None:
        if name not in NAMES:
            raise ValueError(f"unknown credential {name!r}; expected one of {', '.join(NAMES)}")

    def source(self, name: str) -> Optional[str]:
        self._check(name)
        if self._env.get(name):
            return "environment"
        backend = self._keychain()
        if backend is None:
            return None
        status, value = backend.read(name)
        return "keychain" if status == 0 and value else None

    def get(self, name: str) -> Optional[str]:
        self._check(name)
        from_env = self._env.get(name)
        if from_env:
            return from_env
        backend = self._keychain()
        if backend is None:
            return None
        status, value = backend.read(name)
        if status != 0 or not value:
            return None
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def set(self, name: str, value: str) -> str:
        self._check(name)
        if not value:
            return "failed: an empty value was not saved; use Remove to clear a credential"
        backend = self._keychain()
        if backend is None:
            return "failed: the Keychain is not available in this process"
        encoded = value.encode("utf-8")
        status = backend.add(name, encoded)
        if status == ERR_SEC_DUPLICATE_ITEM:
            status = backend.update(name, encoded)
        if status != 0:
            return f"failed: Keychain returned OSStatus {status}"
        return f"ok: {name} saved to the Keychain"

    def delete(self, name: str) -> str:
        self._check(name)
        backend = self._keychain()
        if backend is None:
            return "failed: the Keychain is not available in this process"
        status = backend.delete(name)
        if status == ERR_SEC_ITEM_NOT_FOUND:
            return f"ok: {name} was not in the Keychain"
        if status != 0:
            return f"failed: Keychain returned OSStatus {status}"
        return f"ok: {name} removed from the Keychain"

    def describe(self) -> dict[str, str]:
        """Presence only, for status panes. Never the value."""
        labels = {"environment": "set (environment)", "keychain": "set (Keychain)"}
        return {name: labels.get(self.source(name) or "", "not set") for name in NAMES}

    def as_env(self) -> Mapping[str, str]:
        """A read-only mapping view for code that takes an `env` dict.

        `build_notifier(config, env)` only calls `.get`, so this lets it read
        Keychain values without learning that the Keychain exists.
        """
        store = self

        class _View(Mapping):
            def __getitem__(self, key: str) -> str:
                value = store.get(key) if key in NAMES else store._env.get(key)
                if value is None:
                    raise KeyError(key)
                return value

            def __iter__(self):
                return iter(n for n in NAMES if store.get(n))

            def __len__(self) -> int:
                return sum(1 for _ in self)

        return _View()
