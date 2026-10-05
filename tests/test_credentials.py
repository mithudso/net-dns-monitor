import pytest

from netdnsmonitor.credentials import (
    ERR_SEC_DUPLICATE_ITEM,
    ERR_SEC_ITEM_NOT_FOUND,
    NAMES,
    CredentialStore,
)


class FakeKeychain:
    def __init__(self, items=None, fail_status=None):
        self.items = dict(items or {})
        self.fail_status = fail_status
        self.calls = []

    def read(self, account):
        self.calls.append(("read", account))
        if self.fail_status is not None:
            return self.fail_status, None
        if account not in self.items:
            return ERR_SEC_ITEM_NOT_FOUND, None
        return 0, self.items[account]

    def add(self, account, value):
        self.calls.append(("add", account))
        if self.fail_status is not None:
            return self.fail_status
        if account in self.items:
            return ERR_SEC_DUPLICATE_ITEM
        self.items[account] = value
        return 0

    def update(self, account, value):
        self.calls.append(("update", account))
        self.items[account] = value
        return 0

    def delete(self, account):
        self.calls.append(("delete", account))
        if account not in self.items:
            return ERR_SEC_ITEM_NOT_FOUND
        del self.items[account]
        return 0


def store(env=None, keychain=None):
    keychain = keychain if keychain is not None else FakeKeychain()
    return CredentialStore(env=env or {}, backend_factory=lambda: keychain), keychain


def test_the_environment_wins_so_the_direct_build_behaves_as_before():
    creds, keychain = store(
        env={"ANTHROPIC_API_KEY": "from-env"},
        keychain=FakeKeychain({"ANTHROPIC_API_KEY": b"from-keychain"}),
    )
    assert creds.get("ANTHROPIC_API_KEY") == "from-env"
    assert creds.source("ANTHROPIC_API_KEY") == "environment"
    assert keychain.calls == []


def test_the_keychain_is_used_when_the_environment_has_nothing():
    creds, _ = store(keychain=FakeKeychain({"SLACK_WEBHOOK_URL": b"https://hooks.example/x"}))
    assert creds.get("SLACK_WEBHOOK_URL") == "https://hooks.example/x"
    assert creds.source("SLACK_WEBHOOK_URL") == "keychain"


def test_a_missing_credential_is_none_not_an_empty_string():
    creds, _ = store()
    assert creds.get("SMTP_PASSWORD") is None
    assert creds.source("SMTP_PASSWORD") is None


def test_an_unknown_name_is_refused_rather_than_read():
    creds, keychain = store()
    with pytest.raises(ValueError):
        creds.get("HOME")
    assert keychain.calls == []


def test_saving_twice_updates_instead_of_failing_on_the_duplicate():
    creds, keychain = store()
    assert creds.set("ANTHROPIC_API_KEY", "one").startswith("ok:")
    assert creds.set("ANTHROPIC_API_KEY", "two").startswith("ok:")
    assert keychain.items["ANTHROPIC_API_KEY"] == b"two"
    assert ("update", "ANTHROPIC_API_KEY") in keychain.calls


def test_a_keychain_error_is_reported_by_status_only_never_with_the_value():
    creds, _ = store(keychain=FakeKeychain(fail_status=-34018))
    outcome = creds.set("SMTP_PASSWORD", "hunter2-secret")
    assert outcome == "failed: Keychain returned OSStatus -34018"
    assert "hunter2" not in outcome


def test_an_empty_value_is_not_saved():
    creds, keychain = store()
    assert creds.set("SMTP_PASSWORD", "").startswith("failed:")
    assert keychain.calls == []


def test_deleting_a_missing_item_is_not_an_error():
    creds, _ = store()
    assert creds.delete("SMTP_PASSWORD") == "ok: SMTP_PASSWORD was not in the Keychain"


def test_deleting_removes_the_value():
    creds, keychain = store(keychain=FakeKeychain({"SMTP_PASSWORD": b"x"}))
    assert creds.delete("SMTP_PASSWORD").startswith("ok:")
    assert "SMTP_PASSWORD" not in keychain.items
    assert creds.get("SMTP_PASSWORD") is None


def test_no_keychain_degrades_to_environment_only():
    def broken():
        raise ImportError("no PyObjC")

    creds = CredentialStore(env={"SMTP_PASSWORD": "env"}, backend_factory=broken)
    assert creds.get("SMTP_PASSWORD") == "env"
    assert creds.get("ANTHROPIC_API_KEY") is None
    assert creds.set("ANTHROPIC_API_KEY", "x").startswith("failed:")


def test_the_backend_is_built_once_even_when_it_fails():
    attempts = []

    def broken():
        attempts.append(1)
        raise OSError("nope")

    creds = CredentialStore(env={}, backend_factory=broken)
    creds.get("ANTHROPIC_API_KEY")
    creds.get("SLACK_WEBHOOK_URL")
    assert attempts == [1]


def test_describe_reports_presence_and_never_the_value():
    creds, _ = store(
        env={"ANTHROPIC_API_KEY": "sk-ant-secret"},
        keychain=FakeKeychain({"SLACK_WEBHOOK_URL": b"https://hooks.example/secret"}),
    )
    described = creds.describe()
    assert described == {
        "ANTHROPIC_API_KEY": "set (environment)",
        "SLACK_WEBHOOK_URL": "set (Keychain)",
        "SMTP_PASSWORD": "not set",
    }
    assert "secret" not in str(described)


def test_the_env_view_lets_env_taking_code_read_keychain_values():
    creds, _ = store(keychain=FakeKeychain({"SLACK_WEBHOOK_URL": b"https://hooks.example/x"}))
    view = creds.as_env()
    assert view.get("SLACK_WEBHOOK_URL") == "https://hooks.example/x"
    assert view.get("SMTP_PASSWORD") is None
    assert "SLACK_WEBHOOK_URL" in list(view)
    assert set(view) <= set(NAMES)


def test_undecodable_keychain_bytes_read_as_missing():
    creds, _ = store(keychain=FakeKeychain({"SMTP_PASSWORD": b"\xff\xfe"}))
    assert creds.get("SMTP_PASSWORD") is None


class RaisingKeychain(FakeKeychain):
    def read(self, account):
        raise TypeError("bridge error")


def test_a_keychain_read_that_raises_reads_as_missing():
    """get() runs inside app construction; an exception there kills the launch."""
    creds, _ = store(keychain=RaisingKeychain())
    assert creds.get("ANTHROPIC_API_KEY") is None
    assert creds.source("ANTHROPIC_API_KEY") is None


def test_source_agrees_with_get_on_undecodable_bytes():
    creds, _ = store(keychain=FakeKeychain({"SMTP_PASSWORD": b"\xff\xfe"}))
    assert creds.source("SMTP_PASSWORD") is None


class _Raising(FakeKeychain):
    def __init__(self, add_exc=None, update_exc=None, delete_exc=None, **kw):
        super().__init__(**kw)
        self.add_exc, self.update_exc, self.delete_exc = add_exc, update_exc, delete_exc

    def add(self, account, value):
        if self.add_exc:
            raise self.add_exc(value.decode())  # a message that carries the secret
        return super().add(account, value)

    def update(self, account, value):
        if self.update_exc:
            raise self.update_exc(value.decode())
        return super().update(account, value)

    def delete(self, account):
        if self.delete_exc:
            raise self.delete_exc("bridge")
        return super().delete(account)


def _store(kc, env=None):
    return CredentialStore(env=env or {}, backend_factory=lambda: kc)


@pytest.mark.parametrize("status", [-25308, -25293, -128])  # locked, auth failed, cancelled
def test_an_unreadable_keychain_item_is_not_reported_as_not_set(status):
    creds = _store(FakeKeychain(items={"SMTP_PASSWORD": b"x"}, fail_status=status))
    assert creds.describe()["SMTP_PASSWORD"] == f"unreadable (OSStatus {status})"
    assert creds.read_problem("SMTP_PASSWORD") == status
    assert creds.get("SMTP_PASSWORD") is None


def test_item_not_found_is_not_a_read_problem():
    creds = _store(FakeKeychain())
    assert creds.describe()["SMTP_PASSWORD"] == "not set"
    assert creds.read_problem("SMTP_PASSWORD") is None


def test_read_problem_is_none_after_a_good_read_and_without_a_backend():
    kc = FakeKeychain(items={"SMTP_PASSWORD": b"x"})
    creds = _store(kc)
    assert creds.get("SMTP_PASSWORD") == "x"
    assert creds.read_problem("SMTP_PASSWORD") is None
    nobackend = CredentialStore(env={}, backend_factory=None)
    assert nobackend.read_problem("SMTP_PASSWORD") is None


def test_read_problem_follows_the_latest_read():
    kc = FakeKeychain(items={"SMTP_PASSWORD": b"x"}, fail_status=-25308)
    creds = _store(kc)
    creds.get("SMTP_PASSWORD")
    assert creds.read_problem("SMTP_PASSWORD") == -25308
    kc.fail_status = None
    creds.get("SMTP_PASSWORD")
    assert creds.read_problem("SMTP_PASSWORD") is None


def test_set_reports_a_raising_backend_by_class_and_never_echoes_the_value():
    out = _store(_Raising(add_exc=RuntimeError)).set("SMTP_PASSWORD", "hunter2")
    assert out == "failed: the Keychain write raised RuntimeError"
    assert "hunter2" not in out


def test_set_reports_a_raising_update_after_a_duplicate():
    kc = _Raising(items={"SMTP_PASSWORD": b"old"}, update_exc=ValueError)
    out = _store(kc).set("SMTP_PASSWORD", "hunter2")
    assert out == "failed: the Keychain write raised ValueError"


def test_delete_reports_a_raising_backend_by_class():
    out = _store(_Raising(delete_exc=RuntimeError)).delete("SMTP_PASSWORD")
    assert out == "failed: the Keychain delete raised RuntimeError"


def test_duplicate_then_failed_update_reports_the_update_status():
    class Kc(FakeKeychain):
        def update(self, account, value):
            return -25293

    out = _store(Kc(items={"SMTP_PASSWORD": b"old"})).set("SMTP_PASSWORD", "new")
    assert out == "failed: Keychain returned OSStatus -25293"


def test_delete_with_a_nonzero_status_reports_it():
    class Kc(FakeKeychain):
        def delete(self, account):
            return -25293

    assert _store(Kc()).delete("SMTP_PASSWORD") == "failed: Keychain returned OSStatus -25293"
