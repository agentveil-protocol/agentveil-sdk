# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Custody tests for the Console device-token credential."""

from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest

import agentveil_mcp_proxy.console_credentials as creds
from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCHEMA_VERSION,
    CREDENTIAL_SCOPE,
    RUNTIME_BINDING_SCOPE,
    CredentialError,
    StoredCredential,
    console_credential_home_for_runtime,
    console_login_lock,
    credential_path,
    delete_credential,
    delete_runtime_binding_credential,
    delete_scoped_runtime_binding_credential,
    load_credential,
    load_runtime_binding_credential,
    load_scoped_runtime_binding_credential,
    resolve_runtime_binding_for_context,
    runtime_binding_credential_path,
    save_credential,
    save_runtime_binding_credential,
    save_scoped_runtime_binding_credential,
    scoped_runtime_binding_namespace_hash,
)

POSIX = os.name != "nt"
TOKEN = "opaque-device-token-value"
BINDING_TOKEN = "paired-runtime-binding-token-value"


class _FakeWindowsCredentialBackend:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.lock_names: list[str] = []
        self.fail_write_after: int | None = None
        self.write_calls = 0
        self.lock_timeout = False

    def read(self, target: str) -> bytes | None:
        return self.values.get(target)

    def write(self, target: str, blob: bytes) -> None:
        self.write_calls += 1
        if (
            self.fail_write_after is not None
            and self.write_calls > self.fail_write_after
        ):
            raise creds._WindowsCredentialBackendError()
        self.values[target] = bytes(blob)

    def delete(self, target: str) -> bool:
        return self.values.pop(target, None) is not None

    @contextmanager
    def lock(self, name: str, *, nonblocking: bool):
        self.lock_names.append(name)
        if nonblocking and self.lock_timeout:
            raise creds._WindowsCredentialLockTimeout()
        yield


@pytest.fixture
def windows_backend(monkeypatch):
    backend = _FakeWindowsCredentialBackend()
    monkeypatch.setattr(creds, "_uses_windows_credential_manager", lambda: True)
    monkeypatch.setattr(creds, "_windows_credential_backend", lambda: backend)
    return backend


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _write_raw(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(path.parent, 0o700)
    path.write_bytes(data)
    if POSIX:
        os.chmod(path, mode)


def test_save_then_load_round_trip(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    loaded = load_credential(home=tmp_path)

    assert loaded is not None
    assert loaded.token == TOKEN
    assert loaded.scope == CREDENTIAL_SCOPE


def test_runtime_binding_save_load_round_trip(tmp_path):
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)
    loaded = load_runtime_binding_credential(home=tmp_path)
    assert loaded is not None
    assert loaded.token == BINDING_TOKEN
    assert loaded.scope == RUNTIME_BINDING_SCOPE
    assert credential_path(home=tmp_path) != runtime_binding_credential_path(home=tmp_path)


def test_dual_credentials_are_stored_separately(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)
    summary = load_credential(home=tmp_path)
    binding = load_runtime_binding_credential(home=tmp_path)
    assert summary is not None and binding is not None
    assert summary.token == TOKEN
    assert binding.token == BINDING_TOKEN
    assert summary.token != binding.token


def test_runtime_binding_credential_is_redacted_and_owner_only(tmp_path):
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)
    loaded = load_runtime_binding_credential(home=tmp_path)
    assert loaded is not None
    assert repr(loaded) == f"StoredCredential(scope={RUNTIME_BINDING_SCOPE!r})"
    assert BINDING_TOKEN not in repr(loaded)
    if POSIX:
        assert _mode(runtime_binding_credential_path(home=tmp_path)) == 0o600


def test_delete_runtime_binding_credential(tmp_path):
    save_runtime_binding_credential(BINDING_TOKEN, home=tmp_path)
    assert delete_runtime_binding_credential(home=tmp_path) is True
    assert load_runtime_binding_credential(home=tmp_path) is None
    assert load_credential(home=tmp_path) is None


def test_scoped_runtime_binding_isolated_from_legacy_file(tmp_path):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    legacy = "legacy-runtime-binding-token-value-0123456789ab"
    scoped = "scoped-runtime-binding-token-value-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    save_scoped_runtime_binding_credential(
        scoped,
        agent_did=agent_did,
        summary_token=summary,
        home=tmp_path,
    )
    legacy_path = runtime_binding_credential_path(home=tmp_path)
    assert legacy_path.read_text(encoding="utf-8").count(legacy) == 1
    loaded = load_scoped_runtime_binding_credential(agent_did, summary, home=tmp_path)
    assert loaded is not None and loaded.token == scoped
    namespace = scoped_runtime_binding_namespace_hash(agent_did, summary)
    assert legacy_path.name != f"runtime-binding-scoped-{namespace}.json"


def test_resolve_runtime_binding_prefers_scoped_over_legacy(tmp_path):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    save_runtime_binding_credential("legacy-runtime-binding-token-value-0123456789ab", home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=agent_did,
        summary_token=summary,
        home=tmp_path,
    )
    resolved = resolve_runtime_binding_for_context(agent_did, summary, tmp_path)
    assert resolved is not None and resolved.token == BINDING_TOKEN


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_corrupt_scoped_source_marker_fails_closed(tmp_path):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    marker_path = (
        creds.credential_directory(tmp_path)
        / creds._scoped_source_marker_filename(agent_did)
    )
    _write_raw(marker_path, b"{not-json", mode=0o600)
    with pytest.raises(CredentialError):
        creds._load_scoped_source_marker(agent_did, home=tmp_path)
    assert resolve_runtime_binding_for_context(agent_did, "summary-token-a-0123456789abcdef0123456789ab", tmp_path) is None
    assert creds.agent_scoped_runtime_opt_in_recorded(agent_did, home=tmp_path) is True


def test_legacy_binding_without_summary_remains_usable(tmp_path):
    agent_did = "did:key:z6MklegacyAgent012345678901234567890123456"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    resolved = resolve_runtime_binding_for_context(
        agent_did,
        "summary-token-a-0123456789abcdef0123456789ab",
        tmp_path,
    )
    assert resolved is not None
    assert resolved.token == legacy


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_load_scoped_binding_rejects_symlink(tmp_path):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    namespace = scoped_runtime_binding_namespace_hash(agent_did, summary)
    filename = f"runtime-binding-scoped-{namespace}.json"
    directory = creds.credential_directory(tmp_path)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    real = tmp_path / "real-scoped.json"
    real.write_text("{}", encoding="utf-8")
    os.symlink(real, directory / filename)
    with pytest.raises(CredentialError):
        load_scoped_runtime_binding_credential(agent_did, summary, home=tmp_path)


def test_scoped_store_failure_preserves_legacy_bytes(tmp_path, monkeypatch):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    before = runtime_binding_credential_path(home=tmp_path).read_text(encoding="utf-8")
    namespace = scoped_runtime_binding_namespace_hash(agent_did, summary)
    scoped_name = f"runtime-binding-scoped-{namespace}.json"

    real_atomic_write = creds._atomic_write_to_directory_fd

    def _boom(dir_fd, filename, payload):
        if filename == scoped_name:
            raise CredentialError("credential_write_failed")
        return real_atomic_write(dir_fd, filename, payload)

    monkeypatch.setattr(creds, "_atomic_write_to_directory_fd", _boom)
    with pytest.raises(CredentialError):
        save_scoped_runtime_binding_credential(
            BINDING_TOKEN,
            agent_did=agent_did,
            summary_token=summary,
            home=tmp_path,
        )
    assert runtime_binding_credential_path(home=tmp_path).read_text(encoding="utf-8") == before
    marker = (
        creds.credential_directory(tmp_path)
        / creds._scoped_source_marker_filename(agent_did)
    )
    assert marker.is_file()
    assert load_scoped_runtime_binding_credential(agent_did, summary, home=tmp_path) is None
    assert resolve_runtime_binding_for_context(agent_did, summary, home=tmp_path) is None
    summary_b = "summary-token-b-0123456789abcdef0123456789ab"
    assert resolve_runtime_binding_for_context(agent_did, summary_b, home=tmp_path) is None


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_scoped_marker_write_failure_leaves_no_scoped_secret(tmp_path, monkeypatch):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"

    def _marker_fail(*_args, **_kwargs):
        raise CredentialError("credential_write_failed")

    monkeypatch.setattr(creds, "_save_scoped_source_marker", _marker_fail)
    with pytest.raises(CredentialError):
        save_scoped_runtime_binding_credential(
            BINDING_TOKEN,
            agent_did=agent_did,
            summary_token=summary,
            home=tmp_path,
        )
    directory = creds.credential_directory(tmp_path)
    assert not any(directory.glob("runtime-binding-scoped-*.json"))
    assert not (
        directory / creds._scoped_source_marker_filename(agent_did)
    ).exists()


def test_windows_scoped_marker_write_failure_leaves_no_binding(
    tmp_path,
    windows_backend,
):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    marker_target = creds._windows_scoped_source_marker_target(tmp_path, agent_did)
    windows_backend.fail_write_after = 0
    with pytest.raises(CredentialError, match="credential_write_failed"):
        save_scoped_runtime_binding_credential(
            BINDING_TOKEN,
            agent_did=agent_did,
            summary_token=summary,
            home=tmp_path,
        )
    assert marker_target not in windows_backend.values
    namespace = scoped_runtime_binding_namespace_hash(agent_did, summary)
    assert creds._windows_scoped_active_target(tmp_path, namespace) not in windows_backend.values


def test_windows_scoped_secret_write_failure_after_marker_blocks_legacy(
    tmp_path,
    windows_backend,
):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary_a = "summary-token-a-0123456789abcdef0123456789ab"
    summary_b = "summary-token-b-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    marker_target = creds._windows_scoped_source_marker_target(tmp_path, agent_did)
    windows_backend.fail_write_after = windows_backend.write_calls + 1
    with pytest.raises(CredentialError, match="credential_write_failed"):
        save_scoped_runtime_binding_credential(
            BINDING_TOKEN,
            agent_did=agent_did,
            summary_token=summary_a,
            home=tmp_path,
        )
    assert marker_target in windows_backend.values
    namespace = scoped_runtime_binding_namespace_hash(agent_did, summary_a)
    assert creds._windows_scoped_active_target(tmp_path, namespace) not in windows_backend.values
    assert resolve_runtime_binding_for_context(agent_did, summary_a, home=tmp_path) is None
    assert resolve_runtime_binding_for_context(agent_did, summary_b, home=tmp_path) is None
    assert load_runtime_binding_credential(home=tmp_path).token == legacy


def test_legacy_binding_survives_other_agent_scoped_credential(tmp_path):
    agent_legacy = "did:key:z6MklegacyAgent012345678901234567890123456"
    agent_scoped = "did:key:z6MkscopedAgent0123456789012345678901234567"
    summary = "summary-token-a-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    save_scoped_runtime_binding_credential(
        "scoped-runtime-binding-token-b-0123456789ab",
        agent_did=agent_scoped,
        summary_token=summary,
        home=tmp_path,
    )
    resolved = resolve_runtime_binding_for_context(agent_legacy, summary, tmp_path)
    assert resolved is not None
    assert resolved.token == legacy


def test_delete_scoped_runtime_binding_credential(tmp_path):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=agent_did,
        summary_token=summary,
        home=tmp_path,
    )
    assert delete_scoped_runtime_binding_credential(agent_did, summary, home=tmp_path)
    assert load_scoped_runtime_binding_credential(agent_did, summary, home=tmp_path) is None


def test_runtime_binding_rejects_summary_scope(tmp_path):
    with pytest.raises(CredentialError):
        save_runtime_binding_credential(BINDING_TOKEN, scope=CREDENTIAL_SCOPE, home=tmp_path)


def test_stored_credential_repr_hides_token():
    assert TOKEN not in repr(StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN))


def test_created_directory_and_file_modes(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    path = credential_path(home=tmp_path)

    if POSIX:
        assert _mode(path) == 0o600
        assert _mode(path.parent) == 0o700
    else:
        assert not path.exists()
        assert not path.parent.exists()


@pytest.mark.skipif(not POSIX, reason="filesystem payload is a POSIX guarantee")
def test_persisted_payload_is_bounded_exact_schema(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    payload = json.loads(credential_path(home=tmp_path).read_text(encoding="utf-8"))

    assert payload == {
        "schema_version": CREDENTIAL_SCHEMA_VERSION,
        "scope": CREDENTIAL_SCOPE,
        "token": TOKEN,
    }


def test_load_missing_returns_none(tmp_path):
    assert load_credential(home=tmp_path) is None


@pytest.mark.skipif(not POSIX, reason="symlink custody is a POSIX guarantee")
def test_load_rejects_symlink(tmp_path):
    path = credential_path(home=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    real = tmp_path / "elsewhere.json"
    real.write_text("{}", encoding="utf-8")
    os.symlink(real, path)

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.skipif(not POSIX, reason="hardlink custody is a POSIX guarantee")
def test_load_rejects_hardlink(tmp_path):
    path = credential_path(home=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    other = tmp_path / "console" / "other.json"
    other.write_bytes(b"{}")
    os.chmod(other, 0o600)
    os.link(other, path)

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_load_rejects_non_regular(tmp_path):
    path = credential_path(home=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.skipif(not POSIX, reason="ownership check is a POSIX guarantee")
def test_load_rejects_wrong_owner(tmp_path, monkeypatch):
    save_credential(TOKEN, home=tmp_path)
    real_owner = credential_path(home=tmp_path).stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: real_owner + 1)

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.skipif(not POSIX, reason="mode check is a POSIX guarantee")
def test_load_rejects_permissive_mode(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    os.chmod(credential_path(home=tmp_path), 0o644)

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_load_rejects_oversized_file(tmp_path):
    path = credential_path(home=tmp_path)
    _write_raw(path, b"x" * (8192 + 1))

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_load_rejects_malformed_json(tmp_path):
    _write_raw(credential_path(home=tmp_path), b"{not json")

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 1, "scope": CREDENTIAL_SCOPE, "token": TOKEN, "x": 1},
        {"schema_version": 2, "scope": CREDENTIAL_SCOPE, "token": TOKEN},
        {"schema_version": True, "scope": CREDENTIAL_SCOPE, "token": TOKEN},
        {"schema_version": 1, "scope": "other_scope", "token": TOKEN},
        {"schema_version": 1, "scope": CREDENTIAL_SCOPE, "token": ""},
        {"schema_version": 1, "scope": CREDENTIAL_SCOPE, "token": 123},
        {"scope": CREDENTIAL_SCOPE, "token": TOKEN},
    ],
)
@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_load_rejects_unknown_schema_scope_or_types(tmp_path, payload):
    _write_raw(
        credential_path(home=tmp_path),
        json.dumps(payload).encode("utf-8"),
    )

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


@pytest.mark.parametrize("bad_scope", ["", "wrong", None])
def test_save_rejects_bad_scope(tmp_path, bad_scope):
    with pytest.raises(CredentialError):
        save_credential(TOKEN, scope=bad_scope, home=tmp_path)
    assert load_credential(home=tmp_path) is None


@pytest.mark.parametrize("bad_token", ["", "line\nbreak", "tab\tchar", 123, True])
def test_save_rejects_bad_token(tmp_path, bad_token):
    with pytest.raises(CredentialError):
        save_credential(bad_token, home=tmp_path)
    assert load_credential(home=tmp_path) is None


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_atomic_write_failure_keeps_prior_credential(tmp_path, monkeypatch):
    save_credential(TOKEN, home=tmp_path)

    def _boom(*_args, **_kwargs):
        raise CredentialError("credential_write_failed")

    monkeypatch.setattr(creds, "_atomic_write_to_directory_fd", _boom)
    with pytest.raises(CredentialError):
        save_credential("new-token-value", home=tmp_path)

    still = load_credential(home=tmp_path)
    assert still is not None
    assert still.token == TOKEN


def test_delete_removes_regular_credential(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    path = credential_path(home=tmp_path)

    assert delete_credential(home=tmp_path) is True
    if POSIX:
        assert not path.exists()
    else:
        assert load_credential(home=tmp_path) is None


def test_delete_missing_is_false(tmp_path):
    assert delete_credential(home=tmp_path) is False


@pytest.mark.skipif(not POSIX, reason="symlink custody is a POSIX guarantee")
def test_delete_rejects_symlink_and_preserves_target(tmp_path):
    path = credential_path(home=tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    real = tmp_path / "target.json"
    real.write_text("keep", encoding="utf-8")
    os.symlink(real, path)

    with pytest.raises(CredentialError):
        delete_credential(home=tmp_path)
    assert real.exists()


@pytest.mark.skipif(not POSIX, reason="filesystem custody is a POSIX guarantee")
def test_error_text_carries_no_token(tmp_path):
    _write_raw(credential_path(home=tmp_path), b"{bad")
    try:
        load_credential(home=tmp_path)
    except CredentialError as exc:
        assert TOKEN not in str(exc)
        assert "/" not in str(exc)
    else:  # pragma: no cover - defensive
        pytest.fail("expected CredentialError")


# --- C4-001: parent-directory symlink custody --------------------------------


def _write_valid_credential_file(path: Path, token: str = TOKEN) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(path.parent, 0o700)
    payload = {
        "schema_version": CREDENTIAL_SCHEMA_VERSION,
        "scope": CREDENTIAL_SCOPE,
        "token": token,
    }
    path.write_bytes(json.dumps(payload).encode("utf-8"))
    if POSIX:
        os.chmod(path, 0o600)


@pytest.mark.skipif(not POSIX, reason="symlink custody is a POSIX guarantee")
def test_load_rejects_parent_directory_symlink(tmp_path):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = tmp_path / "real-console"
    real_console.mkdir(mode=0o700)
    _write_valid_credential_file(real_console / "device-token.json")
    os.symlink(real_console, home / "console")

    with pytest.raises(CredentialError):
        load_credential(home=home)


@pytest.mark.skipif(not POSIX, reason="symlink custody is a POSIX guarantee")
def test_delete_rejects_parent_directory_symlink(tmp_path):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = tmp_path / "real-console"
    real_console.mkdir(mode=0o700)
    _write_valid_credential_file(real_console / "device-token.json")
    os.symlink(real_console, home / "console")

    with pytest.raises(CredentialError):
        delete_credential(home=home)
    assert (real_console / "device-token.json").exists()


@pytest.mark.skipif(not POSIX, reason="symlink custody is a POSIX guarantee")
def test_save_rejects_parent_directory_symlink(tmp_path):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = tmp_path / "real-console"
    real_console.mkdir(mode=0o700)
    os.symlink(real_console, home / "console")

    with pytest.raises(CredentialError):
        save_credential(TOKEN, home=home)
    assert list(real_console.iterdir()) == []


# --- C4-001-R1: parent-directory TOCTOU via pinned dir_fd -------------------

EXTERNAL_TOKEN = "external-secret-token-value"


def _install_parent_swap_after_directory_open(monkeypatch, home: Path, external: Path):
    real_console = home / "console"
    backup = home / "console-pinned-backup"
    original_open = os.open
    swapped = {"done": False}

    def _opening(path, flags, mode=0o777, *, dir_fd=None, **kwargs):
        fd = original_open(path, flags, mode, dir_fd=dir_fd, **kwargs)
        if (
            dir_fd is None
            and not swapped["done"]
            and str(path) == str(real_console)
            and flags & os.O_DIRECTORY
        ):
            swapped["done"] = True
            real_console.rename(backup)
            os.symlink(external, real_console)
        return fd

    monkeypatch.setattr(os, "open", _opening)
    return backup


@pytest.mark.skipif(not POSIX, reason="directory fd custody is a POSIX guarantee")
def test_load_survives_parent_directory_swap(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = home / "console"
    real_console.mkdir(mode=0o700)
    save_credential(TOKEN, home=home)

    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    _write_valid_credential_file(external / "device-token.json", EXTERNAL_TOKEN)

    backup = _install_parent_swap_after_directory_open(monkeypatch, home, external)

    loaded = load_credential(home=home)

    assert loaded is not None
    assert loaded.token == TOKEN
    assert json.loads((external / "device-token.json").read_text())["token"] == EXTERNAL_TOKEN
    assert (backup / "device-token.json").exists()


@pytest.mark.skipif(not POSIX, reason="directory fd custody is a POSIX guarantee")
def test_delete_survives_parent_directory_swap(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = home / "console"
    real_console.mkdir(mode=0o700)
    save_credential(TOKEN, home=home)

    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    _write_valid_credential_file(external / "device-token.json", EXTERNAL_TOKEN)

    backup = _install_parent_swap_after_directory_open(monkeypatch, home, external)

    assert delete_credential(home=home) is True
    assert not (backup / "device-token.json").exists()
    assert (external / "device-token.json").exists()


@pytest.mark.skipif(not POSIX, reason="directory fd custody is a POSIX guarantee")
def test_save_survives_parent_directory_swap(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = home / "console"
    real_console.mkdir(mode=0o700)

    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    _write_valid_credential_file(external / "device-token.json", EXTERNAL_TOKEN)

    backup = _install_parent_swap_after_directory_open(monkeypatch, home, external)

    save_credential(TOKEN, home=home)

    assert json.loads((backup / "device-token.json").read_text())["token"] == TOKEN
    assert json.loads((external / "device-token.json").read_text())["token"] == EXTERNAL_TOKEN
    with pytest.raises(CredentialError):
        load_credential(home=home)


@pytest.mark.skipif(not POSIX, reason="directory fd custody is a POSIX guarantee")
def test_login_lock_survives_parent_directory_swap(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    home.mkdir()
    real_console = home / "console"
    real_console.mkdir(mode=0o700)

    external = tmp_path / "external"
    external.mkdir(mode=0o700)

    backup = _install_parent_swap_after_directory_open(monkeypatch, home, external)

    with console_login_lock(home=home):
        assert (backup / ".login.lock").exists()
        assert not (external / ".login.lock").exists()


# --- Windows Credential Manager custody --------------------------------------


def test_windows_scoped_binding_round_trip_without_plaintext_file(
    tmp_path,
    windows_backend,
):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary = "summary-token-scoped-0123456789abcdef0123456789ab"
    scoped = "scoped-runtime-binding-token-value-0123456789ab"
    save_scoped_runtime_binding_credential(
        scoped,
        agent_did=agent_did,
        summary_token=summary,
        home=tmp_path,
    )
    loaded = load_scoped_runtime_binding_credential(agent_did, summary, home=tmp_path)
    assert loaded is not None and loaded.token == scoped
    assert not any(tmp_path.rglob("runtime-binding-scoped-*.json"))


def test_windows_scoped_source_change_blocks_legacy_fallback(
    tmp_path,
    windows_backend,
):
    agent_did = "did:key:z6MkhaWgW9R3mQ8p1k2v3N4m5L6n7O8p9Q0r1S2t3U4v5W6x7Y8z9"
    summary_a = "summary-token-a-0123456789abcdef0123456789ab"
    summary_b = "summary-token-b-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=agent_did,
        summary_token=summary_a,
        home=tmp_path,
    )
    assert resolve_runtime_binding_for_context(agent_did, summary_b, home=tmp_path) is None
    assert load_runtime_binding_credential(home=tmp_path).token == legacy


def test_windows_other_agent_scoped_entry_preserves_legacy_agent(
    tmp_path,
    windows_backend,
):
    agent_legacy = "did:key:z6MklegacyAgent012345678901234567890123456"
    agent_scoped = "did:key:z6MkscopedAgent0123456789012345678901234567"
    summary = "summary-token-a-0123456789abcdef0123456789ab"
    legacy = "legacy-global-runtime-binding-token-0123456789ab"
    save_runtime_binding_credential(legacy, home=tmp_path)
    save_scoped_runtime_binding_credential(
        BINDING_TOKEN,
        agent_did=agent_scoped,
        summary_token=summary,
        home=tmp_path,
    )
    resolved = resolve_runtime_binding_for_context(agent_legacy, summary, home=tmp_path)
    assert resolved is not None and resolved.token == legacy


def test_windows_save_load_delete_uses_current_user_credential_store(
    tmp_path,
    windows_backend,
):
    save_credential(TOKEN, home=tmp_path)

    assert not credential_path(home=tmp_path).exists()
    assert load_credential(home=tmp_path) == creds.StoredCredential(
        scope=CREDENTIAL_SCOPE,
        token=TOKEN,
    )
    assert delete_credential(home=tmp_path) is True
    assert load_credential(home=tmp_path) is None
    assert windows_backend.values == {}


@pytest.mark.parametrize(
    ("token", "expected_chunks"),
    [
        ("x" * 4096, 2),
        ("\U0001F642" * 4096, creds._WINDOWS_MAX_CHUNKS),
    ],
)
def test_windows_store_chunks_maximum_contract_token_without_raw_path(
    tmp_path,
    windows_backend,
    token,
    expected_chunks,
):
    save_credential(token, home=tmp_path)

    active_target = creds._windows_active_target(tmp_path)
    generation, chunk_count, token_byte_length = creds._parse_windows_metadata(
        windows_backend.values[active_target]
    )
    assert token_byte_length == len(token.encode("utf-8"))
    assert chunk_count == expected_chunks
    assert load_credential(home=tmp_path).token == token
    assert str(tmp_path) not in "\n".join(windows_backend.values)
    assert not any(
        len(blob) > creds._WINDOWS_CREDENTIAL_BLOB_BYTES
        for blob in windows_backend.values.values()
    )
    assert generation


def test_windows_save_failure_preserves_prior_active_credential(
    tmp_path,
    windows_backend,
):
    save_credential(TOKEN, home=tmp_path)
    windows_backend.fail_write_after = windows_backend.write_calls + 1

    with pytest.raises(CredentialError, match="credential_write_failed"):
        save_credential("y" * 4096, home=tmp_path)

    loaded = load_credential(home=tmp_path)
    assert loaded is not None
    assert loaded.token == TOKEN


def test_windows_rejects_malformed_pointer_and_missing_chunk(
    tmp_path,
    windows_backend,
):
    active_target = creds._windows_active_target(tmp_path)
    windows_backend.values[active_target] = b"{}"

    with pytest.raises(CredentialError, match="credential_invalid"):
        load_credential(home=tmp_path)

    del windows_backend.values[active_target]
    save_credential(TOKEN, home=tmp_path)
    generation, chunk_count, _ = creds._parse_windows_metadata(
        windows_backend.values[active_target]
    )
    del windows_backend.values[
        creds._windows_chunk_target(creds._windows_namespace(tmp_path), generation, 0)
    ]

    with pytest.raises(CredentialError, match="credential_invalid"):
        load_credential(home=tmp_path)
    assert chunk_count == 1


def test_windows_login_lock_is_named_and_fails_closed_on_contention(
    tmp_path,
    windows_backend,
):
    windows_backend.lock_timeout = True

    with pytest.raises(CredentialError, match="login_in_progress"):
        with console_login_lock(home=tmp_path):
            pytest.fail("lock should not be acquired")

    assert windows_backend.lock_names == [
        creds._windows_mutex_name(tmp_path, purpose="login")
    ]
    assert str(tmp_path) not in windows_backend.lock_names[0]


def test_cursor_project_runtime_uses_global_console_credential_home(
    monkeypatch,
    tmp_path,
):
    monkeypatch.delenv("AVP_HOME", raising=False)
    runtime_home = tmp_path / "project" / ".agentveil"
    assert console_credential_home_for_runtime(runtime_home) == (
        tmp_path.home() / ".avp"
    )


def test_project_runtime_symlink_to_global_is_distinct_and_fails_closed_on_alias(
    tmp_path,
    monkeypatch,
):
    from agentveil_mcp_proxy.console_credentials import (
        is_distinct_project_runtime_home,
        requires_scoped_paid_provider_discovery,
    )

    global_home = tmp_path / "global.avp"
    global_home.mkdir()
    project_home = tmp_path / "project" / ".avp"
    project_home.parent.mkdir(parents=True)
    project_home.symlink_to(global_home)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials._global_console_credential_home",
        lambda: global_home,
    )

    assert is_distinct_project_runtime_home(project_home) is True
    assert requires_scoped_paid_provider_discovery(project_home) is True
    assert console_credential_home_for_runtime(project_home) == project_home


@pytest.mark.parametrize("runtime_name", [".avp", ".agentveil"])
def test_project_runtime_symlink_preflight_skips_automatic_sync(
    tmp_path,
    monkeypatch,
    runtime_name,
):
    from agentveil_mcp_proxy.console_credentials import (
        project_runtime_home_automatic_sync_preflight_skip,
    )

    global_home = tmp_path / "global.avp"
    global_home.mkdir()
    project_home = tmp_path / "project" / runtime_name
    project_home.parent.mkdir(parents=True)
    project_home.symlink_to(global_home)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_credentials._global_console_credential_home",
        lambda: global_home,
    )

    assert project_runtime_home_automatic_sync_preflight_skip(project_home) == (
        "skipped_unsafe_runtime_home"
    )
    real_project_home = tmp_path / "project-real" / runtime_name
    real_project_home.mkdir(parents=True)
    assert project_runtime_home_automatic_sync_preflight_skip(real_project_home) is None


def test_windows_native_backend_errors_do_not_expose_token_or_path(
    tmp_path,
    windows_backend,
):
    windows_backend.fail_write_after = 0
    try:
        save_credential(TOKEN, home=tmp_path)
    except CredentialError as exc:
        assert str(exc) == "credential_write_failed"
        assert TOKEN not in str(exc)
        assert str(tmp_path) not in str(exc)
    else:  # pragma: no cover - defensive
        pytest.fail("expected CredentialError")
