# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Custody tests for the Console device-token credential."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import agentveil_mcp_proxy.console_credentials as creds
from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCHEMA_VERSION,
    CREDENTIAL_SCOPE,
    CredentialError,
    console_login_lock,
    credential_path,
    delete_credential,
    load_credential,
    save_credential,
)

POSIX = os.name != "nt"
TOKEN = "opaque-device-token-value"


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


def test_created_directory_and_file_modes(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    path = credential_path(home=tmp_path)

    if POSIX:
        assert _mode(path) == 0o600
        assert _mode(path.parent) == 0o700


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


def test_load_rejects_oversized_file(tmp_path):
    path = credential_path(home=tmp_path)
    _write_raw(path, b"x" * (8192 + 1))

    with pytest.raises(CredentialError):
        load_credential(home=tmp_path)


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
    assert not path.exists()


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
