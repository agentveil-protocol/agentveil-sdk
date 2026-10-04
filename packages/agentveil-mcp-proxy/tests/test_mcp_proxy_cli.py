"""P2 tests for minimal MCP proxy CLI init/run/doctor."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace
from typing import Any

import pytest
from nacl.signing import VerifyKey

import agentveil_mcp_proxy.cli as proxy_cli
import agentveil_mcp_proxy.control_artifacts as control_artifacts
from agentveil_mcp_proxy.client_guidance import (
    ProjectSecretGitCustodyError,
    prepare_project_local_secret_git_custody,
)
import agentveil_mcp_proxy.console_credentials as console_creds
from agentveil.delegation import verify_delegation
from agentveil.exceptions import AVPNotFoundError, AVPServerError, AVPValidationError
from agentveil_mcp_proxy.cli import (
    AGENTVEIL_DEV_SIGNER_DIDS,
    MIN_IDENTITY_PASSPHRASE_LENGTH,
    ProxyCliError,
    configure_downstream,
    doctor_proxy,
    evidence_summary,
    export_evidence,
    init_proxy,
    list_events,
    main,
    proxy_paths,
    quickstart_filesystem_downstream,
    register_proxy,
    reissue_grant,
    run_proxy,
    smoke_proxy,
)
from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    RUNTIME_BINDING_SCOPE,
    credential_path,
    load_credential,
    load_runtime_binding_credential,
    save_credential,
    save_runtime_binding_credential,
)
from agentveil_mcp_proxy.console_attach_client import (
    AttachClientError,
    AttachStart,
    AttachToken,
)
from agentveil_mcp_proxy.console_pairing_client import (
    PairingClientError,
    PairingStart,
    PairingToken,
    RevokeOutcome,
)
from agentveil_mcp_proxy.controlled_alternatives import inject_agentveil_write_file_tool
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, PendingApproval
from agentveil_mcp_proxy.identity import encrypted_identity_payload, load_agent_from_identity
from agentveil_mcp_proxy.client_config import assert_proxy_cli_json_is_privacy_safe
from agentveil_mcp_proxy.policy import ProxyConfig
from agentveil_mcp_proxy.quickstart_filesystem import _tools as quickstart_filesystem_tools


TEST_PASSPHRASE = "correct horse battery staple"
WRONG_PASSPHRASE = "wrong horse battery staple"
_INIT_PROJECT_LOCAL = {"project_local_secret_custody": True}


def _stub_project_proxy_home(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(proxy_dir, 0o700)
    (proxy_dir / "config.json").write_text("{}", encoding="utf-8")


def _quickstart_filesystem_tool_count() -> int:
    response = {"result": {"tools": quickstart_filesystem_tools()}}
    injected = inject_agentveil_write_file_tool(response)
    return len(injected["result"]["tools"])


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _secret_material(identity: dict) -> str:
    return identity.get("private_key_hex") or identity.get("private_key_encrypted") or identity.get("encrypted_blob") or ""


def _evidence_record(request_id: str = "req-1") -> PendingApproval:
    return PendingApproval(
        request_id=request_id,
        session_id="session-1",
        client_id="cursor",
        downstream_server="github",
        tool_name="create_issue",
        action_class="write",
        risk_class="write",
        resource_hash="sha256:" + "a" * 64,
        payload_hash="sha256:" + "b" * 64,
        policy_id="github-default",
        policy_rule_id="rule-write",
        policy_context_hash="c" * 64,
        status="pending",
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        decision_audit_id="audit-1",
        decision_receipt_sha256="d" * 64,
    )


def _issue_grant(result, *, valid_for: timedelta, valid_from: datetime | None = None) -> dict:
    identity = _load(result.identity_path)
    from agentveil_mcp_proxy.identity import load_agent_from_identity
    from agentveil.delegation import issue_delegation

    agent = load_agent_from_identity(
        identity,
        base_url=identity["base_url"],
        agent_name=identity["name"],
        passphrase=TEST_PASSPHRASE if identity.get("encrypted") else None,
    )
    return issue_delegation(
        principal_private_key=agent._private_key,
        agent_did=agent.did,
        scope=[{"predicate": "allowed_category", "value": "mcp_proxy"}],
        valid_for=valid_for,
        purpose="Local MCP proxy control grant",
        valid_from=valid_from,
    )


def _replace_grant(
    result,
    *,
    valid_for: timedelta,
    valid_from: datetime | None = None,
) -> dict:
    grant = _issue_grant(result, valid_for=valid_for, valid_from=valid_from)
    result.control_grant_path.write_text(json.dumps(grant), encoding="utf-8")
    os.chmod(result.control_grant_path, 0o600)
    return grant


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-local secret custody")
def test_secure_write_json_fsyncs_before_close(tmp_path, monkeypatch):
    calls: list[int] = []

    def fake_fsync(fd: int) -> None:
        os.fstat(fd)
        calls.append(fd)

    monkeypatch.setattr(proxy_cli.os, "fsync", fake_fsync)

    proxy_cli._secure_write_json(tmp_path / "config.json", {"ok": True})

    assert calls


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-local secret custody")
def test_secure_write_json_force_fsyncs_parent_directory_on_posix(tmp_path, monkeypatch):
    calls: list[bool] = []

    def fake_fsync(fd: int) -> None:
        calls.append(stat.S_ISDIR(os.fstat(fd).st_mode))

    monkeypatch.setattr(proxy_cli.os, "fsync", fake_fsync)
    path = tmp_path / "config.json"
    proxy_cli._secure_write_json(path, {"old": True})

    calls.clear()
    proxy_cli._secure_write_json(path, {"new": True}, force=True)

    assert calls[-1] is True


def test_init_creates_identity_config_and_control_grant_with_0600(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )

    assert result.identity_path == home / "agents" / "proxy.json"
    assert result.config_path == home / "mcp-proxy" / "config.json"
    assert result.control_grant_path == home / "mcp-proxy" / "proxy.control-grant.json"
    if os.name != "nt":
        assert _mode(result.identity_path) == 0o600
        assert _mode(result.config_path) == 0o600
        assert _mode(result.control_grant_path) == 0o600
        assert _mode(result.identity_path.parent) == 0o700
        assert _mode(result.config_path.parent) == 0o700

    identity = _load(result.identity_path)
    assert identity["name"] == "proxy"
    assert identity["did"] == result.agent_did
    assert identity["encrypted"] is True
    assert "private_key_hex" not in identity
    assert isinstance(identity["encrypted_blob"], str)
    assert identity["encrypted_blob"]

    config = ProxyConfig.from_dict(_load(result.config_path))
    assert config.avp.agent_name == "proxy"
    assert config.avp.trusted_signer_dids == AGENTVEIL_DEV_SIGNER_DIDS
    assert config.policy.id == "github"

    grant = _load(result.control_grant_path)
    verified = verify_delegation(grant)
    assert verified["issuer"] == result.agent_did
    assert verified["subject"] == result.agent_did
    assert verified["scope"] == [{"predicate": "allowed_category", "value": "mcp_proxy"}]

    now = datetime.now(timezone.utc)
    ttl_seconds = (verified["valid_until"] - now).total_seconds()
    assert 29 * 24 * 60 * 60 < ttl_seconds <= 30 * 24 * 60 * 60


def test_init_scaffold_fallback_is_not_fail_open(tmp_path):
    # B5 hardening: an init-generated config must not silently forward on a
    # Runtime Gate outage. read defaults to approval (not allow); destructive
    # stays blocked.  claim-check: allow describes the destructive-fallback default asserted by this test
    result = init_proxy(
        home=tmp_path / "avp-home",
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )

    fallback = _load(result.config_path)["fallback"]
    assert fallback["read"] == "approval"
    assert fallback["write"] == "approval"
    assert fallback["destructive"] == "block"
    assert "allow" not in fallback.values()
    # The hardened scaffold still loads as a valid config.
    assert ProxyConfig.from_dict(_load(result.config_path)).fallback.read.value == "approval"


def test_init_scaffold_tool_surface_defaults_off(tmp_path):
    # B9: init scaffold ships tool_surface OFF (backward compatible). observe
    # with an empty allowlist would flag every call as undeclared (noise), so
    # claim-check: allow "every" describes scaffold noise tradeoff.
    # operators opt in after declaring their allowlist.
    result = init_proxy(
        home=tmp_path / "avp-home",
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )

    tool_surface = _load(result.config_path)["tool_surface"]
    assert tool_surface == {"mode": "off", "allow": []}
    # The scaffold still loads and the parsed surface is OFF.
    assert ProxyConfig.from_dict(_load(result.config_path)).tool_surface.mode.value == "off"


def test_init_defaults_to_encrypted_storage_with_passphrase(tmp_path):
    result = init_proxy(
        home=tmp_path / "avp-home",
        agent_name="proxy",
        passphrase=TEST_PASSPHRASE,
    )

    identity = _load(result.identity_path)
    assert identity["encrypted"] is True
    assert "private_key_hex" not in identity
    assert isinstance(identity["encrypted_blob"], str)
    assert identity["encrypted_blob"]


def test_init_rejects_passphrase_arg_shorter_than_min(tmp_path):
    with pytest.raises(ProxyCliError, match="at least"):
        init_proxy(home=tmp_path / "avp-home", agent_name="proxy", passphrase="short")


def test_init_rejects_passphrase_file_with_short_value(tmp_path):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text("short\n", encoding="utf-8")
    os.chmod(passphrase_file, 0o600)

    with pytest.raises(ProxyCliError, match="at least"):
        init_proxy(
            home=tmp_path / "avp-home",
            agent_name="proxy",
            passphrase_file=passphrase_file,
        )


def test_init_rejects_env_passphrase_too_short(tmp_path, monkeypatch):
    monkeypatch.setenv("AVP_PROXY_PASSPHRASE", "short")

    with pytest.raises(ProxyCliError, match="at least"):
        init_proxy(home=tmp_path / "avp-home", agent_name="proxy")


def test_init_rejects_tty_passphrase_too_short(tmp_path, monkeypatch):
    class TTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)
    monkeypatch.setattr(proxy_cli.sys, "stdin", TTY(""))
    monkeypatch.setattr(proxy_cli.getpass, "getpass", lambda _prompt: "short")

    with pytest.raises(ProxyCliError, match="at least"):
        init_proxy(home=tmp_path / "avp-home", agent_name="proxy")


def test_init_accepts_passphrase_at_exact_min_length(tmp_path):
    passphrase = "a" * MIN_IDENTITY_PASSPHRASE_LENGTH

    result = init_proxy(
        home=tmp_path / "avp-home",
        agent_name="proxy",
        passphrase=passphrase,
    )

    assert _load(result.identity_path)["encrypted"] is True


def test_doctor_accepts_pre_existing_short_passphrase_identity(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", plaintext=True)
    plaintext_identity = _load(result.identity_path)
    agent = load_agent_from_identity(
        plaintext_identity,
        base_url=plaintext_identity["base_url"],
        agent_name=plaintext_identity["name"],
    )
    result.identity_path.write_text(
        json.dumps(encrypted_identity_payload(agent, "short")),
        encoding="utf-8",
    )
    os.chmod(result.identity_path, 0o600)
    out = io.StringIO()

    assert doctor_proxy(home=home, passphrase="short", out=out) == 0
    assert "OK: trusted signers 2" in out.getvalue()


def test_init_plaintext_flag_explicitly_required_for_plaintext_storage(tmp_path, monkeypatch):
    class NonTTY(io.StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)
    monkeypatch.setattr("sys.stdin", NonTTY(""))

    try:
        init_proxy(home=tmp_path / "avp-home", agent_name="proxy")
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "--plaintext" in str(exc)
        assert "--passphrase" in str(exc)
    else:
        raise AssertionError("expected encrypted init to require a passphrase")


def test_init_plaintext_flag_emits_audit_warning(tmp_path):
    err = io.StringIO()

    result = init_proxy(
        home=tmp_path / "avp-home",
        agent_name="proxy",
        plaintext=True,
        err=err,
    )

    identity = _load(result.identity_path)
    assert identity["encrypted"] is False
    assert "private_key_hex" in identity
    assert "--plaintext stores the MCP proxy private key unencrypted" in err.getvalue()
    assert identity["private_key_hex"] not in err.getvalue()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode checks do not map to Windows ACLs")
def test_read_passphrase_file_rejects_world_readable_on_posix(tmp_path):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o644)

    with pytest.raises(ProxyCliError, match="owner-only"):
        proxy_cli._read_passphrase_file(passphrase_file)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode checks do not map to Windows ACLs")
def test_read_passphrase_file_rejects_group_readable_on_posix(tmp_path):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o640)

    with pytest.raises(ProxyCliError, match="owner-only"):
        proxy_cli._read_passphrase_file(passphrase_file)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode checks do not map to Windows ACLs")
def test_read_passphrase_file_accepts_0600_on_posix(tmp_path):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o600)

    assert proxy_cli._read_passphrase_file(passphrase_file) == TEST_PASSPHRASE


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode checks do not map to Windows ACLs")
def test_read_passphrase_file_accepts_0400_on_posix(tmp_path):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o400)

    assert proxy_cli._read_passphrase_file(passphrase_file) == TEST_PASSPHRASE


def test_read_passphrase_file_accepts_when_owner_only_requirement_passes(tmp_path, monkeypatch):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o644)
    monkeypatch.setattr(proxy_cli, "_require_owner_only_passphrase_file", lambda path: None)

    assert proxy_cli._read_passphrase_file(passphrase_file) == TEST_PASSPHRASE


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode checks do not map to Windows ACLs")
def test_init_with_passphrase_file_validates_permissions(tmp_path):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o644)

    with pytest.raises(ProxyCliError, match="owner-only"):
        init_proxy(
            home=tmp_path / "avp-home",
            agent_name="proxy",
            passphrase_file=passphrase_file,
        )


def test_init_refuses_to_overwrite_existing_identity_without_force(tmp_path):
    home = tmp_path / "avp-home"
    first = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    first_identity = _load(first.identity_path)

    try:
        init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    except ProxyCliError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected init to refuse overwrite")

    assert _load(first.identity_path)["did"] == first_identity["did"]

    second = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE, force=True)
    assert second.agent_did != first.agent_did
    assert _load(second.identity_path)["did"] == second.agent_did


def test_init_requires_explicit_trusted_signer_for_unknown_base_url(tmp_path):
    try:
        init_proxy(
            home=tmp_path / "avp-home",
            base_url="https://avp.example.test",
            passphrase=TEST_PASSPHRASE,
        )
    except ProxyCliError as exc:
        assert "trusted signer DID" in str(exc)
    else:
        raise AssertionError("expected init to require trusted signer DID")

    result = init_proxy(
        home=tmp_path / "avp-home",
        base_url="https://avp.example.test",
        trusted_signer_dids=["did:key:z6MkcustomSigner"],
        passphrase=TEST_PASSPHRASE,
    )
    config = ProxyConfig.from_dict(_load(result.config_path))
    assert config.avp.trusted_signer_dids == ("did:key:z6MkcustomSigner",)


def test_doctor_fails_when_trusted_signers_empty(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    config = _load(result.config_path)
    config["avp"]["trusted_signer_dids"] = []
    result.config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(result.config_path, 0o600)

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 1
    assert "trusted_signer_dids" in out.getvalue()
    identity = _load(result.identity_path)
    assert _secret_material(identity) not in out.getvalue()


def test_doctor_fails_on_insecure_identity_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX chmod permissions are not the Windows ACL enforcement surface")

    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    os.chmod(result.identity_path, 0o644)

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 1
    assert "permissions must be 0600" in out.getvalue()


def test_doctor_passes_after_init_without_printing_secrets(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 0
    assert "OK: trusted signers 2" in out.getvalue()
    assert secret not in out.getvalue()


def test_doctor_reads_encrypted_identity_with_passphrase_env_var(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    monkeypatch.setenv("AVP_PROXY_PASSPHRASE", TEST_PASSPHRASE)
    out = io.StringIO()
    assert doctor_proxy(home=home, out=out) == 0
    assert "OK: trusted signers 2" in out.getvalue()
    assert secret not in out.getvalue()

    monkeypatch.setenv("AVP_PROXY_PASSPHRASE", WRONG_PASSPHRASE)
    bad_out = io.StringIO()
    assert doctor_proxy(home=home, out=bad_out) == 1
    assert "encrypted identity could not be decrypted" in bad_out.getvalue()
    assert secret not in bad_out.getvalue()


def test_run_without_downstream_config_fails_without_printing_secrets(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    out = io.StringIO()
    try:
        run_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "downstream.command" in str(exc)
    else:
        raise AssertionError("expected run to require downstream.command")

    assert out.getvalue() == ""
    assert secret not in out.getvalue()


def test_run_auto_deny_requires_headless(tmp_path):
    try:
        run_proxy(home=tmp_path / "avp-home", auto_deny=True, out=io.StringIO())
    except ProxyCliError as exc:
        assert exc.exit_code == 2
        assert "--auto-deny requires --headless" in str(exc)
    else:
        raise AssertionError("expected --auto-deny without --headless to fail")


def test_run_proxy_binds_controlled_runtime_before_source_upload_fn(tmp_path, monkeypatch):
    home = tmp_path / "project" / ".avp"
    monkeypatch.delenv("AVP_HOME", raising=False)
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "idle",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
    }
    (home / "mcp-proxy" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    order: list[str] = []

    def capture_bind(**kwargs):
        order.append("bind")
        return None

    def capture_upload_fn(**kwargs):
        order.append("upload_fn")
        return lambda _payload, **_kw: "accepted"

    monkeypatch.setattr(proxy_cli, "bind_controlled_alternative_runtime", capture_bind)
    monkeypatch.setattr(
        proxy_cli,
        "build_run_proxy_decision_summary_upload_fn",
        capture_upload_fn,
    )
    monkeypatch.setattr(
        proxy_cli,
        "ConsoleDecisionSummaryDispatcher",
        lambda **kwargs: type(
            "NoopDecision",
            (),
            {"is_active": False, "__init__": lambda self, **kw: None, "start": lambda self: None, "stop": lambda self, **kw: None},
        )(**kwargs),
    )
    monkeypatch.setattr(
        proxy_cli,
        "ControlledAlternativesStatusDispatcher",
        lambda **kwargs: type(
            "NoopStatus",
            (),
            {"__init__": lambda self, **kw: None, "start": lambda self: None, "stop": lambda self, **kw: None},
        )(**kwargs),
    )
    monkeypatch.setattr(
        proxy_cli,
        "ConsoleApprovalSummaryDispatcher",
        lambda **kwargs: type(
            "NoopApproval",
            (),
            {
                "is_active": False,
                "__init__": lambda self, **kw: None,
                "start": lambda self: None,
                "stop": lambda self, **kw: None,
                "request_snapshot": lambda self: None,
            },
        )(**kwargs),
    )
    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert order == ["bind", "upload_fn"]


def test_run_proxy_wires_one_common_source_aware_dispatcher(tmp_path, monkeypatch):
    home = tmp_path / "project" / ".avp"
    monkeypatch.delenv("AVP_HOME", raising=False)
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "idle",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
    }
    (home / "mcp-proxy" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    wiring = {"count": 0, "dispatcher_upload_fn": None}

    def capture_upload_fn(**kwargs):
        wiring["count"] += 1
        wiring["build_kwargs"] = kwargs
        return lambda _payload, **_kw: "accepted"

    class RecordingDecisionDispatcher:
        is_active = False

        def __init__(self, **kwargs):
            wiring["dispatcher_upload_fn"] = kwargs.get("upload_fn")

        def start(self):
            return None

        def stop(self, **kwargs):
            return None

    monkeypatch.setattr(
        proxy_cli,
        "build_run_proxy_decision_summary_upload_fn",
        capture_upload_fn,
    )
    monkeypatch.setattr(
        proxy_cli,
        "ConsoleDecisionSummaryDispatcher",
        RecordingDecisionDispatcher,
    )
    monkeypatch.setattr(
        proxy_cli,
        "ControlledAlternativesStatusDispatcher",
        lambda **kwargs: type(
            "NoopStatus",
            (),
            {
                "__init__": lambda self, **kw: None,
                "start": lambda self: None,
                "stop": lambda self, **kw: None,
            },
        )(**kwargs),
    )
    monkeypatch.setattr(
        proxy_cli,
        "ConsoleApprovalSummaryDispatcher",
        lambda **kwargs: type(
            "NoopApproval",
            (),
            {
                "is_active": False,
                "__init__": lambda self, **kw: None,
                "start": lambda self: None,
                "stop": lambda self, **kw: None,
                "request_snapshot": lambda self: None,
            },
        )(**kwargs),
    )

    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert wiring["count"] == 1
    assert callable(wiring["dispatcher_upload_fn"])
    assert wiring["build_kwargs"]["state_root"] == home


def test_run_proxy_starts_and_stops_decision_summary_dispatcher(tmp_path, monkeypatch):
    home = tmp_path / "project" / ".avp"
    monkeypatch.delenv("AVP_HOME", raising=False)
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "idle",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
    }
    (home / "mcp-proxy" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    lifecycle = {
        "decision_started": 0,
        "decision_stopped": 0,
        "approval_started": 0,
        "approval_stopped": 0,
        "ca_status_started": 0,
        "ca_status_stopped": 0,
    }
    dispatcher_homes = {}

    class RecordingDecisionDispatcher:
        is_active = True

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            dispatcher_homes["decision"] = kwargs["home"]

        def start(self):
            lifecycle["decision_started"] += 1

        def stop(self, **kwargs):
            lifecycle["decision_stopped"] += 1

        def notify_terminal_record(self, record):
            return None

    class RecordingApprovalDispatcher:
        is_active = True

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            dispatcher_homes["approval"] = kwargs["home"]

        def start(self):
            lifecycle["approval_started"] += 1

        def stop(self, **kwargs):
            lifecycle["approval_stopped"] += 1

        def request_snapshot(self):
            return None

    class RecordingControlledStatusDispatcher:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            dispatcher_homes["ca_status"] = kwargs["home"]
            assert kwargs["runtime_context"] is None

        def start(self):
            lifecycle["ca_status_started"] += 1

        def stop(self, **kwargs):
            lifecycle["ca_status_stopped"] += 1

    monkeypatch.setattr(
        proxy_cli,
        "ConsoleDecisionSummaryDispatcher",
        RecordingDecisionDispatcher,
    )
    monkeypatch.setattr(
        proxy_cli,
        "ConsoleApprovalSummaryDispatcher",
        RecordingApprovalDispatcher,
    )
    monkeypatch.setattr(
        proxy_cli,
        "ControlledAlternativesStatusDispatcher",
        RecordingControlledStatusDispatcher,
    )

    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert lifecycle == {
        "decision_started": 1,
        "decision_stopped": 1,
        "approval_started": 1,
        "approval_stopped": 1,
        "ca_status_started": 1,
        "ca_status_stopped": 1,
    }
    expected_console_home = tmp_path.home() / ".avp"
    assert dispatcher_homes == {
        "decision": expected_console_home,
        "approval": expected_console_home,
        "ca_status": expected_console_home,
    }


def test_export_evidence_warns_when_signed_receipts_are_not_fetched(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_evidence_record())
    out = io.StringIO()

    bundle = export_evidence(output_path=tmp_path / "bundle.json", home=home, out=out)

    assert bundle["unverified_receipt_count"] == 1
    assert "WARN: 1 records have decision_audit_id" in out.getvalue()
    assert _secret_material(_load(result.identity_path)) not in out.getvalue()


def test_run_proxy_fails_clearly_on_encrypted_identity_without_passphrase(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    class NonTTY(io.StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)
    monkeypatch.setattr("sys.stdin", NonTTY(""))

    try:
        run_proxy(home=home, out=io.StringIO())
    except ProxyCliError as exc:
        rendered = str(exc)
        assert exc.exit_code == 1
        assert "encrypted identity passphrase required" in rendered
        assert secret not in rendered
    else:
        raise AssertionError("expected run_proxy to require encrypted identity passphrase")


def test_run_does_not_start_without_trusted_signer_config(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    config = _load(result.config_path)
    config["avp"]["trusted_signer_dids"] = []
    result.config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(result.config_path, 0o600)

    try:
        run_proxy(home=home, passphrase=TEST_PASSPHRASE)
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "trusted_signer_dids" in str(exc)
    else:
        raise AssertionError("expected run to refuse invalid trusted signer config")


def test_doctor_fails_on_tampered_grant_signature(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    grant = _load(result.control_grant_path)
    grant["credentialSubject"]["purpose"] = "Tampered purpose breaks signature"
    result.control_grant_path.write_text(json.dumps(grant), encoding="utf-8")
    os.chmod(result.control_grant_path, 0o600)

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 1
    output = out.getvalue()
    assert "control grant invalid" in output
    assert "signature verification failed" in output
    assert secret not in output


def test_doctor_fails_on_swapped_issuer_did(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    identity = _load(result.identity_path)
    swapped_did = "did:key:z6MkSwappedSignerForDoctorMismatchTest"
    assert identity["did"] != swapped_did
    identity["did"] = swapped_did
    result.identity_path.write_text(json.dumps(identity), encoding="utf-8")
    os.chmod(result.identity_path, 0o600)

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 1
    output = out.getvalue()
    assert "control grant issuer does not match proxy identity" in output
    assert "control grant subject does not match proxy identity" in output
    assert secret not in output


def test_doctor_warns_when_grant_expires_within_seven_days(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    _replace_grant(result, valid_for=timedelta(days=5))

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 0
    output = out.getvalue()
    assert "WARN: control grant expires in 5 days" in output
    assert "agentveil-mcp-proxy reissue-grant" in output
    assert secret not in output


def test_doctor_fails_when_grant_already_expired(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    _replace_grant(
        result,
        valid_for=timedelta(days=1),
        valid_from=datetime.now(timezone.utc) - timedelta(days=2),
    )

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 1
    output = out.getvalue()
    assert "FAIL: control grant expired at" in output
    assert secret not in output


def test_doctor_fails_when_identity_file_missing(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity_path = proxy_paths(home).identity_path("proxy")
    identity_path.unlink()

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 1
    output = out.getvalue()
    assert "FAIL: agent identity not found" in output


class _StubBackendAgent:
    """Minimal stub for `--check-backend` tests.

    Counts ``health()`` and ``get_onboarding_status()`` invocations so a
    regression test can assert the doctor does not call the backend
    without ``--check-backend``.
    """

    def __init__(self, *, did: str, health_raises: Exception | None = None,
                 onboarding_raises: Exception | None = None):
        self.did = did
        self._health_raises = health_raises
        self._onboarding_raises = onboarding_raises
        self.health_calls = 0
        self.onboarding_calls = 0

    def health(self) -> dict:
        self.health_calls += 1
        if self._health_raises is not None:
            raise self._health_raises
        return {"status": "ok"}

    def get_onboarding_status(self) -> dict:
        self.onboarding_calls += 1
        if self._onboarding_raises is not None:
            raise self._onboarding_raises
        return {"status": "verified"}


def _install_stub_agent(monkeypatch, agent: _StubBackendAgent) -> None:
    monkeypatch.setattr(
        proxy_cli,
        "_load_proxy_agent",
        lambda **_kwargs: agent,
    )


def test_doctor_local_only_does_not_call_backend(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    stub = _StubBackendAgent(did=identity["did"])
    _install_stub_agent(monkeypatch, stub)

    out = io.StringIO()
    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 0
    assert stub.health_calls == 0
    assert stub.onboarding_calls == 0
    assert "backend reachable" not in out.getvalue()


def test_doctor_check_backend_succeeds_with_registered_agent(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    stub = _StubBackendAgent(did=identity["did"])
    _install_stub_agent(monkeypatch, stub)

    out = io.StringIO()
    code = doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        out=out,
        check_backend=True,
    )

    assert code == 0
    assert stub.health_calls == 1
    assert stub.onboarding_calls == 1
    output = out.getvalue()
    assert "OK: backend reachable at " in output
    assert "agent registered" in output


def test_doctor_check_backend_fails_when_backend_unreachable(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    stub = _StubBackendAgent(
        did=identity["did"],
        health_raises=ConnectionError("connection refused"),
    )
    _install_stub_agent(monkeypatch, stub)

    out = io.StringIO()
    code = doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        out=out,
        check_backend=True,
    )

    assert code == 1
    output = out.getvalue()
    assert "FAIL: backend unreachable at" in output
    assert stub.health_calls == 1
    assert stub.onboarding_calls == 0
    assert "connection refused" not in output


def test_doctor_check_backend_fails_when_agent_not_registered(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    stub = _StubBackendAgent(
        did=identity["did"],
        onboarding_raises=AVPNotFoundError("agent not found", 404, "agent not found"),
    )
    _install_stub_agent(monkeypatch, stub)

    out = io.StringIO()
    code = doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        out=out,
        check_backend=True,
    )

    assert code == 1
    output = out.getvalue()
    assert "FAIL: agent " in output
    assert "is not registered with backend at" in output
    assert stub.health_calls == 1
    assert stub.onboarding_calls == 1


def test_doctor_check_backend_fails_on_server_error(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    stub = _StubBackendAgent(
        did=identity["did"],
        health_raises=AVPServerError("server error", 500, "server error"),
    )
    _install_stub_agent(monkeypatch, stub)

    out = io.StringIO()
    code = doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        out=out,
        check_backend=True,
    )

    assert code == 1
    output = out.getvalue()
    assert "FAIL: backend health check failed at" in output
    assert "status 500" in output
    assert stub.health_calls == 1
    assert stub.onboarding_calls == 0


def test_doctor_check_backend_skipped_when_local_checks_fail(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    stub = _StubBackendAgent(did=identity["did"])
    _install_stub_agent(monkeypatch, stub)

    # Break a local check (empty signer set) so backend preflight is skipped.
    config = _load(result.config_path)
    config["avp"]["trusted_signer_dids"] = []
    result.config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(result.config_path, 0o600)

    out = io.StringIO()
    code = doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        out=out,
        check_backend=True,
    )

    assert code == 1
    assert stub.health_calls == 0
    assert stub.onboarding_calls == 0
    assert "trusted_signer_dids" in out.getvalue()


_FAKE_REGISTRATION_POW_DIFFICULTY = 4


def _fake_registration_pow_valid(challenge: str, nonce: str, difficulty: int) -> bool:
    digest = hashlib.sha256((challenge + nonce).encode()).digest()
    full_bytes = difficulty // 8
    remaining_bits = difficulty % 8
    mask = (0xFF >> remaining_bits) ^ 0xFF if remaining_bits else 0
    for index in range(full_bytes):
        if digest[index] != 0:
            return False
    if remaining_bits > 0 and (digest[full_bytes] & mask) != 0:
        return False
    return True


def _fake_registration_verify_payload(
    state: "_FakeAvpRegistrationState",
    payload: dict[str, Any],
) -> str | None:
    did = payload.get("did", "")
    agent = state.agents.get(did)
    if agent is None:
        return "unknown agent"
    public_key_hex = agent.get("public_key_hex", "")
    challenge_entry = state.challenges_by_pubkey.get(public_key_hex)
    if not isinstance(challenge_entry, dict):
        return "missing registration challenge"
    challenge = payload.get("challenge", "")
    if challenge != challenge_entry.get("challenge"):
        return "challenge mismatch"
    signature_hex = payload.get("signature_hex", "")
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            challenge.encode(),
            bytes.fromhex(signature_hex),
        )
    except Exception:
        return "invalid signature"
    pow_nonce = payload.get("pow_nonce", "")
    pow_challenge = challenge_entry.get("pow_challenge", "")
    if not _fake_registration_pow_valid(
        str(pow_challenge),
        str(pow_nonce),
        _FAKE_REGISTRATION_POW_DIFFICULTY,
    ):
        return "invalid pow"
    return None


@dataclass
class _FakeAvpRegistrationState:
    register_status: int = 200
    verify_status: int = 200
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    challenges_by_pubkey: dict[str, dict[str, str]] = field(default_factory=dict)
    lookup_is_verified: dict[str, Any] = field(default_factory=dict)
    lookup_did: dict[str, str] = field(default_factory=dict)


class _FakeAvpRegistrationHandler(BaseHTTPRequestHandler):
    state: _FakeAvpRegistrationState

    def log_message(self, _format, *_args) -> None:
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else {}

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.startswith("/v1/health"):
            self._send_json(200, {"status": "ok"})
            return
        prefix = "/v1/agents/"
        if self.path.startswith(prefix):
            did = self.path[len(prefix) :].split("?", 1)[0]
            agent = self.state.agents.get(did)
            if agent is None:
                self._send_json(404, {"detail": "not found"})
                return
            reported_did = self.state.lookup_did.get(did, did)
            if did in self.state.lookup_is_verified:
                reported_verified = self.state.lookup_is_verified[did]
            else:
                reported_verified = agent.get("is_verified") is True
            self._send_json(
                200,
                {
                    "did": reported_did,
                    "is_verified": reported_verified,
                    "status": "active",
                },
            )
            return
        self._send_json(404, {"detail": "not found"})

    def do_POST(self) -> None:
        if self.path == "/v1/agents/register":
            payload = self._read_json()
            pubkey = payload.get("public_key_hex", "")
            if self.state.register_status == 409:
                self._send_json(409, {"detail": "conflict"})
                return
            if self.state.register_status >= 400:
                self._send_json(
                    self.state.register_status,
                    {"detail": "registration rejected"},
                )
                return
            challenge = secrets.token_hex(16)
            self.state.challenges_by_pubkey[pubkey] = {
                "challenge": challenge,
                "pow_challenge": challenge,
            }
            self._send_json(
                200,
                {
                    "challenge": challenge,
                    "pow_challenge": challenge,
                    "pow_difficulty": _FAKE_REGISTRATION_POW_DIFFICULTY,
                },
            )
            return
        if self.path == "/v1/agents/verify":
            payload = self._read_json()
            did = payload.get("did", "")
            if self.state.verify_status == 409:
                self._send_json(409, {"detail": "verify conflict"})
                return
            if self.state.verify_status >= 400:
                self._send_json(
                    self.state.verify_status,
                    {"detail": "verify rejected"},
                )
                return
            verify_error = _fake_registration_verify_payload(self.state, payload)
            if verify_error is not None:
                self._send_json(400, {"detail": verify_error})
                return
            entry = self.state.agents.setdefault(did, {})
            entry["is_verified"] = True
            self._send_json(
                200,
                {"onboarding_pending": False, "onboarding_started": False},
            )
            return
        self._send_json(404, {"detail": "not found"})


@contextmanager
def _fake_avp_registration_backend(
    *,
    register_status: int = 200,
    verify_status: int = 200,
):
    state = _FakeAvpRegistrationState(
        register_status=register_status,
        verify_status=verify_status,
    )
    _FakeAvpRegistrationHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeAvpRegistrationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base_url, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=0.2)


def _set_proxy_home_base_url(home: Path, base_url: str) -> None:
    paths = proxy_paths(home)
    config = _load(paths.config_path)
    config["avp"]["base_url"] = base_url
    paths.config_path.write_text(json.dumps(config), encoding="utf-8")
    identity_path = paths.identity_path(config["avp"]["agent_name"])
    identity = _load(identity_path)
    identity["base_url"] = base_url
    identity_path.write_text(json.dumps(identity), encoding="utf-8")


def _seed_identity_on_fake_backend(
    state: _FakeAvpRegistrationState,
    home: Path,
    *,
    passphrase: str | None = TEST_PASSPHRASE,
    passphrase_file: Path | None = None,
) -> str:
    from agentveil_mcp_proxy.identity import load_agent_from_identity

    paths = proxy_paths(home)
    config = _load(paths.config_path)
    identity_path = paths.identity_path(config["avp"]["agent_name"])
    identity = _load(identity_path)
    resolved_passphrase = passphrase
    if identity.get("encrypted") and passphrase_file is not None:
        resolved_passphrase = passphrase_file.read_text(encoding="utf-8").strip()
    agent = load_agent_from_identity(
        identity,
        base_url=identity["base_url"],
        agent_name=identity["name"],
        passphrase=resolved_passphrase if identity.get("encrypted") else None,
    )
    state.agents[agent.did] = {
        "public_key_hex": agent.public_key_hex,
        "is_verified": False,
    }
    return agent.did


def _assert_bounded_project_login_output(
    combined: str,
    identity: dict,
    *,
    home: Path,
) -> None:
    assert identity["did"] not in combined
    assert str(home.resolve()) not in combined
    assert TEST_PASSPHRASE not in combined
    assert _secret_material(identity) not in combined
    assert "OK: agent " not in combined
    assert "already registered at" not in combined
    assert "registered at http" not in combined.lower()


def _install_fake_register(monkeypatch, *, raises=None, capture_dids=None):
    """Replace ``AVPAgent.register`` with a deterministic fake.

    ``raises`` — exception instance to raise instead of completing.
    ``capture_dids`` — optional list to append the agent DID for each call.
    """

    from agentveil.agent import AVPAgent

    def fake_register(self):
        if capture_dids is not None:
            capture_dids.append(self.did)
        if raises is not None:
            raise raises
        self._is_registered = True
        self._is_verified = True
        return {"did": self.did, "onboarding_pending": True}

    monkeypatch.setattr(AVPAgent, "register", fake_register)


def test_register_loads_existing_proxy_did(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity_before = _load(result.identity_path)
    captured: list[str] = []
    _install_fake_register(monkeypatch, capture_dids=captured)

    out = io.StringIO()
    code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    assert code == 0
    assert captured == [identity_before["did"]]
    # Identity file still exists, still encrypted, same DID, registered flag set.
    identity_after = _load(result.identity_path)
    assert identity_after["did"] == identity_before["did"]
    assert identity_after["encrypted"] is True
    assert identity_after.get("registered") is True


def test_register_success_prints_sanitized_ok_and_no_secret(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    secret = _secret_material(identity)
    _install_fake_register(monkeypatch)

    out = io.StringIO()
    code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    output = out.getvalue()
    assert code == 0
    assert "OK: agent " in output
    assert identity["did"] in output
    assert secret not in output
    assert "private_key" not in output
    assert "encryption_salt" not in output


def test_register_success_json_is_machine_readable_and_sanitized(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    secret = _secret_material(identity)
    _install_fake_register(monkeypatch)

    out = io.StringIO()
    code = register_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        output_json=True,
        out=out,
    )

    payload = json.loads(out.getvalue())
    assert code == 0
    assert payload == {
        "agent_did": identity["did"],
        "base_url": "https://agentveil.dev",
        "errors": [],
        "ok": True,
        "registered": True,
        "warnings": [],
    }
    assert secret not in out.getvalue()
    assert "private_key" not in out.getvalue()


def test_register_backend_failure_prints_sanitized_fail(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    _install_fake_register(
        monkeypatch,
        raises=AVPServerError("server boom raw body", 500, "raw response detail"),
    )

    out = io.StringIO()
    code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    output = out.getvalue()
    assert code == 1
    assert "FAIL: registration failed at " in output
    assert "status 500" in output
    assert "server boom raw body" not in output
    assert "raw response detail" not in output
    assert secret not in output


def test_register_backend_unreachable_prints_sanitized_fail(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    _install_fake_register(
        monkeypatch,
        raises=ConnectionError("connect timeout to host"),
    )

    out = io.StringIO()
    code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    output = out.getvalue()
    assert code == 1
    assert "FAIL: backend unreachable at " in output
    assert "ConnectionError" in output
    assert "connect timeout to host" not in output
    assert secret not in output


def test_register_already_registered_returns_ok(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity_before = _load(result.identity_path)
    with _fake_avp_registration_backend(register_status=409) as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home)
        state.agents[did]["is_verified"] = True
        _set_proxy_home_base_url(home, base_url)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        output = out.getvalue()
        assert code == 0
        assert "already registered" in output

        identity_after = _load(result.identity_path)
        assert identity_after["did"] == identity_before["did"]
        assert identity_after["encrypted"] is True
        assert "private_key_hex" not in identity_after
        assert identity_after.get("registered") is True
        assert identity_after.get("verified") is True
        if os.name != "nt":
            assert _mode(result.identity_path) == 0o600


def test_register_409_unverified_does_not_mark_registered(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend(register_status=409) as (base_url, state):
        _seed_identity_on_fake_backend(state, home)
        _set_proxy_home_base_url(home, base_url)
        identity_before = _load(result.identity_path)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 1
        assert "not verified on server" in out.getvalue()
        identity_after = _load(result.identity_path)
        assert identity_after.get("registered") is not True
        assert identity_after.get("verified") is not True
        assert identity_after["did"] == identity_before["did"]


def test_register_409_malformed_is_verified_false_preserves_identity(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend(register_status=409) as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home)
        state.agents[did]["is_verified"] = True
        state.lookup_is_verified[did] = "false"
        _set_proxy_home_base_url(home, base_url)
        identity_before = _load(result.identity_path)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 1
        assert "not verified on server" in out.getvalue()
        identity_after = _load(result.identity_path)
        assert identity_after.get("registered") is not True
        assert identity_after.get("verified") is not True
        assert identity_after == identity_before


def test_register_409_mismatched_lookup_did_preserves_identity(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend(register_status=409) as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home)
        state.agents[did]["is_verified"] = True
        state.lookup_did[did] = "did:web:avp:agent:mismatch"
        _set_proxy_home_base_url(home, base_url)
        identity_before = _load(result.identity_path)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 1
        assert "not verified on server" in out.getvalue()
        identity_after = _load(result.identity_path)
        assert identity_after.get("registered") is not True
        assert identity_after.get("verified") is not True
        assert identity_after == identity_before


def test_fake_avp_registration_backend_rejects_invalid_verify_signature(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend() as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home)
        public_key_hex = state.agents[did]["public_key_hex"]
        register_payload = json.dumps({"public_key_hex": public_key_hex}).encode("utf-8")
        register_request = urllib.request.Request(  # noqa: S310
            f"{base_url}/v1/agents/register",
            data=register_payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(register_request) as response:  # noqa: S310
            register_body = json.loads(response.read().decode("utf-8"))
        challenge = register_body["challenge"]
        verify_payload = json.dumps(
            {
                "did": did,
                "challenge": challenge,
                "signature_hex": "00" * 64,
                "pow_nonce": "0",
            }
        ).encode("utf-8")
        verify_request = urllib.request.Request(  # noqa: S310
            f"{base_url}/v1/agents/verify",
            data=verify_payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(verify_request)  # noqa: S310
        assert exc_info.value.code == 400
        assert state.agents[did]["is_verified"] is False


def test_register_verify_409_unverified_does_not_mark_registered(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend(verify_status=409) as (base_url, state):
        _seed_identity_on_fake_backend(state, home)
        _set_proxy_home_base_url(home, base_url)
        identity_before = _load(result.identity_path)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 1
        assert "not verified on server" in out.getvalue()
        identity_after = _load(result.identity_path)
        assert identity_after.get("registered") is not True
        assert identity_after.get("verified") is not True
        assert identity_after["did"] == identity_before["did"]


def test_register_backend_auth_failure(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend(register_status=401) as (base_url, state):
        _seed_identity_on_fake_backend(state, home)
        _set_proxy_home_base_url(home, base_url)
        identity_before = _load(result.identity_path)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 1
        assert "status 401" in out.getvalue()
        identity_after = _load(result.identity_path)
        assert identity_after.get("registered") is not True
        assert identity_after["did"] == identity_before["did"]


def test_register_backend_unavailable(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    with _fake_avp_registration_backend(register_status=503) as (base_url, state):
        _seed_identity_on_fake_backend(state, home)
        _set_proxy_home_base_url(home, base_url)
        identity_before = _load(result.identity_path)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 1
        assert "status 503" in out.getvalue()
        identity_after = _load(result.identity_path)
        assert identity_after.get("registered") is not True
        assert identity_after["did"] == identity_before["did"]


def test_register_already_registered_json_reports_warning(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    with _fake_avp_registration_backend(register_status=409) as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home)
        state.agents[did]["is_verified"] = True
        _set_proxy_home_base_url(home, base_url)

        out = io.StringIO()
        code = register_proxy(
            home=home,
            passphrase=TEST_PASSPHRASE,
            output_json=True,
            out=out,
        )

        payload = json.loads(out.getvalue())
        assert code == 0
        assert payload["ok"] is True
        assert payload["registered"] is True
        assert payload["agent_did"] == identity["did"]
        assert payload["errors"] == []
        assert payload["warnings"] == ["agent already registered"]


def test_register_real_backend_round_trip_updates_identity(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity_before = _load(result.identity_path)
    with _fake_avp_registration_backend() as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home)
        _set_proxy_home_base_url(home, base_url)

        out = io.StringIO()
        code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

        assert code == 0
        assert state.agents[did]["is_verified"] is True
        identity_after = _load(result.identity_path)
        assert identity_after["did"] == identity_before["did"]
        assert identity_after.get("registered") is True
        assert identity_after.get("verified") is True


def test_register_encrypted_identity_requires_passphrase(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    _install_fake_register(monkeypatch)
    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)

    out = io.StringIO()
    try:
        register_proxy(home=home, out=out)
    except ProxyCliError as exc:
        assert "passphrase" in str(exc)
        assert exc.exit_code == 1
    else:
        raise AssertionError("expected register to require encrypted identity passphrase")


def test_register_does_not_downgrade_encrypted_identity_to_plaintext(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    encrypted_blob_before = _load(result.identity_path).get("encrypted_blob")
    assert encrypted_blob_before  # sanity: init produced an encrypted identity
    _install_fake_register(monkeypatch)

    register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=io.StringIO())

    identity_after = _load(result.identity_path)
    assert identity_after["encrypted"] is True
    # No plaintext private key should ever appear in the file after register.
    assert "private_key_hex" not in identity_after
    if os.name != "nt":
        assert _mode(result.identity_path) == 0o600


def test_register_wired_through_main(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    _install_fake_register(monkeypatch)

    exit_code = main([
        "register",
        "--home", str(home),
        "--passphrase", TEST_PASSPHRASE,
    ])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert "OK: agent " in out


def test_register_json_wired_through_main(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    _install_fake_register(monkeypatch)

    exit_code = main([
        "register",
        "--home", str(home),
        "--passphrase", TEST_PASSPHRASE,
        "--json",
    ])
    out, err = capsys.readouterr()

    payload = json.loads(out)
    assert exit_code == 0
    assert err == ""
    assert payload["ok"] is True
    assert payload["registered"] is True
    assert payload["agent_did"] == identity["did"]


def test_configure_downstream_writes_valid_config(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    sandbox = tmp_path / "sandbox"
    out = io.StringIO()

    configured = configure_downstream(
        home=home,
        name="filesystem",
        command=sys.executable,
        args=("-m", "agentveil_mcp_proxy.quickstart_filesystem", str(sandbox)),
        response_timeout_seconds=5.0,
        out=out,
    )

    config = _load(result.config_path)
    assert configured.downstream_name == "filesystem"
    assert config["downstream"]["command"] == sys.executable
    assert config["downstream"]["args"][-1] == str(sandbox)
    assert "OK: downstream filesystem configured" in out.getvalue()


def test_downstream_set_wired_through_main_with_json(tmp_path, capsys):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    sandbox = tmp_path / "sandbox"

    exit_code = main([
        "downstream",
        "set",
        "--home", str(home),
        "--name", "filesystem",
        "--command", sys.executable,
        "--arg", "-m",
        "--arg", "agentveil_mcp_proxy.quickstart_filesystem",
        "--arg", str(sandbox),
        "--json",
    ])
    out, err = capsys.readouterr()

    assert exit_code == 0
    assert err == ""
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert payload["downstream"]["name"] == "filesystem"
    assert payload["downstream"]["command"] == sys.executable
    assert payload["evidence_count"] == 0
    assert _load(result.config_path)["downstream"]["args"][-1] == str(sandbox)


def test_configure_downstream_rejects_avp_env(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)

    with pytest.raises(ProxyCliError, match="AVP_\\*"):
        configure_downstream(
            home=home,
            name="filesystem",
            command=sys.executable,
            env_entries=("AVP_PROXY_PASSPHRASE=secret",),
        )


def test_init_quickstart_filesystem_configures_downstream_and_filesystem_policy(tmp_path):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"

    result = init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(sandbox),
    )

    config = _load(result.config_path)
    assert sandbox.is_dir()
    assert config["policy"]["id"] == "filesystem"
    assert config["downstream"]["name"] == "filesystem"
    assert config["downstream"]["command"] == sys.executable
    assert any(str(arg).endswith("quickstart_filesystem.py") for arg in config["downstream"]["args"])


def test_doctor_full_fails_without_downstream_config(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    out = io.StringIO()

    code = doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, full=True, out=out)

    assert code == 1
    assert "downstream.command is required" in out.getvalue()


def test_doctor_full_smokes_downstream(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(tmp_path / "sandbox"),
    )
    out = io.StringIO()

    code = doctor_proxy(home=home, full=True, out=out)

    assert code == 0
    assert "OK: downstream filesystem configured" in out.getvalue()
    tool_count = _quickstart_filesystem_tool_count()
    assert (
        f"OK: downstream filesystem answered initialize/tools/list ({tool_count} tools)"
        in out.getvalue()
    )


def test_doctor_json_reports_downstream_and_evidence_count(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(tmp_path / "sandbox"),
    )
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_evidence_record("req-doctor-json"))
    out = io.StringIO()

    code = doctor_proxy(home=home, full=True, output_json=True, out=out)

    payload = json.loads(out.getvalue())
    assert code == 0
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert payload["downstream"]["name"] == "filesystem"
    assert payload["downstream"]["tool_count"] == _quickstart_filesystem_tool_count()
    assert payload["evidence_count"] == 1


def test_doctor_json_reports_missing_downstream_as_warning(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    out = io.StringIO()

    code = doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        output_json=True,
        out=out,
    )

    payload = json.loads(out.getvalue())
    assert code == 0
    assert payload["ok"] is True
    assert payload["downstream"]["configured"] is False
    assert "downstream is not configured" in payload["warnings"][0]


def test_smoke_proxy_smokes_downstream(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(tmp_path / "sandbox"),
    )
    out = io.StringIO()

    result = smoke_proxy(home=home, out=out)

    assert result.downstream_name == "filesystem"
    assert result.tool_count == _quickstart_filesystem_tool_count()
    assert "OK: downstream filesystem answered initialize/tools/list" in out.getvalue()


def test_smoke_json_reports_machine_readable_result(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(tmp_path / "sandbox"),
    )
    out = io.StringIO()

    result = smoke_proxy(home=home, output_json=True, out=out)

    payload = json.loads(out.getvalue())
    assert result.tool_count == _quickstart_filesystem_tool_count()
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert payload["downstream"]["name"] == "filesystem"
    assert payload["downstream"]["tool_count"] == _quickstart_filesystem_tool_count()
    assert payload["evidence_count"] == 0


def test_events_list_and_summary_are_privacy_safe(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_evidence_record("req-events"))

    events_out = io.StringIO()
    count = list_events(home=home, out=events_out)

    assert count == 1
    rendered = events_out.getvalue()
    assert "server=github" in rendered
    assert "tool=create_issue" in rendered
    assert "risk=write" in rendered
    assert "receipt=present" in rendered
    assert "id=req-events" in rendered
    assert "b" * 64 not in rendered

    summary_out = io.StringIO()
    summary = evidence_summary(home=home, out=summary_out)
    rendered_summary = summary_out.getvalue()
    assert summary["record_count"] == 1
    assert summary["receipt_present_count"] == 1
    assert summary["records"][0]["request_id"] == "req-events"
    if summary["downstream"].get("configured"):
        assert summary["downstream"]["command_ref"]
        assert summary["downstream"]["command_basename"]
        assert "command" not in summary["downstream"]
        assert "args" not in summary["downstream"]
    else:
        assert summary["downstream"] == {"configured": False}
    assert "/tmp/" not in rendered_summary


def test_events_list_json_is_machine_readable_and_privacy_safe(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=True,
        policy_pack="filesystem",
        downstream_config=quickstart_filesystem_downstream(tmp_path / "sandbox"),
    )
    paths = proxy_paths(home)
    with ApprovalEvidenceStore(paths.proxy_dir / "evidence.sqlite") as store:
        store.write_pending(_evidence_record("req-events-json"))

    events_out = io.StringIO()
    count = list_events(home=home, output_json=True, out=events_out)

    payload = json.loads(events_out.getvalue())
    assert count == 1
    assert payload["ok"] is True
    assert payload["evidence_count"] == 1
    assert payload["downstream"]["downstream_kind"] == "filesystem"
    assert payload["downstream"]["command_ref"]
    assert payload["downstream"]["command_basename"]
    assert "command" not in payload["downstream"]
    assert "args" not in payload["downstream"]
    assert payload["events"] == [{
        "timestamp": "2023-11-14T22:13:20Z",
        "server": "github",
        "tool": "create_issue",
        "risk_class": "write",
        "status": "pending",
        "policy_rule": "rule-write",
        "receipt": "present",
        "record_id": "req-events-json",
    }]
    assert "b" * 64 not in events_out.getvalue()


def test_main_init_quickstart_filesystem_without_role_uses_safe_autopilot(tmp_path, capsys):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"

    assert main([
        "init",
        "--quickstart-filesystem", str(sandbox),
        "--home", str(home),
        "--agent-name", "proxy",
        "--plaintext",
        "--json",
    ]) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    config = _load(proxy_paths(home).config_path)
    assert payload["setup_profile"] == "safe_autopilot"
    # claim-check: allow product label; this test verifies bounded first-run output.
    assert payload["setup_label"] == "Safe Autopilot"
    assert config["setup_profile"] == "safe_autopilot"
    assert config["role_preset"] == "reviewer"
    assert config["policy"]["id"] == "filesystem"
    assert sandbox.is_dir()
    assert "identity_path" not in payload
    assert payload["identity_ref"]["basename"] == "proxy.json"
    serialized = captured.out
    assert "/private/" not in serialized
    assert "/var/folders/" not in serialized
    assert "/Users/" not in serialized
    assert str(home) not in serialized


def test_main_init_explicit_reviewer_quickstart_persists_advanced_role_and_blocks_write(
    tmp_path,
    monkeypatch,
    capsys,
):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"

    assert main([
        "init",
        "--quickstart-filesystem", str(sandbox),
        "--role", "reviewer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--plaintext",
        "--json",
    ]) == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    config = _load(proxy_paths(home).config_path)
    assert payload["setup_profile"] == "advanced_role"
    assert config["setup_profile"] == "advanced_role"
    assert config["role_preset"] == "reviewer"

    class ExplodingAgent:
        def __init__(self, *args, **kwargs):
            raise AssertionError("reviewer quickstart must not construct AVPAgent")

    monkeypatch.setattr(proxy_cli, "AVPAgent", ExplodingAgent)
    client_out = io.StringIO()
    write_call = json.dumps({
        "jsonrpc": "2.0",
        "id": "write-1",
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "probe.txt", "content": "x"}},
    }) + "\n"
    assert run_proxy(
        home=home,
        client_in=io.StringIO(write_call),
        out=client_out,
        approval_ui_mode="none",
    ) == 0
    response = json.loads(client_out.getvalue().strip().splitlines()[-1])
    assert response["error"]["data"]["reason"] == "role_authority_denied"
    assert not (sandbox / "probe.txt").exists()


def test_main_init_quickstart_filesystem_human_output_is_privacy_bounded(tmp_path, capsys):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"

    assert main([
        "init",
        "--quickstart-filesystem", str(sandbox),
        "--home", str(home),
        "--agent-name", "proxy",
        "--plaintext",
    ]) == 0

    out = capsys.readouterr().out
    # claim-check: allow product label; this test rejects role-choice wording.
    assert "Safe Autopilot" in out
    assert "/private/" not in out
    assert "/var/folders/" not in out
    assert "/Users/" not in out
    assert str(home) not in out
    assert "proxy.json" in out


def test_main_init_json_supports_noninteractive_downstream_flags(tmp_path, capsys):
    home = tmp_path / "avp-home"
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    sandbox = tmp_path / "sandbox"

    exit_code = main([
        "init",
        "--role", "implementer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--passphrase-file", str(passphrase_file),
        "--policy-pack", "filesystem",
        "--downstream-name", "filesystem",
        "--downstream-command", sys.executable,
        "--downstream-arg", "-m",
        "--downstream-arg", "agentveil_mcp_proxy.quickstart_filesystem",
        "--downstream-arg", str(sandbox),
        "--json",
    ])
    out, err = capsys.readouterr()

    payload = json.loads(out)
    assert exit_code == 0
    assert err == ""
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert payload["downstream"]["name"] == "filesystem"
    assert payload["evidence_count"] == 0
    config_payload = _load(proxy_paths(home).config_path)
    assert config_payload["downstream"]["args"][-1] == str(sandbox)
    assert config_payload["identity_passphrase_file"] == str(passphrase_file)


def test_client_config_infers_stored_passphrase_file_for_encrypted_quickstart(tmp_path, capsys):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o600)

    assert main([
        "init",
        "--quickstart-filesystem", str(sandbox),
        "--home", str(home),
        "--passphrase-file", str(passphrase_file),
        "--json",
    ]) == 0
    capsys.readouterr()

    assert main([
        "client-config",
        "print",
        "--home", str(home),
        "--client", "cursor",
        "--json",
    ]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    entry = payload["clients"]["cursor"]["local_client_config"]["mcpServers"]["agentveil-mcp-proxy"]
    assert "--passphrase-file" in entry["args"]
    flag_index = entry["args"].index("--passphrase-file")
    assert entry["args"][flag_index + 1] == str(passphrase_file)
    assert TEST_PASSPHRASE not in captured.out


def test_doctor_infers_stored_passphrase_file_for_encrypted_quickstart(tmp_path, capsys):
    home = tmp_path / "avp-home"
    sandbox = tmp_path / "sandbox"
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o600)

    assert main([
        "init",
        "--quickstart-filesystem", str(sandbox),
        "--home", str(home),
        "--passphrase-file", str(passphrase_file),
        "--json",
    ]) == 0
    capsys.readouterr()

    assert main(["doctor", "--home", str(home), "--full", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["errors"] == []


def test_main_init_policy_pack_git_writes_git_policy_id(tmp_path):
    # Real product path (Bug 1 follow-up): the git pack must be reachable through
    # the CLI argv parser, not only via builtin_policy_pack("git").
    home = tmp_path / "avp-home"

    exit_code = main([
        "init",
        "--role", "implementer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--policy-pack", "git",
        "--plaintext",
    ])

    assert exit_code == 0
    assert _load(proxy_paths(home).config_path)["policy"]["id"] == "git"


def test_configure_downstream_named_git_preserves_explicit_git_policy(tmp_path):
    # configure-downstream writes only the downstream block; it does not infer or
    # override the policy pack from the downstream name. The git policy chosen at
    # init survives, confirming explicit --policy-pack git is the supported path
    # (the product has no name-based auto-policy-selection for any pack).
    home = tmp_path / "avp-home"
    assert main([
        "init",
        "--role", "implementer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--policy-pack", "git",
        "--plaintext",
    ]) == 0

    result = configure_downstream(
        name="git",
        command=sys.executable,
        args=("-m", "example_git_mcp_server"),
        home=home,
    )

    config = _load(result.config_path)
    assert config["policy"]["id"] == "git"
    assert config["downstream"]["name"] == "git"


def test_main_init_policy_pack_fetch_writes_fetch_policy_id(tmp_path):
    # Real product path (Bug 2 follow-up): the fetch pack must be reachable
    # through the CLI argv parser, not only via builtin_policy_pack("fetch").
    home = tmp_path / "avp-home"

    exit_code = main([
        "init",
        "--role", "implementer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--policy-pack", "fetch",
        "--plaintext",
    ])

    assert exit_code == 0
    assert _load(proxy_paths(home).config_path)["policy"]["id"] == "fetch"


def test_configure_downstream_named_fetch_preserves_explicit_fetch_policy(tmp_path):
    # configure-downstream writes only the downstream block; it does not infer or
    # override the policy pack from the downstream name. The fetch policy chosen
    # at init survives, confirming explicit --policy-pack fetch is the supported
    # path (the product has no name-based auto-policy-selection for any pack).
    home = tmp_path / "avp-home"
    assert main([
        "init",
        "--role", "implementer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--policy-pack", "fetch",
        "--plaintext",
    ]) == 0

    result = configure_downstream(
        name="fetch",
        command=sys.executable,
        args=("-m", "example_fetch_mcp_server"),
        home=home,
    )

    config = _load(result.config_path)
    assert config["policy"]["id"] == "fetch"
    assert config["downstream"]["name"] == "fetch"


def test_main_init_policy_pack_package_json_writes_package_policy_and_downstream(tmp_path, capsys):
    home = tmp_path / "avp-home"
    downstream_script = tmp_path / "package_downstream.py"
    project_root = tmp_path / "project"
    target_venv = tmp_path / "target-venv"
    project_root.mkdir()
    target_venv.mkdir()
    downstream_script.write_text("print('stub')\n", encoding="utf-8")

    exit_code = main([
        "init",
        "--role", "implementer",
        "--home", str(home),
        "--agent-name", "proxy",
        "--policy-pack", "package",
        "--downstream-name", "package",
        "--downstream-command", sys.executable,
        "--downstream-arg", str(downstream_script),
        "--downstream-arg", str(project_root),
        "--downstream-arg", str(target_venv),
        "--plaintext",
        "--json",
    ])
    out, err = capsys.readouterr()

    assert exit_code == 0
    assert err == ""
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert payload["downstream"]["name"] == "package"
    config_payload = _load(proxy_paths(home).config_path)
    assert config_payload["policy"]["id"] == "package"
    assert config_payload["downstream"]["args"] == [
        str(downstream_script),
        str(project_root),
        str(target_venv),
    ]


def test_reissue_grant_creates_new_grant_with_default_ttl(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    old_grant = _replace_grant(result, valid_for=timedelta(hours=1))
    out = io.StringIO()

    reissued = reissue_grant(home=home, passphrase=TEST_PASSPHRASE, out=out)

    new_grant = _load(result.control_grant_path)
    assert new_grant["id"] != old_grant["id"]
    verified = verify_delegation(new_grant)
    assert verified["issuer"] == result.agent_did
    assert verified["subject"] == result.agent_did
    ttl_seconds = (verified["valid_until"] - datetime.now(timezone.utc)).total_seconds()
    assert 29 * 24 * 60 * 60 < ttl_seconds <= 30 * 24 * 60 * 60
    assert reissued.control_grant_expires_at in out.getvalue()
    assert secret not in out.getvalue()


def test_reissue_grant_refuses_without_force_when_existing_grant_has_more_than_24h(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))

    try:
        reissue_grant(home=home, passphrase=TEST_PASSPHRASE, out=io.StringIO())
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "more than 24 hours remaining" in str(exc)
        assert secret not in str(exc)
    else:
        raise AssertionError("expected reissue-grant to require --force")


def test_reissue_grant_with_force_replaces_grant(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    old_grant = _load(result.control_grant_path)
    out = io.StringIO()

    reissue_grant(home=home, passphrase=TEST_PASSPHRASE, force=True, out=out)

    new_grant = _load(result.control_grant_path)
    assert new_grant["id"] != old_grant["id"]
    assert verify_delegation(new_grant)["subject"] == result.agent_did
    assert secret not in out.getvalue()


def test_reissue_grant_uses_passphrase_for_encrypted_identity(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    secret = _secret_material(_load(result.identity_path))
    monkeypatch.setenv("AVP_PROXY_PASSPHRASE", TEST_PASSPHRASE)

    out = io.StringIO()
    assert reissue_grant(home=home, force=True, out=out).agent_name == "proxy"
    assert secret not in out.getvalue()

    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)
    class NonTTY(io.StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr("sys.stdin", NonTTY(""))
    try:
        reissue_grant(home=home, force=True, out=io.StringIO())
    except ProxyCliError as exc:
        assert "encrypted identity passphrase required" in str(exc)
        assert secret not in str(exc)
    else:
        raise AssertionError("expected reissue-grant to require passphrase")


def test_main_init_doctor_and_run_exit_codes(tmp_path, capsys):
    home = tmp_path / "avp-home"

    assert main([
        "init",
        "--role", "implementer",
        "--home",
        str(home),
        "--agent-name",
        "proxy",
        "--passphrase",
        TEST_PASSPHRASE,
    ]) == 0
    created = capsys.readouterr()
    assert "Created protected agent connection:" in created.out
    secret = _secret_material(_load(proxy_paths(home).identity_path("proxy")))
    assert secret not in created.out

    assert main(["doctor", "--home", str(home), "--passphrase", TEST_PASSPHRASE]) == 0
    doctor = capsys.readouterr()
    assert "OK: trusted signers" in doctor.out
    assert secret not in doctor.out

    assert main(["run", "--home", str(home), "--passphrase", TEST_PASSPHRASE]) == 1
    run = capsys.readouterr()
    assert run.out == ""
    assert "downstream.command" in run.err
    assert secret not in run.out
    assert secret not in run.err


def test_setup_cli_run_status_and_restore(tmp_path, capsys):
    home = tmp_path / "setup-home"
    proxy_command = tmp_path / "agentveil-mcp-proxy"
    proxy_command.write_text("", encoding="utf-8")
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps([
            {"tool_name": "read_file", "server_label": "filesystem", "capabilities": ["read"]},
            {"tool_name": "git_status", "server_label": "git", "capabilities": ["read"]},
        ]),
        encoding="utf-8",
    )

    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "review",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    run_payload = json.loads(capsys.readouterr().out)
    assert run_payload["setup_status"] == "protected"
    assert run_payload["proxy_config_written"] is True
    assert run_payload["summary"]["role_preset"] == "reviewer"

    first_proxy = (home / "mcp-proxy" / "config.json").read_bytes()
    assert main([
        "setup",
        "run",
        "--home",
        str(home),
        "--inventory",
        str(inventory_path),
        "--mode",
        "build",
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    capsys.readouterr()
    assert (home / "mcp-proxy" / "config.json").read_bytes() != first_proxy

    assert main([
        "setup",
        "status",
        "--home",
        str(home),
        "--proxy-command",
        str(proxy_command),
        "--json",
    ]) == 0
    status_payload = json.loads(capsys.readouterr().out)
    assert status_payload["setup_status"] == "protected"

    assert main([
        "setup",
        "restore",
        "--home",
        str(home),
        "--target",
        # claim-check: allow "all" is a restore target enum value, not a coverage claim.
        "all",
        "--json",
    ]) == 0
    restore_payload = json.loads(capsys.readouterr().out)
    assert restore_payload["ok"] is True
    assert restore_payload["restored_targets"] == ["proxy", "client"]
    assert (home / "mcp-proxy" / "config.json").read_bytes() == first_proxy
    restore_text = json.dumps(restore_payload)
    assert str(home) not in restore_text
    assert "/private/" not in restore_text
    assert "/var/folders/" not in restore_text
    assert "/Users/" not in restore_text


# ----- P10D.14 S2: Claude hook install/status/uninstall CLI dispatch --------


def test_cli_install_claude_hook_preview_does_not_write(tmp_path, capsys):
    assert main([
        "install-claude-hook", "--project", "--project-dir", str(tmp_path),
    ]) == 0
    capsys.readouterr()
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_cli_install_status_uninstall_dispatch_roundtrip(tmp_path, capsys):
    # install --yes --json
    assert main([
        "install-claude-hook", "--project", "--project-dir", str(tmp_path), "--yes", "--json",
    ]) == 0
    install_payload = json.loads(capsys.readouterr().out)
    assert install_payload["ok"] is True
    assert install_payload["applied"] is True
    settings = tmp_path / ".claude" / "settings.json"
    assert settings.exists()

    # status --json -> advisory (installed, no firing evidence yet), bounded
    assert main([
        "status-claude-hook", "--project", "--project-dir", str(tmp_path), "--json",
    ]) == 0
    status_payload = json.loads(capsys.readouterr().out)
    assert status_payload["status"] == "advisory"
    assert status_payload["state"] == "installed"
    assert status_payload["reload_required"] is True
    status_text = json.dumps(status_payload)
    assert str(tmp_path) not in status_text
    assert "/Users/" not in status_text and "/private/" not in status_text

    # uninstall --yes --json
    assert main([
        "uninstall-claude-hook", "--project", "--project-dir", str(tmp_path), "--yes", "--json",
    ]) == 0
    uninstall_payload = json.loads(capsys.readouterr().out)
    assert uninstall_payload["ok"] is True
    assert uninstall_payload["removed_entries"] == 1


def test_cli_status_missing_is_unsafe(tmp_path, capsys):
    assert main([
        "status-claude-hook", "--project", "--project-dir", str(tmp_path), "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "unsafe"
    assert payload["state"] == "missing"


def test_cli_install_claude_hook_requires_project_flag(tmp_path):
    # --project is required; omitting it is an argparse error (SystemExit).
    with pytest.raises(SystemExit):
        main(["install-claude-hook", "--project-dir", str(tmp_path), "--yes"])


def test_cli_status_claude_hook_requires_project_flag(tmp_path):
    with pytest.raises(SystemExit):
        main(["status-claude-hook", "--project-dir", str(tmp_path), "--json"])


# ----- P10D.14 S5: one-command Claude connector setup CLI --------------------


def test_cli_setup_status_bare_is_connector(tmp_path, capsys):
    assert main(["setup", "status", "--project-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    # connector-shaped keys
    assert payload["status"] == "unsafe"
    assert payload["hook"] == "missing"
    assert payload["mcp_route"] == "missing"
    assert "next_step" in payload
    assert payload["trust_boundary"]["host_wide_control_claim"] is False
    assert payload["trust_boundary"]["hook_coverage"] == "missing"


def test_cli_setup_status_home_routes_to_wizard(tmp_path, capsys):
    # --home routes to the adaptive wizard, NOT the connector status.
    home = tmp_path / "avp-home"
    home.mkdir()
    main(["setup", "status", "--home", str(home), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    # wizard output must not carry the connector-only keys
    assert "mcp_route" not in payload
    assert "hook" not in payload or "next_step" not in payload
    assert payload["trust_boundary"]["hook_coverage"] == "not reported"


def test_cli_setup_status_client_codex_includes_trust_boundary(
    tmp_path,
    monkeypatch,
    capsys,
):
    from agentveil_mcp_proxy import codex_setup

    monkeypatch.setattr(
        codex_setup,
        "connector_status",
        lambda **_kwargs: {
            "status": "advisory",
            "hook": "installed",
            "hook_state": "installed",
            "mcp_route": "present",
            "proxy_route": "present",
            "approval_center": "running",
        },
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
        lambda _home: SimpleNamespace(state="running", pid=123, port=8765),
    )

    assert main([
        "setup",
        "status",
        "--client",
        "codex",
        "--project-dir",
        str(tmp_path),
        "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["trust_boundary"]["host_wide_control_claim"] is False
    assert payload["trust_boundary"]["hook_coverage"] == "installed"


def test_cli_setup_claude_code_preview_does_not_write(tmp_path, capsys):
    assert main(["setup", "claude-code", "--project-dir", str(tmp_path)]) == 0
    capsys.readouterr()
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert not (tmp_path / ".mcp.json").exists()


def test_choose_setup_project_folder_macos(monkeypatch, tmp_path):
    selected = tmp_path / "Selected Project"
    selected.mkdir()

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"{selected}\n",
            stderr="",
        ),
    )

    assert proxy_cli._choose_setup_project_folder() == selected


def test_cli_setup_claude_code_rejects_choose_folder_with_project_dir(tmp_path, capsys):
    rc = main([
        "setup", "claude-code",
        "--choose-folder",
        "--project-dir", str(tmp_path),
        "--yes",
    ])

    assert rc == 2
    assert "cannot be combined" in capsys.readouterr().err


def test_cli_setup_remove_claude_code_apply(tmp_path, capsys):
    from agentveil_mcp_proxy import claude_hook_setup
    # seed an installed hook + an .mcp.json with agentveil + an unrelated server
    claude_hook_setup.install_hook(tmp_path)
    (tmp_path / ".mcp.json").write_text(json.dumps({
        "mcpServers": {
            "agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy", "args": ["run"]},
            "other-server": {"command": "other"},
        }
    }), encoding="utf-8")

    assert main(["setup", "remove", "claude-code", "--project-dir", str(tmp_path), "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["hook_entries_removed"] == 1
    assert payload["mcp_route_removed"] is True

    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    for entry in pre:
        assert "agentveil_mcp_proxy.claude_hook" not in json.dumps(entry)
    mcp = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert "agentveil-mcp-proxy" not in mcp.get("mcpServers", {})
    assert "other-server" in mcp.get("mcpServers", {}), "unrelated MCP server must survive"


def test_cli_setup_status_bounded_no_paths(tmp_path, capsys):
    from agentveil_mcp_proxy import claude_hook_setup
    claude_hook_setup.install_hook(tmp_path)
    assert main(["setup", "status", "--project-dir", str(tmp_path), "--json"]) == 0
    text = capsys.readouterr().out
    assert str(tmp_path) not in text
    assert "/Users/" not in text and "/private/" not in text


def test_cli_setup_claude_code_starts_center_with_passphrase_without_url_leak(
    tmp_path,
    monkeypatch,
    capsys,
):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    seen: dict[str, object] = {}

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        _stub_project_proxy_home(home)
        seen["init_plaintext"] = kwargs["plaintext"]
        seen["init_passphrase_file"] = kwargs["passphrase_file"]
        seen["policy_pack"] = kwargs.get("policy_pack")
        seen["downstream_root"] = kwargs["downstream_config"]["args"][-1]

    def fake_connect(**kwargs):
        project = kwargs["project_root"]
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy"}}}),
            encoding="utf-8",
        )
        return 0

    def fake_ensure_running(**kwargs):
        seen["center_passphrase_file"] = kwargs["passphrase_file"]
        return SimpleNamespace(
            status=SimpleNamespace(
                state="running",
                url="http://127.0.0.1:12345/approval/SECRET_TOKEN",
            ),
            started=True,
            reused=False,
            restarted=False,
        )

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "run_connect_cli", fake_connect)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        fake_ensure_running,
    )

    rc = main([
        "setup", "claude-code",
        "--project-dir", str(tmp_path),
        "--passphrase-file", str(passphrase_file),
        "--yes",
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["approval_center"]["state"] == "running"
    assert "url" not in payload["approval_center"]
    assert "SECRET_TOKEN" not in json.dumps(payload)
    assert payload["identity_encrypted"] is True
    assert seen["init_plaintext"] is False
    assert seen["policy_pack"] == "filesystem"
    assert seen["init_passphrase_file"] == passphrase_file
    assert seen["center_passphrase_file"] == passphrase_file
    assert seen["downstream_root"] == str(tmp_path.resolve())
    config = json.loads((tmp_path / ".avp" / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    assert config["approval"]["ui_open_mode"] == "terminal"
    assert config["approval"]["wait_for_decision"] is True


def test_cli_setup_claude_code_choose_folder_uses_selected_project(
    tmp_path,
    monkeypatch,
    capsys,
):
    selected = tmp_path / "Selected Project"
    selected.mkdir()
    seen: dict[str, object] = {}

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        _stub_project_proxy_home(home)
        seen["home"] = home
        seen["downstream_root"] = kwargs["downstream_config"]["args"][-1]

    def fake_connect(**kwargs):
        project = kwargs["project_root"]
        seen["project_root"] = project
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy"}}}),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", lambda: selected)
    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "run_connect_cli", fake_connect)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        lambda **_kwargs: SimpleNamespace(
            status=SimpleNamespace(state="running", url="http://127.0.0.1/approval/SECRET"),
            started=True,
            reused=False,
            restarted=False,
        ),
    )

    rc = main(["setup", "claude-code", "--choose-folder", "--yes", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert seen["project_root"] == selected.resolve()
    assert seen["home"] == selected.resolve() / ".avp"
    assert seen["downstream_root"] == str(selected.resolve())
    config = json.loads((selected / ".avp" / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    assert config["approval"]["wait_for_decision"] is True


def _assert_setup_enables_approval_wait_mode(
    project_dir: Path,
    *,
    home_relpath: str = ".avp",
) -> None:
    config_path = project_dir / home_relpath / "mcp-proxy" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["approval"]["wait_for_decision"] is True


def _fake_running_approval_center(**_kwargs):
    return SimpleNamespace(
        status=SimpleNamespace(state="running"),
        started=True,
        reused=False,
        restarted=False,
    )


def test_cli_setup_gemini_cli_enables_approval_wait_mode(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import gemini_setup

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        _stub_project_proxy_home(home)

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "run_connect_cli", lambda **_kwargs: 0)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(gemini_setup, "validate_hook_config", lambda **_kwargs: None)
    monkeypatch.setattr(
        gemini_setup,
        "install_hook",
        lambda **_kwargs: SimpleNamespace(applied=True),
    )
    monkeypatch.setattr(
        gemini_setup,
        "connect_status",
        lambda **_kwargs: {"config_ref": "gemini"},
    )
    monkeypatch.setattr(gemini_setup, "managed_route_present", lambda _status: True)
    monkeypatch.setattr(gemini_setup, "connector_status", lambda **_kwargs: {"ok": True})
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        _fake_running_approval_center,
    )

    rc = main(["setup", "gemini-cli", "--project-dir", str(tmp_path), "--yes", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    _assert_setup_enables_approval_wait_mode(tmp_path)


def test_cli_setup_codex_enables_approval_wait_mode(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import codex_setup

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        _stub_project_proxy_home(home)

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "run_connect_cli", lambda **_kwargs: 0)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(codex_setup, "validate_hook_config", lambda **_kwargs: None)
    monkeypatch.setattr(
        codex_setup,
        "install_hook",
        lambda **_kwargs: SimpleNamespace(applied=True),
    )
    monkeypatch.setattr(
        codex_setup,
        "connect_status",
        lambda **_kwargs: {"config_ref": "codex"},
    )
    monkeypatch.setattr(codex_setup, "managed_route_present", lambda _status: True)
    monkeypatch.setattr(codex_setup, "connector_status", lambda **_kwargs: {"ok": True})
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        _fake_running_approval_center,
    )

    rc = main(["setup", "codex", "--project-dir", str(tmp_path), "--yes", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    _assert_setup_enables_approval_wait_mode(tmp_path)


def test_cli_setup_cursor_enables_approval_wait_mode(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import cursor_setup

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        _stub_project_proxy_home(home)

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
    monkeypatch.setattr(
        proxy_cli,
        "build_product_route_downstream_config",
        lambda _prof: {"command": sys.executable, "args": ["downstream.py"]},
    )
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(cursor_setup, "prepare_proxy_home", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cursor_setup, "profile_root", lambda home: home / "profiles" / "product_route")
    monkeypatch.setattr(cursor_setup, "proxy_config_path", lambda home: home / "mcp-proxy" / "config.json")
    monkeypatch.setattr(cursor_setup, "passphrase_path", lambda home: home / "identity.passphrase")
    monkeypatch.setattr(
        cursor_setup,
        "neutralize_competing_global_route",
        lambda *_args, **_kwargs: SimpleNamespace(changed=False),
    )
    monkeypatch.setattr(cursor_setup, "install_mcp_route", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        cursor_setup,
        "install_hooks",
        lambda *_args, **_kwargs: SimpleNamespace(created_hooks=["beforeSubmitPrompt"]),
    )
    monkeypatch.setattr(
        cursor_setup,
        "ensure_approval_center_running",
        _fake_running_approval_center,
    )
    monkeypatch.setattr(cursor_setup, "connector_status", lambda *_args, **_kwargs: {"ok": True})

    rc = main(["setup", "cursor", "--workspace", str(tmp_path), "--yes", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    _assert_setup_enables_approval_wait_mode(tmp_path, home_relpath=".agentveil")


def test_cli_setup_claude_code_fails_when_center_not_running(
    tmp_path,
    monkeypatch,
    capsys,
):
    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        _stub_project_proxy_home(home)

    def fake_connect(**kwargs):
        project = kwargs["project_root"]
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"agentveil-mcp-proxy": {"command": "agentveil-mcp-proxy"}}}),
            encoding="utf-8",
        )
        return 0

    def fake_ensure_running(**_kwargs):
        return SimpleNamespace(
            status=SimpleNamespace(state="stale", url=None),
            started=False,
            reused=False,
            restarted=False,
            reason="approval-center did not become healthy",
        )

    monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
    monkeypatch.setattr(proxy_cli, "run_connect_cli", fake_connect)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        fake_ensure_running,
    )

    rc = main(["setup", "claude-code", "--project-dir", str(tmp_path), "--yes", "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["approval_center"]["state"] == "stale"
    assert "not ready/protected" in payload["errors"][0]


def test_claude_center_stop_does_not_kill_unhealthy_manifest(tmp_path, monkeypatch):
    from agentveil_mcp_proxy import claude_center_lifecycle
    from agentveil_mcp_proxy.approval.persistent import (
        ApprovalCenterManifest,
        save_manifest,
        token_hash_for,
    )

    proxy_dir = tmp_path / ".avp" / "mcp-proxy"
    token = "session-token"
    save_manifest(
        proxy_dir,
        ApprovalCenterManifest(
            schema_version=2,
            host="127.0.0.1",
            port=43210,
            session_token=token,
            token_hash=token_hash_for(token),
            internal_register_token="internal",
            pid=12345,
            started_at=1,
        ),
    )
    monkeypatch.setattr(claude_center_lifecycle, "is_process_alive", lambda _pid: True)
    monkeypatch.setattr(claude_center_lifecycle, "_center_health", lambda _manifest: False)

    def fail_kill(_pid, _signal):
        raise AssertionError("must not kill an unhealthy/non-AgentVeil manifest pid")

    monkeypatch.setattr(os, "kill", fail_kill)
    result = claude_center_lifecycle.stop_if_managed(tmp_path / ".avp")
    assert result["stopped"] is False
    assert "not a healthy AgentVeil Approval Center" in result["reason"]


def test_claude_center_health_uses_approval_center_page(tmp_path, monkeypatch):
    from agentveil_mcp_proxy import claude_center_lifecycle
    from agentveil_mcp_proxy.approval.persistent import (
        ApprovalCenterManifest,
        token_hash_for,
    )

    token = "session-token"
    manifest = ApprovalCenterManifest(
        schema_version=2,
        host="127.0.0.1",
        port=43210,
        session_token=token,
        token_hash=token_hash_for(token),
        internal_register_token="internal",
        pid=12345,
        started_at=1,
    )
    seen_urls: list[str] = []

    def fake_status(url: str, *, timeout: float) -> int:
        del timeout
        seen_urls.append(url)
        return 200 if url == manifest.approval_center_url() else 403

    monkeypatch.setattr(claude_center_lifecycle, "loopback_get_status", fake_status)

    assert claude_center_lifecycle._center_health(manifest)
    assert seen_urls == [manifest.approval_center_url()]


def test_claude_center_status_uses_loopback_not_pid_probe(tmp_path, monkeypatch):
    from agentveil_mcp_proxy import claude_center_lifecycle
    from agentveil_mcp_proxy.approval.persistent import (
        ApprovalCenterManifest,
        save_manifest,
        token_hash_for,
    )

    token = "session-token"
    manifest = ApprovalCenterManifest(
        schema_version=2,
        host="127.0.0.1",
        port=43210,
        session_token=token,
        token_hash=token_hash_for(token),
        internal_register_token="internal",
        pid=12345,
        started_at=1,
    )
    save_manifest(tmp_path / ".avp" / "mcp-proxy", manifest)
    monkeypatch.setattr(claude_center_lifecycle, "is_process_alive", lambda _pid: False)
    monkeypatch.setattr(claude_center_lifecycle, "_center_health", lambda _manifest: True)

    status = claude_center_lifecycle.check_status(tmp_path / ".avp")

    assert status.state == "running"
    assert status.port == 43210


def test_setup_proxy_command_falls_back_to_invoked_console_script(tmp_path, monkeypatch):
    script = tmp_path / "agentveil-mcp-proxy"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(sys, "argv", [str(script), "setup", "claude-code"])

    assert proxy_cli._resolve_setup_proxy_command() == str(script.resolve())


def test_setup_proxy_command_prefers_invoked_script_over_path(tmp_path, monkeypatch):
    invoked = tmp_path / "venv" / "bin" / "agentveil-mcp-proxy"
    invoked.parent.mkdir(parents=True)
    invoked.write_text("#!/bin/sh\n", encoding="utf-8")
    global_script = tmp_path / "global" / "agentveil-mcp-proxy"
    global_script.parent.mkdir()
    global_script.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda _name: str(global_script))
    monkeypatch.setattr(sys, "argv", [str(invoked), "setup", "claude-code"])

    assert proxy_cli._resolve_setup_proxy_command() == str(invoked.resolve())


# ----- P0.12: Managed Agent Runtime Profiles ----------------------------------


def test_cli_launch_rejects_missing_profile(tmp_path, capsys):
    rc = main([
        "launch",
        "--project-dir",
        str(tmp_path),
        "--",
        sys.executable,
        "-c",
        "print(1)",
    ])
    assert rc == 2
    assert "profile" in capsys.readouterr().err.lower()


def test_cli_launch_status_bounded_without_paths(tmp_path, capsys):
    rc = main(["launch", "status", "--project-dir", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile_id"] == "generic-process"
    assert payload["host_wide_control_claim"] is False
    assert payload["protection_mode"] == "not protected"
    assert payload["mcp_route_state"] == "missing"
    assert payload["proof_hint"] == ""
    assert payload["trust_boundary"]["host_wide_control_claim"] is False
    assert "Protection scope: project MCP route, not host-wide" not in json.dumps(payload)
    assert str(tmp_path) not in json.dumps(payload)


def test_cli_launch_status_human_includes_trust_boundary_scope_line(tmp_path, capsys):
    rc = main(["launch", "status", "--project-dir", str(tmp_path)])
    assert rc == 0
    text = capsys.readouterr().out
    assert "Protection scope: project MCP route, not host-wide" in text
    assert text.count("Protection scope: project MCP route, not host-wide") == 1


def test_cli_launch_doctor_requires_profile(tmp_path, capsys):
    rc = main(["launch", "doctor", "--project-dir", str(tmp_path)])
    assert rc == 2
    assert "profile" in capsys.readouterr().err.lower()


def test_cli_launch_doctor_empty_project_json(tmp_path, capsys):
    rc = main([
        "launch",
        "doctor",
        "--profile",
        "generic-process",
        "--project-dir",
        str(tmp_path),
        "--json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["action"] == "launch-doctor"
    assert payload["project_route"] == "missing"
    assert payload["local_proof"] == "not initialized"
    assert payload["ready"] is False
    assert payload["provider_key"] == "not applicable"
    assert payload["trust_boundary"]["host_wide_control_claim"] is False
    assert str(tmp_path) not in json.dumps(payload)


def test_cli_launch_doctor_is_read_only(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import agent_launcher

    called = {"launch": False, "center": False, "init_defaults": False}

    def fake_launch(**_kwargs):
        called["launch"] = True
        raise AssertionError("launch_managed_process must not run for doctor")

    def fake_center(**_kwargs):
        called["center"] = True
        raise AssertionError("ensure_approval_center_running must not run for doctor")

    def fake_defaults(_path):
        called["init_defaults"] = True
        raise AssertionError("ensure_interactive_connector_defaults must not run for doctor")

    monkeypatch.setattr(agent_launcher, "launch_managed_process", fake_launch)
    monkeypatch.setattr(agent_launcher, "ensure_approval_center_running", fake_center)
    monkeypatch.setattr(agent_launcher, "ensure_interactive_connector_defaults", fake_defaults)

    rc = main([
        "launch",
        "doctor",
        "--profile",
        "hermes-cli",
        "--project-dir",
        str(tmp_path),
    ])
    assert rc == 0
    assert called == {"launch": False, "center": False, "init_defaults": False}
    text = capsys.readouterr().out
    assert "AgentVeil launcher doctor" in text
    assert "Provider key:" in text
    assert "Protection scope: project MCP route, not host-wide" in text


def test_cli_launch_status_reports_hermes_cli_from_manifest(tmp_path, capsys, monkeypatch):
    from agentveil_mcp_proxy.agent_launcher import (
        LAUNCH_MANIFEST_SCHEMA_VERSION,
        LaunchManifest,
        project_avp_home,
        save_launch_manifest,
    )

    project = tmp_path / "project"
    project.mkdir()
    home = project_avp_home(project)
    (home / "mcp-proxy").mkdir(parents=True)
    (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
    save_launch_manifest(
        home,
        LaunchManifest(
            schema_version=LAUNCH_MANIFEST_SCHEMA_VERSION,
            profile_id="hermes-cli",
            session_id="session-cli-status",
            child_pid=None,
            child_argv0="hermes",
            child_command_ref="hermes chat -q hello",
            started_at=1,
            project_dir_ref="project",
        ),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.check_approval_center_status",
        lambda _home: SimpleNamespace(state="running", pid=111, port=8765),
    )

    rc = main(["launch", "status", "--project-dir", str(project), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile_id"] == "hermes-cli"


def test_cli_launch_preflight_fail_closed(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import agent_launcher

    project = tmp_path / "project"
    project.mkdir()

    def fake_launch(**kwargs):
        raise agent_launcher.AgentLauncherError(
            "preflight failed: approval center unavailable; child process was not started",
            exit_code=1,
        )

    monkeypatch.setattr(agent_launcher, "launch_managed_process", fake_launch)
    monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: "agentveil-mcp-proxy")

    rc = main([
        "launch",
        "--profile",
        "generic-process",
        "--project-dir",
        str(project),
        "--",
        sys.executable,
        "-c",
        "print(1)",
    ])
    assert rc == 1
    assert "preflight failed" in capsys.readouterr().err.lower()


# ----- P0.12b: launch --choose-folder parity ----------------------------------


def test_cli_launch_rejects_choose_folder_with_project_dir(tmp_path, capsys):
    rc = main([
        "launch",
        "--profile",
        "generic-process",
        "--choose-folder",
        "--project-dir",
        str(tmp_path),
        "--",
        sys.executable,
        "-c",
        "print(1)",
    ])
    assert rc == 2
    assert "cannot be combined" in capsys.readouterr().err.lower()


def test_cli_launch_choose_folder_cancel_fail_closed(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import agent_launcher

    called = {"launch": False}

    def fake_launch(**_kwargs):
        called["launch"] = True

    monkeypatch.setattr(agent_launcher, "launch_managed_process", fake_launch)
    monkeypatch.setattr(
        proxy_cli,
        "_choose_setup_project_folder",
        lambda: (_ for _ in ()).throw(
            proxy_cli.ProxyCliError("folder selection cancelled", exit_code=2)
        ),
    )

    rc = main([
        "launch",
        "--profile",
        "generic-process",
        "--choose-folder",
        "--",
        sys.executable,
        "-c",
        "print(1)",
    ])
    assert rc == 2
    assert "cancel" in capsys.readouterr().err.lower()
    assert called["launch"] is False


def test_cli_launch_choose_folder_uses_selected_project(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import agent_launcher

    selected = tmp_path / "picked-project"
    selected.mkdir()
    seen: dict[str, Path] = {}

    def fake_launch(**kwargs):
        seen["project_dir"] = kwargs["project_dir"]
        raise agent_launcher.AgentLauncherError(
            "preflight failed: approval center unavailable; child process was not started",
            exit_code=1,
        )

    monkeypatch.setattr(agent_launcher, "launch_managed_process", fake_launch)
    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", lambda: selected)
    monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: "agentveil-mcp-proxy")

    rc = main([
        "launch",
        "--profile",
        "generic-process",
        "--choose-folder",
        "--json",
        "--",
        sys.executable,
        "-c",
        "print(1)",
    ])
    assert rc == 1
    assert seen["project_dir"] == selected.resolve()
    err = capsys.readouterr()
    assert str(selected) not in err.out
    assert str(selected) not in err.err


def test_cli_launch_status_rejects_choose_folder(tmp_path, monkeypatch, capsys):
    picker_called = {"value": False}

    def fake_picker():
        picker_called["value"] = True
        return tmp_path

    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", fake_picker)

    rc = main(["launch", "status", "--choose-folder", "--project-dir", str(tmp_path)])
    assert rc == 2
    assert "only supported for launch" in capsys.readouterr().err.lower()
    assert picker_called["value"] is False


def test_cli_launch_stop_rejects_choose_folder(tmp_path, monkeypatch, capsys):
    picker_called = {"value": False}

    def fake_picker():
        picker_called["value"] = True
        return tmp_path

    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", fake_picker)

    rc = main(["launch", "stop", "--choose-folder", "--project-dir", str(tmp_path)])
    assert rc == 2
    assert "only supported for launch" in capsys.readouterr().err.lower()
    assert picker_called["value"] is False


# ----- P0.13b: hermes-cli profile ------------------------------------------------


def test_cli_launch_hermes_cli_missing_executable_fail_closed(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp" / "mcp-proxy"
    home.mkdir(parents=True)
    (home / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            __import__("types").SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )

    rc = main([
        "launch",
        "--profile",
        "hermes-cli",
        "--project-dir",
        str(project),
        "--",
        "hermes",
        "chat",
        "-q",
        "hello",
    ])
    assert rc == 1
    assert "hermes executable not found" in capsys.readouterr().err.lower()


def test_cli_launch_hermes_cli_missing_provider_fail_closed(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp" / "mcp-proxy"
    home.mkdir(parents=True)
    (home / "config.json").write_text("{}", encoding="utf-8")
    operator_hermes = tmp_path / "bin" / "hermes"
    operator_hermes.parent.mkdir(parents=True)
    operator_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    operator_hermes.chmod(0o755)

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def fake_which(name):
        if name == "hermes":
            return str(operator_hermes)
        return None

    monkeypatch.setattr("agentveil_mcp_proxy.agent_launcher.shutil.which", fake_which)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.agent_launcher.ensure_approval_center_running",
        lambda **_kwargs: (
            __import__("types").SimpleNamespace(state="running", pid=111, port=8765),
            True,
            "approval center started",
        ),
    )

    rc = main([
        "launch",
        "--profile",
        "hermes-cli",
        "--project-dir",
        str(project),
        "--",
        "hermes",
        "chat",
        "-q",
        "hello",
    ])
    assert rc == 1
    assert "llm provider key" in capsys.readouterr().err.lower()


def test_cli_launch_hermes_cli_choose_folder_routes_to_launch(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import agent_launcher

    selected = tmp_path / "picked-project"
    selected.mkdir()
    seen: dict[str, object] = {}

    def fake_launch(**kwargs):
        seen["project_dir"] = kwargs["project_dir"]
        raise agent_launcher.AgentLauncherError(
            "preflight failed: approval center unavailable; child process was not started",
            exit_code=1,
        )

    monkeypatch.setattr(agent_launcher, "launch_managed_process", fake_launch)
    monkeypatch.setattr(proxy_cli, "_choose_setup_project_folder", lambda: selected)
    monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: "agentveil-mcp-proxy")

    rc = main([
        "launch",
        "--profile",
        "hermes-cli",
        "--choose-folder",
        "--json",
        "--",
        "hermes",
        "chat",
        "-q",
        "hello",
    ])
    assert rc == 1
    assert seen["project_dir"] == selected.resolve()
    err = capsys.readouterr()
    assert str(selected) not in err.out
    assert str(selected) not in err.err


def test_root_help_surfaces_grouped_onboarding_sections(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "Getting started:" in text
    assert "init, doctor, run, setup, launch" in text
    assert "Evidence and proof:" in text
    assert "events, export-evidence, verify" in text
    assert "Advanced:" in text
    assert "Typical first-run path:" in text
    assert "Commands:" in text
    assert "protected machine" not in text.lower()
    assert "host-wide" not in text.lower()


def test_root_help_still_lists_all_commands():
    help_text = proxy_cli.build_parser().format_help()
    for command in (
        "init",
        "doctor",
        "run",
        "setup",
        "launch",
        "export-evidence",
        "verify",
        "events",
        "approval-center",
        "wizard",
        "install-claude-hook",
    ):
        assert command in help_text


def test_approval_center_open_help_lists_record_id(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["approval-center", "open", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "--record-id" in text
    assert "--home" in text
    assert "--json" in text


def test_init_help_retains_next_steps_guidance(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["init", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "agentveil-mcp-proxy init --quickstart-filesystem" in text
    assert "client-config print" in text


def test_init_next_steps_include_home_when_custom_home(tmp_path, capsys):
    home = tmp_path / "custom-avp-home"
    rc = main([
        "init",
        "--home",
        str(home),
        "--plaintext",
        "--force",
    ])
    assert rc == 0
    text = capsys.readouterr().out
    assert "doctor --home <same AVP home>" in text
    assert "client-config print --home <same AVP home>" in text
    assert str(home) not in text


def test_init_next_steps_include_config_when_custom_config(tmp_path, capsys):
    home = tmp_path / "custom-avp-home"
    config = home / "custom-config.json"
    rc = main([
        "init",
        "--home",
        str(home),
        "--config",
        str(config),
        "--plaintext",
        "--force",
    ])
    assert rc == 0
    text = capsys.readouterr().out
    assert "doctor --home <same AVP home> --config <same config>" in text
    assert "client-config print --home <same AVP home> --config <same config>" in text
    assert str(home) not in text
    assert str(config) not in text


def _assert_demo_managed_approval_center_stopped(home: Path) -> None:
    from agentveil_mcp_proxy.approval.server import (
        inspect_managed_approval_center,
        scan_cmdline_proven_managed_center_pids,
    )

    status = inspect_managed_approval_center(home)
    assert status.state != "running"
    assert scan_cmdline_proven_managed_center_pids(home) == ()


def test_demo_help_exists_without_hidden_flags(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["demo", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "demo" in text
    assert "product shape only" in text
    assert "--demo-auto-approve" not in text
    assert "--work-dir" not in text


def test_root_help_lists_demo_in_getting_started(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    getting_started = text.split("Getting started:", 1)[1].split("Evidence and proof:", 1)[0]
    assert "demo" in getting_started
    assert "  demo" in text or ", demo" in getting_started


@pytest.mark.allow_demo_managed_approval_center
def test_demo_auto_approve_runs_real_flow(tmp_path, capsys):
    work_dir = tmp_path / "demo-work"
    rc = main([
        "demo",
        "--work-dir",
        str(work_dir),
        "--demo-auto-approve",
        "--json",
    ])
    assert rc == 0
    text = capsys.readouterr().out
    payload = json.loads(text)
    assert payload["ok"] is True
    assert payload["demo_timeline"] == "redirect -> approval -> proof"
    assert payload["local_proof"] == "pending -> approved -> executed"
    assert payload["target_reached"] is True
    assert "redirect_playbook" not in text
    assert "risk_family" not in text
    assert "host-wide" not in text.lower()
    _assert_demo_managed_approval_center_stopped(work_dir / "avp-home")


@pytest.mark.allow_demo_managed_approval_center
def test_demo_human_output_is_bounded_without_secrets(tmp_path, capsys):
    work_dir = tmp_path / "demo-human"
    rc = main([
        "demo",
        "--work-dir",
        str(work_dir),
        "--demo-auto-approve",
    ])
    assert rc == 0
    text = capsys.readouterr().out
    assert proxy_cli._DEMO_BOUNDARY_LINE in text
    assert proxy_cli._DEMO_REDIRECT_LINE in text
    assert "Action continued: demo file written." in text
    assert "Local proof: pending -> approved -> executed" in text
    assert "redirect_playbook" not in text
    assert "risk_family" not in text
    assert "/approval/" not in text
    _assert_demo_managed_approval_center_stopped(work_dir / "avp-home")


@pytest.mark.allow_demo_managed_approval_center
def test_demo_uses_source_aware_proxy_command_for_approval_center(tmp_path, monkeypatch):
    from agentveil_mcp_proxy.approval.server import ensure_managed_approval_center_for_cli

    captured: dict[str, str] = {}

    def capture_center_start(**kwargs):
        captured["proxy_command"] = kwargs["proxy_command"]
        return ensure_managed_approval_center_for_cli(**kwargs)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        capture_center_start,
    )
    rc = main([
        "demo",
        "--work-dir",
        str(tmp_path / "demo-source-route"),
        "--demo-auto-approve",
        "--json",
    ])
    assert rc == 0
    assert captured["proxy_command"] == sys.executable
    _assert_demo_managed_approval_center_stopped(tmp_path / "demo-source-route" / "avp-home")


_ROLE_DOCTOR_FORBIDDEN_WORDING = (
    "AgentVeil learned",
    "inferred role",
)


def _assert_role_doctor_reviewer_output(output: str) -> None:
    assert "Preset: reviewer" in output
    assert "Allowed action families" in output
    assert "Blocked action families" in output
    assert "Action boundary:" in output
    assert "Implementer" in output
    assert "Build agent" in output
    lowered = output.lower()
    for forbidden in _ROLE_DOCTOR_FORBIDDEN_WORDING:
        assert forbidden.lower() not in lowered
    assert "adaptive recommendation" not in lowered
    assert "before local policy" not in lowered


def test_role_doctor_reviewer_preset_shows_action_boundary(capsys):
    assert main(["role", "doctor", "--preset", "reviewer"]) == 0
    _assert_role_doctor_reviewer_output(capsys.readouterr().out)


def test_explain_role_reviewer_still_works(capsys):
    assert main(["explain", "role", "--preset", "reviewer"]) == 0
    _assert_role_doctor_reviewer_output(capsys.readouterr().out)


def test_role_doctor_and_explain_role_reviewer_match(capsys):
    assert main(["role", "doctor", "--preset", "reviewer"]) == 0
    role_output = capsys.readouterr().out
    assert main(["explain", "role", "--preset", "reviewer"]) == 0
    explain_output = capsys.readouterr().out
    assert role_output == explain_output


def test_role_doctor_help_is_discoverable(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["role", "doctor", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert "--preset" in text
    assert "reviewer" in text


def test_root_help_lists_role_doctor(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    advanced = text.split("Advanced:", 1)[1].split("Typical first-run path:", 1)[0]
    assert "role" in advanced


def test_doctor_human_output_includes_role_presets_hint(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    out = io.StringIO()
    assert doctor_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out) == 0
    text = out.getvalue()
    assert proxy_cli._ROLE_PRESETS_DISCOVERABILITY_HINT in text
    assert "inferred" not in text.lower()
    assert "adaptive" not in text.lower()


def test_doctor_json_output_omits_role_presets_hint(tmp_path):
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    out = io.StringIO()
    assert doctor_proxy(
        home=home,
        passphrase=TEST_PASSPHRASE,
        output_json=True,
        out=out,
    ) == 0
    payload = json.loads(out.getvalue())
    serialized = json.dumps(payload)
    assert proxy_cli._ROLE_PRESETS_DISCOVERABILITY_HINT not in serialized
    assert "role doctor" not in serialized


def test_init_human_output_includes_role_presets_hint(tmp_path, capsys):
    home = tmp_path / "avp-home"
    assert main(["init", "--home", str(home), "--plaintext", "--force"]) == 0
    text = capsys.readouterr().out
    assert proxy_cli._ROLE_PRESETS_DISCOVERABILITY_HINT in text
    assert "Next:" in text


@pytest.mark.allow_demo_managed_approval_center
def test_demo_human_output_omits_role_presets_hint(tmp_path, capsys):
    work_dir = tmp_path / "demo-no-role-hint"
    assert main([
        "demo",
        "--work-dir",
        str(work_dir),
        "--demo-auto-approve",
    ]) == 0
    text = capsys.readouterr().out
    assert proxy_cli._ROLE_PRESETS_DISCOVERABILITY_HINT not in text


# --- Console login / logout (Slice 4) --------------------------------------

CONSOLE_DEVICE_CODE = "device-code-secret-cli"
CONSOLE_USER_CODE = "ABCD-2468"
CONSOLE_TOKEN = "confirmed-device-token-secret-cli"
CONSOLE_BINDING_TOKEN = "runtime-binding-token-secret-cli"
CONSOLE_URL = "https://agentveil.dev/console/pairing"
CONSOLE_ATTACH_DEVICE_CODE = "attach-device-code-secret-cli"
CONSOLE_ATTACH_TOKEN = "attach-confirmed-token-secret-cli"
CONSOLE_ATTACH_STATE = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
CONSOLE_ATTACH_URL = f"https://agentveil.dev/console/attach?state={CONSOLE_ATTACH_STATE}"


def _console_start() -> PairingStart:
    return PairingStart(
        device_code=CONSOLE_DEVICE_CODE,
        user_code=CONSOLE_USER_CODE,
        verification_url=CONSOLE_URL,
        expires_in=600,
        interval=5,
    )


class _FakeConsoleClient:
    def __init__(
        self,
        *,
        start=None,
        token=None,
        start_error=None,
        poll_error=None,
        revoke_result=None,
        revoke_error=None,
        fail_if_used=False,
    ):
        self._start = start
        self._token = token
        self._start_error = start_error
        self._poll_error = poll_error
        self._revoke_result = revoke_result
        self._revoke_error = revoke_error
        self._fail_if_used = fail_if_used
        self.started = False
        self.polled = False
        self.revoked_with = None
        self.revoke_calls: list[str] = []

    def start(self):
        if self._fail_if_used:
            raise AssertionError("network start() must not be called")
        self.started = True
        if self._start_error is not None:
            raise self._start_error
        return self._start

    def poll_for_token(self, start):
        self.polled = True
        if self._poll_error is not None:
            raise self._poll_error
        return self._token

    def revoke(self, token):
        if self._fail_if_used:
            raise AssertionError("network revoke() must not be called")
        self.revoke_calls.append(token)
        self.revoked_with = token
        if self._revoke_error is not None:
            raise self._revoke_error
        return self._revoke_result


def _install_console_client(monkeypatch, client):
    class _FailingAttach:
        def start(self):
            raise AttachClientError("unexpected_status")

    monkeypatch.setattr(proxy_cli, "_console_attach_client", lambda: _FailingAttach())
    monkeypatch.setattr(proxy_cli, "_console_pairing_client", lambda: client)


def test_console_login_and_logout_registered_in_parser():
    parser = proxy_cli.build_parser()
    assert parser.parse_args(["login", "--no-open"]).command == "login"
    assert parser.parse_args(["logout"]).command == "logout"


def test_console_login_full_flow_writes_credential(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(token=CONSOLE_TOKEN, scope=CREDENTIAL_SCOPE),
    )
    _install_console_client(monkeypatch, client)

    exit_code = main(["login", "--no-open"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert CONSOLE_URL in out
    assert CONSOLE_USER_CODE in out
    assert "Connected to AgentVeil Console." in out
    # The command output excludes the device code and issued token.
    assert CONSOLE_DEVICE_CODE not in out
    assert CONSOLE_TOKEN not in out

    stored = load_credential(home=home)
    assert stored is not None
    assert stored.token == CONSOLE_TOKEN
    assert stored.scope == CREDENTIAL_SCOPE
    path = credential_path(home=home)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_console_login_full_flow_real_decoder_accepts_consumed_response(
    tmp_path,
    monkeypatch,
    capsys,
):
    from agentveil_mcp_proxy.console_pairing_client import ConsolePairingClient, RawResponse

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))

    class _PairingTransport:
        def __call__(self, method, url, *, headers, body, timeout):
            if url.endswith("/console/pairing/start"):
                payload = {
                    "device_code": CONSOLE_DEVICE_CODE,
                    "user_code": CONSOLE_USER_CODE,
                    "verification_uri": "/console/pairing",
                    "expires_in": 600,
                    "interval": 5,
                }
            else:
                payload = {
                    "status": "consumed",
                    "token": CONSOLE_TOKEN,
                    "scope": CREDENTIAL_SCOPE,
                }
            return RawResponse(
                status=200,
                content_types=("application/json",),
                body=json.dumps(payload).encode("utf-8"),
            )

    class _FailingAttach:
        def start(self):
            raise AttachClientError("unexpected_status")

    monkeypatch.setattr(proxy_cli, "_console_attach_client", lambda: _FailingAttach())
    monkeypatch.setattr(
        proxy_cli,
        "_console_pairing_client",
        lambda: ConsolePairingClient(transport=_PairingTransport()),
    )

    exit_code = main(["login", "--no-open"])
    out, err = capsys.readouterr()

    assert exit_code == 0
    assert CONSOLE_URL in out
    assert CONSOLE_USER_CODE in out
    assert "Connected to AgentVeil Console." in out
    assert CONSOLE_DEVICE_CODE not in out
    assert CONSOLE_TOKEN not in out
    assert CONSOLE_DEVICE_CODE not in err
    assert CONSOLE_TOKEN not in err

    stored = load_credential(home=home)
    assert stored is not None
    assert stored.token == CONSOLE_TOKEN
    assert stored.scope == CREDENTIAL_SCOPE
    path = credential_path(home=home)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_console_login_browser_opens_after_instruction(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(token=CONSOLE_TOKEN, scope=CREDENTIAL_SCOPE),
    )
    stream = io.StringIO()
    recorded = {}

    def _fake_open(url):
        recorded["url"] = url
        recorded["output_before_open"] = stream.getvalue()
        return True

    assert (
        proxy_cli.run_console_login_cli(
            open_browser=True,
            client=client,
            browser_open=_fake_open,
            out=stream,
        )
        == 0
    )
    assert recorded["url"] == CONSOLE_URL
    assert CONSOLE_USER_CODE in recorded["output_before_open"]


def test_console_login_no_open_does_not_open_browser(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(token=CONSOLE_TOKEN, scope=CREDENTIAL_SCOPE),
    )
    _install_console_client(monkeypatch, client)
    opened = []
    monkeypatch.setattr(proxy_cli.webbrowser, "open", lambda url: opened.append(url))

    assert main(["login", "--no-open"]) == 0
    assert opened == []


def test_console_login_existing_credential_is_not_overwritten(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    save_credential(CONSOLE_TOKEN, home=home)
    client = _FakeConsoleClient(fail_if_used=True)
    _install_console_client(monkeypatch, client)

    exit_code = main(["login"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert "Already connected" in out
    assert client.started is False
    assert load_credential(home=home).token == CONSOLE_TOKEN


def test_console_login_credential_write_failure_leaves_no_partial(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(token=CONSOLE_TOKEN, scope=CREDENTIAL_SCOPE),
    )
    _install_console_client(monkeypatch, client)

    def _boom(*_args, **_kwargs):
        raise console_creds.CredentialError("credential_write_failed")

    monkeypatch.setattr(proxy_cli, "save_credential", _boom)

    exit_code = main(["login", "--no-open"])
    _out, err = capsys.readouterr()

    assert exit_code == 1
    assert "ERROR:" in err
    assert load_credential(home=home) is None
    assert CONSOLE_TOKEN not in err
    assert client.revoke_calls == [CONSOLE_TOKEN]


def test_console_login_store_failure_revokes_orphan_token(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(token=CONSOLE_TOKEN, scope=CREDENTIAL_SCOPE),
        revoke_result=RevokeOutcome.REVOKED,
    )
    _install_console_client(monkeypatch, client)

    def _boom(*_args, **_kwargs):
        raise console_creds.CredentialError("credential_write_failed")

    monkeypatch.setattr(proxy_cli, "save_credential", _boom)

    exit_code = main(["login", "--no-open"])
    _out, err = capsys.readouterr()

    assert exit_code == 1
    assert client.revoke_calls == [CONSOLE_TOKEN]
    assert "ERROR:" in err


def test_console_pairing_dual_storage_failure_revokes_source_and_cleans_both_credentials(
    tmp_path,
    monkeypatch,
    capsys,
):
    from agentveil_mcp_proxy.console_credentials import (
        RUNTIME_BINDING_SCOPE,
        load_runtime_binding_credential,
    )

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(
            token=CONSOLE_TOKEN,
            scope=CREDENTIAL_SCOPE,
            runtime_binding_token=CONSOLE_BINDING_TOKEN,
            runtime_binding_scope=RUNTIME_BINDING_SCOPE,
        ),
        revoke_result=RevokeOutcome.REVOKED,
    )
    _install_console_client(monkeypatch, client)

    def _binding_write_failed(*_args, **_kwargs):
        raise console_creds.CredentialError("credential_write_failed")

    monkeypatch.setattr(
        proxy_cli,
        "save_runtime_binding_credential",
        _binding_write_failed,
    )

    exit_code = main(["login", "--no-open"])
    _out, err = capsys.readouterr()

    assert exit_code == 1
    assert client.revoke_calls == [CONSOLE_TOKEN, CONSOLE_BINDING_TOKEN]
    assert load_credential(home=home) is None
    assert load_runtime_binding_credential(home=home) is None
    assert CONSOLE_TOKEN not in err
    assert CONSOLE_BINDING_TOKEN not in err
    assert "ERROR:" in err


def test_console_pairing_dual_bundle_never_leaks_credentials(
    tmp_path,
    monkeypatch,
    capsys,
):
    from agentveil_mcp_proxy.console_credentials import (
        RUNTIME_BINDING_SCOPE,
        load_runtime_binding_credential,
    )
    from agentveil_mcp_proxy.console_pairing_client import (
        ConsolePairingClient,
        RawResponse,
    )

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))

    class _PairingTransport:
        def __call__(self, method, url, *, headers, body, timeout):
            del method, headers, body, timeout
            if url.endswith("/console/pairing/start"):
                payload = {
                    "device_code": CONSOLE_DEVICE_CODE,
                    "user_code": CONSOLE_USER_CODE,
                    "verification_uri": "/console/pairing",
                    "expires_in": 600,
                    "interval": 5,
                }
            else:
                payload = {
                    "status": "consumed",
                    "token": CONSOLE_TOKEN,
                    "scope": CREDENTIAL_SCOPE,
                    "runtime_binding_token": CONSOLE_BINDING_TOKEN,
                    "runtime_binding_scope": RUNTIME_BINDING_SCOPE,
                }
            return RawResponse(
                status=200,
                content_types=("application/json",),
                body=json.dumps(payload).encode("utf-8"),
            )

    class _FailingAttach:
        def start(self):
            raise AttachClientError("unexpected_status")

    monkeypatch.setattr(proxy_cli, "_console_attach_client", lambda: _FailingAttach())
    monkeypatch.setattr(
        proxy_cli,
        "_console_pairing_client",
        lambda: ConsolePairingClient(transport=_PairingTransport()),
    )

    exit_code = main(["login", "--no-open"])
    out, err = capsys.readouterr()

    assert exit_code == 0
    assert load_credential(home=home).token == CONSOLE_TOKEN
    assert load_runtime_binding_credential(home=home).token == CONSOLE_BINDING_TOKEN
    for secret in (
        CONSOLE_DEVICE_CODE,
        CONSOLE_TOKEN,
        CONSOLE_BINDING_TOKEN,
        RUNTIME_BINDING_SCOPE,
    ):
        assert secret not in out
        assert secret not in err


def test_console_login_recheck_revokes_token_when_credential_appears(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(token="orphan-token-value", scope=CREDENTIAL_SCOPE),
        revoke_result=RevokeOutcome.REVOKED,
    )
    _install_console_client(monkeypatch, client)
    save_credential(CONSOLE_TOKEN, home=home)

    calls = {"count": 0}
    original_load = proxy_cli.load_credential

    def _load_once_then_existing(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] <= 1:
            return None
        return original_load(*args, **kwargs)

    monkeypatch.setattr(proxy_cli, "load_credential", _load_once_then_existing)

    exit_code = main(["login", "--no-open"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert "Already connected" in out
    assert client.revoke_calls == ["orphan-token-value"]
    assert load_credential(home=home).token == CONSOLE_TOKEN


def test_console_logout_without_credential_is_idempotent(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))

    def _no_client():
        raise AssertionError("logout must not build a client without a credential")

    monkeypatch.setattr(proxy_cli, "_console_pairing_client", _no_client)

    exit_code = main(["logout"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert "Not connected to AgentVeil Console." in out


def test_console_logout_revokes_source_and_removes_both_credentials(
    tmp_path, monkeypatch, capsys,
):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    from agentveil_mcp_proxy.console_credentials import (
        RUNTIME_BINDING_SCOPE,
        load_runtime_binding_credential,
        save_runtime_binding_credential,
    )

    save_credential(CONSOLE_TOKEN, home=home)
    save_runtime_binding_credential("runtime-binding-token-logout", home=home)
    client = _FakeConsoleClient(revoke_result=RevokeOutcome.REVOKED)
    _install_console_client(monkeypatch, client)

    exit_code = main(["logout"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert client.revoke_calls == [CONSOLE_TOKEN, "runtime-binding-token-logout"]
    assert load_credential(home=home) is None
    assert load_runtime_binding_credential(home=home) is None
    assert "runtime-binding-token-logout" not in out
    assert RUNTIME_BINDING_SCOPE not in out


def test_console_logout_revoked_removes_credential(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    save_credential(CONSOLE_TOKEN, home=home)
    client = _FakeConsoleClient(revoke_result=RevokeOutcome.REVOKED)
    _install_console_client(monkeypatch, client)

    exit_code = main(["logout"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert "Disconnected from AgentVeil Console." in out
    assert client.revoked_with == CONSOLE_TOKEN
    assert load_credential(home=home) is None
    assert CONSOLE_TOKEN not in out


def test_console_logout_unauthorized_removes_credential(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    save_credential(CONSOLE_TOKEN, home=home)
    client = _FakeConsoleClient(revoke_result=RevokeOutcome.ALREADY_UNAVAILABLE)
    _install_console_client(monkeypatch, client)

    exit_code = main(["logout"])
    out, _err = capsys.readouterr()

    assert exit_code == 0
    assert "already" in out.lower()
    assert load_credential(home=home) is None


def test_console_logout_ambiguous_preserves_credential(tmp_path, monkeypatch, capsys):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    save_credential(CONSOLE_TOKEN, home=home)
    client = _FakeConsoleClient(
        revoke_error=PairingClientError("transport_failed")
    )
    _install_console_client(monkeypatch, client)

    exit_code = main(["logout"])
    out, err = capsys.readouterr()

    assert exit_code == 1
    assert load_credential(home=home).token == CONSOLE_TOKEN
    assert "ERROR:" in err
    assert CONSOLE_TOKEN not in out
    assert CONSOLE_TOKEN not in err


def test_console_project_status_sync_skipped_without_credential(tmp_path, monkeypatch, capsys):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )
    from test_mcp_proxy_console_project_status_client import BackendEchoTransport

    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    transport = BackendEchoTransport()
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client._urllib_transport",
        transport,
    )

    class _FailingAttach:
        def start(self):
            raise AttachClientError("unexpected_status")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_attach_client",
        lambda: _FailingAttach(),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    capsys.readouterr()

    assert rc == 0
    assert transport.calls == []


def test_console_project_status_sync_on_codex_setup_and_status_when_logged_in(
    tmp_path,
    monkeypatch,
    capsys,
):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    save_credential(CONSOLE_TOKEN, home=avp_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "accepted",
    )

    project = tmp_path / "checkout-service"
    project.mkdir()
    assert main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"]) == 0
    capsys.readouterr()
    assert len(sync_calls) == 1
    assert sync_calls[0]["connector"] == "codex"
    assert sync_calls[0]["project_dir"] == project.resolve()

    assert main(["setup", "status", "--client", "codex", "--project-dir", str(project), "--json"]) == 0
    capsys.readouterr()
    assert len(sync_calls) == 2


def test_console_upload_failure_does_not_change_codex_setup_output(
    tmp_path,
    monkeypatch,
    capsys,
):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    save_credential(CONSOLE_TOKEN, home=avp_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)

    def _fail_sync(**_kwargs):
        raise RuntimeError("network must not leak")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        _fail_sync,
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    out, err = capsys.readouterr()

    assert rc == 0
    assert "setup-codex" in out
    assert "network must not leak" not in out
    assert "network must not leak" not in err
    assert CONSOLE_TOKEN not in out
    assert CONSOLE_TOKEN not in err


@pytest.mark.parametrize(
    ("client", "setup_argv", "status_argv", "connector"),
    [
        (
            "cursor",
            ["setup", "cursor", "--yes"],
            ["setup", "status"],
            "cursor",
        ),
        (
            "claude-code",
            ["setup", "claude-code", "--yes"],
            ["setup", "status"],
            "claude-code",
        ),
        (
            "gemini-cli",
            ["setup", "gemini-cli", "--yes"],
            ["setup", "status", "--client", "gemini-cli"],
            "gemini-cli",
        ),
    ],
)
def test_console_project_status_sync_on_setup_status_for_connectors(
    tmp_path,
    monkeypatch,
    capsys,
    client,
    setup_argv,
    status_argv,
    connector,
):
    from agentveil_mcp_proxy import cursor_setup
    from test_mcp_proxy_codex_setup import _make_proxy_command

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    project = tmp_path / "checkout-service"
    project.mkdir()
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "accepted",
    )

    if client == "cursor":
        def fake_init_proxy(**kwargs):
            home = kwargs["home"]
            _stub_project_proxy_home(home)

        def fake_prepare(_workspace, *, force=False, initialize_product_route=False):
            home = cursor_setup.setup_home(_workspace)
            home.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(home, 0o700)
            _write_owner_only_passphrase_file(home / "passphrase")
            return home

        monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
        monkeypatch.setattr(cursor_setup, "prepare_proxy_home", fake_prepare)
        monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
        monkeypatch.setattr(
            cursor_setup,
            "ensure_approval_center_running",
            lambda **_kwargs: SimpleNamespace(
                status=SimpleNamespace(state="running"),
                started=True,
                reused=False,
                restarted=False,
                reason="center started",
            ),
        )
        monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
        setup = [*setup_argv, "--workspace", str(project), "--json"]
        status = [*status_argv, "--workspace", str(project), "--json"]
    elif client == "claude-code":
        monkeypatch.setattr(
            proxy_cli,
            "init_proxy",
            lambda **kwargs: (kwargs["home"] / "mcp-proxy").mkdir(parents=True, exist_ok=True)
            or (kwargs["home"] / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8"),
        )
        monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: "agentveil-mcp-proxy")
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
            lambda **_kwargs: SimpleNamespace(
                status=SimpleNamespace(state="running"),
                started=True,
                reused=False,
                restarted=False,
                reason="center started",
            ),
        )
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
            lambda _home: SimpleNamespace(state="running", url="http://127.0.0.1/approval/"),
        )
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]
    else:
        from test_mcp_proxy_gemini_setup import _install_fast_gemini_setup_fakes

        isolated_home = tmp_path / "home"
        monkeypatch.setenv("HOME", str(isolated_home))
        proxy_command = _make_proxy_command(tmp_path)
        _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]

    assert main(setup) == 0
    capsys.readouterr()
    assert len(sync_calls) == 1
    assert sync_calls[0]["connector"] == connector

    assert main(status) == 0
    capsys.readouterr()
    assert len(sync_calls) == 2


def test_console_project_status_preview_does_not_sync(tmp_path, monkeypatch, capsys):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "accepted",
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--json"])
    capsys.readouterr()
    assert rc == 0
    assert sync_calls == []


def test_console_project_status_failed_setup_does_not_sync(tmp_path, monkeypatch, capsys):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        lambda **_kwargs: SimpleNamespace(
            status=SimpleNamespace(state="stale"),
            started=False,
            reused=False,
            restarted=False,
            reason="approval-center did not become healthy",
        ),
    )
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "accepted",
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    capsys.readouterr()
    assert rc == 1
    assert sync_calls == []


@pytest.mark.parametrize("output_json", [False, True])
def test_console_upload_failure_preserves_setup_output_across_formats(
    tmp_path,
    monkeypatch,
    capsys,
    output_json,
):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    proxy_command = _make_proxy_command(tmp_path)

    def _argv(project: Path) -> list[str]:
        argv = ["setup", "codex", "--project-dir", str(project), "--yes"]
        if output_json:
            argv.append("--json")
        return argv

    def _fresh_run(*, label: str, sync_fn):
        isolated_home = tmp_path / f"home-{label}"
        _isolate_cli_home(monkeypatch, isolated_home)
        _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
        project = tmp_path / f"project-{label}"
        project.mkdir()
        monkeypatch.setattr(
            "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
            sync_fn,
        )
        assert main(_argv(project)) == 0
        return capsys.readouterr()

    accepted_out, accepted_err = _fresh_run(
        label="accepted",
        sync_fn=lambda **_kwargs: "accepted",
    )

    def _fail_sync(**_kwargs):
        raise RuntimeError("network must not leak")

    failed_out, failed_err = _fresh_run(label="failed", sync_fn=_fail_sync)

    if output_json:
        def _strip_refs(value):
            if isinstance(value, dict):
                return {
                    key: _strip_refs(item)
                    for key, item in value.items()
                    if key != "ref"
                }
            if isinstance(value, list):
                return [_strip_refs(item) for item in value]
            return value

        accepted_payload = _strip_refs(json.loads(accepted_out))
        failed_payload = _strip_refs(json.loads(failed_out))
        assert failed_payload == accepted_payload
    else:
        assert failed_out == accepted_out
        assert failed_err == accepted_err
    assert "network must not leak" not in failed_out
    assert "network must not leak" not in failed_err


def test_console_free_builder_sync_skipped_without_credential(tmp_path, monkeypatch, capsys):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_free_builder_client.sync_free_builder_install",
        lambda **kwargs: sync_calls.append(kwargs) or "skipped_no_credential",
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    capsys.readouterr()

    assert rc == 0
    assert len(sync_calls) == 1


def test_console_free_builder_sync_on_login_when_connected(tmp_path, monkeypatch, capsys):
    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_free_builder_client.sync_free_builder_install",
        lambda **kwargs: sync_calls.append(kwargs) or "installed",
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.load_credential",
        lambda home=None: None,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.save_credential",
        lambda token, scope=None, home=None: None,
    )

    class _FakePairing:
        def start(self):
            from agentveil_mcp_proxy.console_pairing_client import PairingStart

            return PairingStart(
                device_code="device-code-secret",
                user_code="ABCD-1234",
                verification_url="https://agentveil.dev/console/pairing",
                expires_in=600,
                interval=5,
            )

        def poll_for_token(self, start):
            from agentveil_mcp_proxy.console_pairing_client import PairingToken

            del start
            return PairingToken(token="paired-token-secret", scope=CREDENTIAL_SCOPE)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_pairing_client",
        lambda: _FakePairing(),
    )

    assert main(["login", "--no-open"]) == 0
    capsys.readouterr()
    assert len(sync_calls) == 1


def _null_context():
    from contextlib import contextmanager

    @contextmanager
    def _cm():
        yield

    return _cm()


@pytest.mark.parametrize(
    ("client", "setup_argv", "status_argv", "connector"),
    [
        (
            "cursor",
            ["setup", "cursor", "--yes"],
            ["setup", "status"],
            "cursor",
        ),
        (
            "codex",
            ["setup", "codex", "--yes"],
            ["setup", "status", "--client", "codex"],
            "codex",
        ),
        (
            "claude-code",
            ["setup", "claude-code", "--yes"],
            ["setup", "status"],
            "claude-code",
        ),
        (
            "gemini-cli",
            ["setup", "gemini-cli", "--yes"],
            ["setup", "status", "--client", "gemini-cli"],
            "gemini-cli",
        ),
    ],
)
def test_console_free_builder_sync_on_setup_status_for_connectors(
    tmp_path,
    monkeypatch,
    capsys,
    client,
    setup_argv,
    status_argv,
    connector,
):
    from agentveil_mcp_proxy import cursor_setup
    from test_mcp_proxy_codex_setup import _make_proxy_command

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    project = tmp_path / "checkout-service"
    project.mkdir()
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_free_builder_client.sync_free_builder_install",
        lambda **kwargs: sync_calls.append(kwargs) or "skipped_no_credential",
    )

    if client == "cursor":
        def fake_init_proxy(**kwargs):
            home = kwargs["home"]
            _stub_project_proxy_home(home)

        def fake_prepare(_workspace, *, force=False, initialize_product_route=False):
            home = cursor_setup.setup_home(_workspace)
            home.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(home, 0o700)
            _write_owner_only_passphrase_file(home / "passphrase")
            return home

        monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
        monkeypatch.setattr(cursor_setup, "prepare_proxy_home", fake_prepare)
        monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
        monkeypatch.setattr(
            cursor_setup,
            "ensure_approval_center_running",
            lambda **_kwargs: SimpleNamespace(
                status=SimpleNamespace(state="running"),
                started=True,
                reused=False,
                restarted=False,
                reason="center started",
            ),
        )
        monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
        setup = [*setup_argv, "--workspace", str(project), "--json"]
        status = [*status_argv, "--workspace", str(project), "--json"]
    elif client == "codex":
        from test_mcp_proxy_codex_setup import (
            _install_fast_codex_setup_fakes,
            _isolate_cli_home,
        )

        isolated_home = tmp_path / "home"
        _isolate_cli_home(monkeypatch, isolated_home)
        proxy_command = _make_proxy_command(tmp_path)
        _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]
    elif client == "claude-code":
        monkeypatch.setattr(
            proxy_cli,
            "init_proxy",
            lambda **kwargs: (kwargs["home"] / "mcp-proxy").mkdir(parents=True, exist_ok=True)
            or (kwargs["home"] / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8"),
        )
        monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: "agentveil-mcp-proxy")
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
            lambda **_kwargs: SimpleNamespace(
                status=SimpleNamespace(state="running"),
                started=True,
                reused=False,
                restarted=False,
                reason="center started",
            ),
        )
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
            lambda _home: SimpleNamespace(state="running", url="http://127.0.0.1/approval/"),
        )
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]
    else:
        from test_mcp_proxy_gemini_setup import _install_fast_gemini_setup_fakes

        isolated_home = tmp_path / "home"
        monkeypatch.setenv("HOME", str(isolated_home))
        proxy_command = _make_proxy_command(tmp_path)
        _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]

    assert main(setup) == 0
    capsys.readouterr()
    assert len(sync_calls) == 1

    assert main(status) == 0
    capsys.readouterr()
    assert len(sync_calls) == 2


# --- Console browser-session attach (Slice 4) -------------------------------


def _console_attach_start() -> AttachStart:
    return AttachStart(
        device_code=CONSOLE_ATTACH_DEVICE_CODE,
        attach_url=CONSOLE_ATTACH_URL,
        expires_in=600,
        interval=5,
    )


class _FakeAttachClient:
    def __init__(
        self,
        *,
        start=None,
        token=None,
        start_error=None,
        poll_error=None,
    ):
        self._start = start
        self._token = token
        self._start_error = start_error
        self._poll_error = poll_error
        self.started = False
        self.polled = False

    def start(self):
        self.started = True
        if self._start_error is not None:
            raise self._start_error
        return self._start or _console_attach_start()

    def poll_for_token(self, start):
        del start
        self.polled = True
        if self._poll_error is not None:
            raise self._poll_error
        return self._token or AttachToken(
            token=CONSOLE_ATTACH_TOKEN,
            scope=CREDENTIAL_SCOPE,
        )


def _install_attach_login_fakes(monkeypatch, attach_client):
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.load_credential",
        lambda home=None: None,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_attach_client",
        lambda: attach_client,
    )


def test_console_login_attach_path_without_user_code(tmp_path, monkeypatch, capsys):
    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    attach = _FakeAttachClient()
    _install_attach_login_fakes(monkeypatch, attach)
    opened: list[str] = []

    assert (
        proxy_cli.run_console_login_cli(
            open_browser=True,
            browser_open=lambda url: opened.append(url) or True,
        )
        == 0
    )
    out, err = capsys.readouterr()

    assert attach.started is True
    assert attach.polled is True
    assert opened == [CONSOLE_ATTACH_URL]
    assert load_credential(home=avp_home).token == CONSOLE_ATTACH_TOKEN
    assert CONSOLE_USER_CODE not in out
    assert CONSOLE_USER_CODE not in err
    assert CONSOLE_ATTACH_DEVICE_CODE not in out
    assert CONSOLE_ATTACH_TOKEN not in out
    assert CONSOLE_ATTACH_TOKEN not in err


def test_console_login_attach_failure_falls_back_to_pairing(
    tmp_path,
    monkeypatch,
    capsys,
):
    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    attach = _FakeAttachClient(start_error=AttachClientError("unexpected_status"))
    pairing = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(
            token=CONSOLE_TOKEN,
            scope=CREDENTIAL_SCOPE,
        ),
    )
    _install_attach_login_fakes(monkeypatch, attach)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_pairing_client",
        lambda: pairing,
    )

    assert proxy_cli.run_console_login_cli(open_browser=False) == 0
    out, err = capsys.readouterr()

    assert attach.started is True
    assert attach.polled is False
    assert pairing.started is True
    assert pairing.polled is True
    assert CONSOLE_USER_CODE in out
    assert load_credential(home=avp_home).token == CONSOLE_TOKEN
    assert CONSOLE_ATTACH_TOKEN not in out
    assert CONSOLE_ATTACH_TOKEN not in err


def test_console_setup_attach_acquires_credential_and_uploads_status(
    tmp_path,
    monkeypatch,
    capsys,
):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    real_attach_credential = proxy_cli._best_effort_console_attach_credential
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    attach = _FakeAttachClient()
    sync_calls = []
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_attach_client",
        lambda: attach,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )
    monkeypatch.setattr(
        proxy_cli,
        "_best_effort_console_attach_credential",
        real_attach_credential,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "accepted",
    )
    monkeypatch.setattr(proxy_cli.webbrowser, "open", lambda _url: True)

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    out, err = capsys.readouterr()

    assert rc == 0
    assert attach.started is True
    assert attach.polled is True
    assert load_credential(home=avp_home).token == CONSOLE_ATTACH_TOKEN
    assert len(sync_calls) == 1
    assert CONSOLE_USER_CODE not in out
    assert CONSOLE_USER_CODE not in err
    assert CONSOLE_ATTACH_DEVICE_CODE not in out
    assert CONSOLE_ATTACH_TOKEN not in out
    assert CONSOLE_ATTACH_TOKEN not in err


def _install_browser_failure_setup_fakes(
    monkeypatch,
    tmp_path,
    *,
    attach_client,
    pairing_client,
    browser_open,
):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    real_attach_credential = proxy_cli._best_effort_console_attach_credential
    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_attach_client",
        lambda: attach_client,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_pairing_client",
        lambda: pairing_client,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.load_credential",
        lambda home=None: None,
    )
    monkeypatch.setattr(
        proxy_cli,
        "_best_effort_console_attach_credential",
        real_attach_credential,
    )
    monkeypatch.setattr(
        proxy_cli.webbrowser,
        "open",
        browser_open,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: "accepted",
    )
    return avp_home


@pytest.mark.parametrize(
    "browser_open",
    [
        lambda _url: False,
        lambda _url: (_ for _ in ()).throw(OSError("browser delivery unavailable")),
    ],
)
def test_console_setup_browser_delivery_failure_surfaces_pairing_without_attach_poll(
    tmp_path,
    monkeypatch,
    capsys,
    browser_open,
):
    attach = _FakeAttachClient()
    pairing = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(
            token=CONSOLE_TOKEN,
            scope=CREDENTIAL_SCOPE,
        ),
    )
    avp_home = _install_browser_failure_setup_fakes(
        monkeypatch,
        tmp_path,
        attach_client=attach,
        pairing_client=pairing,
        browser_open=browser_open,
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    out, err = capsys.readouterr()

    assert rc == 0
    assert attach.started is True
    assert attach.polled is False
    assert pairing.started is True
    assert pairing.polled is True
    assert CONSOLE_USER_CODE in err
    assert CONSOLE_USER_CODE not in out
    assert load_credential(home=avp_home).token == CONSOLE_TOKEN
    assert CONSOLE_ATTACH_DEVICE_CODE not in out
    assert CONSOLE_ATTACH_DEVICE_CODE not in err
    assert CONSOLE_ATTACH_TOKEN not in out
    assert CONSOLE_ATTACH_TOKEN not in err


def test_console_setup_browser_delivery_failure_redacts_attach_secrets_and_preserves_json(
    tmp_path,
    monkeypatch,
    capsys,
):
    attach = _FakeAttachClient()
    pairing = _FakeConsoleClient(
        start=_console_start(),
        token=PairingToken(
            token=CONSOLE_TOKEN,
            scope=CREDENTIAL_SCOPE,
        ),
    )
    _install_browser_failure_setup_fakes(
        monkeypatch,
        tmp_path,
        attach_client=attach,
        pairing_client=pairing,
        browser_open=lambda _url: False,
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    out, err = capsys.readouterr()
    combined = out + err

    assert rc == 0
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["action"] == "setup-codex"
    assert CONSOLE_USER_CODE in err
    assert CONSOLE_USER_CODE not in out
    assert CONSOLE_ATTACH_STATE not in combined
    assert CONSOLE_ATTACH_DEVICE_CODE not in combined
    assert CONSOLE_ATTACH_TOKEN not in combined
    assert CONSOLE_ATTACH_URL not in combined
    assert CONSOLE_TOKEN not in combined
    assert CONSOLE_DEVICE_CODE not in combined


def test_console_setup_succeeds_when_attach_unavailable(
    tmp_path,
    monkeypatch,
    capsys,
):
    from test_mcp_proxy_codex_setup import (
        _install_fast_codex_setup_fakes,
        _isolate_cli_home,
        _make_proxy_command,
    )
    from test_mcp_proxy_console_project_status_client import BackendEchoTransport

    isolated_home = tmp_path / "home"
    _isolate_cli_home(monkeypatch, isolated_home)
    proxy_command = _make_proxy_command(tmp_path)
    _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
    attach = _FakeAttachClient(start_error=AttachClientError("transport_failed"))
    transport = BackendEchoTransport()
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_attach_client",
        lambda: attach,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client._urllib_transport",
        transport,
    )

    project = tmp_path / "project"
    project.mkdir()
    rc = main(["setup", "codex", "--project-dir", str(project), "--yes", "--json"])
    out, err = capsys.readouterr()

    assert rc == 0
    assert "setup-codex" in out
    assert transport.calls == []
    assert "transport_failed" not in out
    assert "transport_failed" not in err


def test_console_status_replaces_rejected_credential_and_retries(monkeypatch):
    attach_calls: list[bool] = []
    delete_calls: list[bool] = []
    sync_results = iter(["credential_rejected", "accepted"])
    sync_calls: list[dict] = []

    monkeypatch.setattr(
        proxy_cli,
        "_best_effort_console_attach_credential",
        lambda: attach_calls.append(True),
    )
    monkeypatch.setattr(
        proxy_cli,
        "delete_credential",
        lambda: delete_calls.append(True) or True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or next(sync_results),
    )

    proxy_cli._best_effort_console_project_status_sync(
        connector="codex",
        connector_status={"status": "protected", "route_launch_proved": False},
        project_dir=Path("/tmp/project"),
    )

    assert attach_calls == [True, True]
    assert delete_calls == [True]
    assert len(sync_calls) == 2


def test_hook_status_worker_never_opens_attach_or_repairs_credential(monkeypatch):
    attach_calls = []
    delete_calls = []
    sync_calls = []
    monkeypatch.setenv("AGENTVEIL_HOOK_STATUS_REFRESH_WORKER", "1")
    monkeypatch.setattr(
        proxy_cli,
        "_best_effort_console_attach_credential",
        lambda: attach_calls.append(True),
    )
    monkeypatch.setattr(
        proxy_cli,
        "delete_credential",
        lambda: delete_calls.append(True) or True,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "credential_rejected",
    )

    proxy_cli._best_effort_console_project_status_sync(
        connector="codex",
        connector_status={"status": "protected"},
        project_dir=Path("/tmp/project"),
    )

    assert len(sync_calls) == 1
    assert attach_calls == []
    assert delete_calls == []


def test_hook_status_worker_skips_free_builder_install(monkeypatch):
    calls = []
    monkeypatch.setenv("AGENTVEIL_HOOK_STATUS_REFRESH_WORKER", "1")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_free_builder_client.sync_free_builder_install",
        lambda **kwargs: calls.append(kwargs),
    )

    proxy_cli._best_effort_console_free_builder_sync(home=Path("/tmp/project/.avp"))

    assert calls == []


@pytest.mark.parametrize(
    ("client", "setup_argv", "status_argv", "connector"),
    [
        (
            "cursor",
            ["setup", "cursor", "--yes"],
            ["setup", "status"],
            "cursor",
        ),
        (
            "codex",
            ["setup", "codex", "--yes"],
            ["setup", "status", "--client", "codex"],
            "codex",
        ),
        (
            "claude-code",
            ["setup", "claude-code", "--yes"],
            ["setup", "status"],
            "claude-code",
        ),
        (
            "gemini-cli",
            ["setup", "gemini-cli", "--yes"],
            ["setup", "status", "--client", "gemini-cli"],
            "gemini-cli",
        ),
    ],
)
def test_console_attach_on_setup_for_connectors(
    tmp_path,
    monkeypatch,
    capsys,
    client,
    setup_argv,
    status_argv,
    connector,
):
    from agentveil_mcp_proxy import cursor_setup
    from test_mcp_proxy_codex_setup import _make_proxy_command

    avp_home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    real_attach_credential = proxy_cli._best_effort_console_attach_credential
    project = tmp_path / "checkout-service"
    project.mkdir()
    attach = _FakeAttachClient()
    sync_calls = []
    free_builder_calls = []
    runtime_name = ".agentveil" if client == "cursor" else ".avp"
    expected_runtime_home = (project / runtime_name).resolve()
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli._console_attach_client",
        lambda: attach,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_free_builder_client.sync_free_builder_install",
        lambda **kwargs: free_builder_calls.append(kwargs) or "skipped_no_credential",
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.cli.console_login_lock",
        lambda home=None: _null_context(),
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **kwargs: sync_calls.append(kwargs) or "accepted",
    )
    monkeypatch.setattr(proxy_cli.webbrowser, "open", lambda _url: True)

    if client == "cursor":
        def fake_init_proxy(**kwargs):
            home = kwargs["home"]
            _stub_project_proxy_home(home)

        def fake_prepare(_workspace, *, force=False, initialize_product_route=False):
            home = cursor_setup.setup_home(_workspace)
            home.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                os.chmod(home, 0o700)
            _write_owner_only_passphrase_file(home / "passphrase")
            return home

        monkeypatch.setattr(proxy_cli, "init_proxy", fake_init_proxy)
        monkeypatch.setattr(cursor_setup, "prepare_proxy_home", fake_prepare)
        monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
        monkeypatch.setattr(
            cursor_setup,
            "ensure_approval_center_running",
            lambda **_kwargs: SimpleNamespace(
                status=SimpleNamespace(state="running"),
                started=True,
                reused=False,
                restarted=False,
                reason="center started",
            ),
        )
        monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
        setup = [*setup_argv, "--workspace", str(project), "--json"]
        status = [*status_argv, "--workspace", str(project), "--json"]
    elif client == "codex":
        from test_mcp_proxy_codex_setup import (
            _install_fast_codex_setup_fakes,
            _isolate_cli_home,
        )

        isolated_home = tmp_path / "home"
        _isolate_cli_home(monkeypatch, isolated_home)
        proxy_command = _make_proxy_command(tmp_path)
        _install_fast_codex_setup_fakes(monkeypatch, proxy_command=proxy_command)
        monkeypatch.setattr(
            proxy_cli,
            "_best_effort_console_attach_credential",
            real_attach_credential,
        )
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]
    elif client == "claude-code":
        monkeypatch.setattr(
            proxy_cli,
            "init_proxy",
            lambda **kwargs: (kwargs["home"] / "mcp-proxy").mkdir(parents=True, exist_ok=True)
            or (kwargs["home"] / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8"),
        )
        monkeypatch.setattr(proxy_cli, "_resolve_setup_proxy_command", lambda: "agentveil-mcp-proxy")
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
            lambda **_kwargs: SimpleNamespace(
                status=SimpleNamespace(state="running"),
                started=True,
                reused=False,
                restarted=False,
                reason="center started",
            ),
        )
        monkeypatch.setattr(
            "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
            lambda _home: SimpleNamespace(state="running", url="http://127.0.0.1/approval/"),
        )
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]
    else:
        from test_mcp_proxy_gemini_setup import _install_fast_gemini_setup_fakes

        isolated_home = tmp_path / "home"
        monkeypatch.setenv("HOME", str(isolated_home))
        proxy_command = _make_proxy_command(tmp_path)
        _install_fast_gemini_setup_fakes(monkeypatch, proxy_command=proxy_command)
        monkeypatch.setattr(
            proxy_cli,
            "_best_effort_console_attach_credential",
            real_attach_credential,
        )
        setup = [*setup_argv, "--project-dir", str(project), "--json"]
        status = [*status_argv, "--project-dir", str(project), "--json"]

    assert main(setup) == 0
    capsys.readouterr()
    assert attach.started is True
    assert load_credential(home=avp_home).token == CONSOLE_ATTACH_TOKEN
    assert len(sync_calls) == 1
    assert sync_calls[0]["connector"] == connector
    assert sync_calls[0]["runtime_home"].resolve() == expected_runtime_home
    assert free_builder_calls[0]["home"].resolve() == expected_runtime_home

    assert main(status) == 0
    capsys.readouterr()
    assert len(sync_calls) == 2
    assert sync_calls[1]["runtime_home"].resolve() == expected_runtime_home
    assert free_builder_calls[1]["home"].resolve() == expected_runtime_home


def test_run_proxy_scopes_paid_provider_discovery_to_runtime_home(tmp_path, monkeypatch):
    home = tmp_path / "project" / ".avp"
    monkeypatch.delenv("AVP_HOME", raising=False)
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "idle",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
    }
    (home / "mcp-proxy" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    provider_homes: list[Path | None] = []
    real_discover = proxy_cli.discover_paid_provider

    def _recording_discover(*, home=None):
        provider_homes.append(home)
        return real_discover(home=home)

    monkeypatch.setattr(proxy_cli, "discover_paid_provider", _recording_discover)
    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert provider_homes == [home]


def test_run_proxy_provider_absent_does_not_bind_controlled_runtime(tmp_path, monkeypatch):
    home = tmp_path / "project" / ".avp"
    monkeypatch.delenv("AVP_HOME", raising=False)
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "idle",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
    }
    (home / "mcp-proxy" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    captured = {}
    real_bind = proxy_cli.bind_controlled_alternative_runtime

    def capture_bind(**kwargs):
        captured["runtime_context"] = kwargs.get("runtime_context")
        return real_bind(**kwargs)

    monkeypatch.setattr(proxy_cli, "bind_controlled_alternative_runtime", capture_bind)
    real = proxy_cli.McpPassthrough

    class CapturingPassthrough(real):
        def __init__(self, *args, **kwargs):
            captured["controlled_runtime"] = kwargs.get("controlled_runtime")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxy_cli, "McpPassthrough", CapturingPassthrough)
    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert captured.get("controlled_runtime") is None
    assert captured["runtime_context"] is not None
    assert captured["runtime_context"].state_root == str(home)


def test_run_proxy_starts_ca_status_only_after_runtime_binding(tmp_path, monkeypatch):
    home = tmp_path / "project" / ".avp"
    monkeypatch.delenv("AVP_HOME", raising=False)
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    config = json.loads((home / "mcp-proxy" / "config.json").read_text(encoding="utf-8"))
    config["downstream"] = {
        "name": "idle",
        "command": sys.executable,
        "args": ["-c", "import time; time.sleep(3600)"],
    }
    (home / "mcp-proxy" / "config.json").write_text(json.dumps(config), encoding="utf-8")
    bound = object()
    captured = {"started": 0, "stopped": 0}

    def bind(**kwargs):
        captured["runtime_context"] = kwargs["runtime_context"]
        return bound

    class RecordingDispatcher:
        def __init__(self, **kwargs):
            captured["dispatcher_context"] = kwargs["runtime_context"]
            captured["home"] = kwargs["home"]

        def start(self):
            captured["started"] += 1

        def stop(self, **_kwargs):
            captured["stopped"] += 1

    monkeypatch.setattr(proxy_cli, "bind_controlled_alternative_runtime", bind)
    monkeypatch.setattr(
        proxy_cli,
        "ControlledAlternativesStatusDispatcher",
        RecordingDispatcher,
    )
    assert run_proxy(
        home=home,
        client_in=io.StringIO(""),
        out=io.StringIO(),
        approval_ui_mode="none",
    ) == 0
    assert captured["dispatcher_context"] is captured["runtime_context"]
    assert captured["home"] == tmp_path.home() / ".avp"
    assert captured["started"] == 1
    assert captured["stopped"] == 1


# ----- W-08 common backend registration guidance -----------------------------


def _connector_runtime_home(project: Path, connector: str) -> Path:
    if connector == "cursor":
        return project / ".agentveil"
    return project / ".avp"


def _write_owner_only_passphrase_file(path: Path, *, value: str = TEST_PASSPHRASE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _seed_project_proxy_identity(project: Path, connector: str, *, registered: bool) -> Path:
    home = _connector_runtime_home(project, connector)
    if connector == "cursor":
        from agentveil_mcp_proxy import cursor_setup

        home.mkdir(parents=True, exist_ok=True)
        passphrase_file = cursor_setup.passphrase_path(home)
        _write_owner_only_passphrase_file(passphrase_file)
        init_proxy(
            home=home,
            agent_name="proxy",
            plaintext=False,
            passphrase_file=passphrase_file,
            **_INIT_PROJECT_LOCAL,
        )
    else:
        init_proxy(home=home, agent_name="proxy", plaintext=True, **_INIT_PROJECT_LOCAL)
    if registered:
        paths = proxy_paths(home)
        identity_path = paths.identity_path("proxy")
        identity = _load(identity_path)
        identity["registered"] = True
        identity["verified"] = True
        identity_path.write_text(json.dumps(identity), encoding="utf-8")
    return home


def _assert_backend_registration_guidance(
    payload: dict,
    *,
    home: Path,
    connector: str,
) -> None:
    guidance = payload["backend_registration"]
    assert guidance["required"] is True
    assert guidance["register_working_directory"] == "selected_project_root"
    expected_cmd = proxy_cli._project_connect_command_for_project(
        home,
        connector=connector,
        json_safe=True,
    )
    assert guidance["register_command"] == expected_cmd
    assert "login" in guidance["register_command"]
    assert guidance.get("manual_passphrase_file_required") is not True
    assert "register" in guidance["message"].lower() or "connection" in guidance["message"].lower()
    serialized = json.dumps(payload)
    identity = _load(proxy_paths(home).identity_path("proxy"))
    assert identity["did"] not in serialized
    assert _secret_material(identity) not in serialized
    assert str(home.resolve()) not in serialized
    project_root = proxy_cli._selected_project_root_for_home(home)
    assert str(project_root.resolve()) not in serialized
    assert_proxy_cli_json_is_privacy_safe(payload)


def _init_proxy_for_connector_setup(**kwargs):
    home = kwargs["home"]
    project = home.parent if home.name == ".avp" else home
    init_proxy(
        home=home,
        downstream_config=kwargs.get("downstream_config")
        or quickstart_filesystem_downstream(project),
        policy_pack=kwargs.get("policy_pack", "filesystem"),
        plaintext=kwargs.get("plaintext", True),
        passphrase_file=kwargs.get("passphrase_file"),
        force=kwargs.get("force", False),
        err=kwargs.get("err") or io.StringIO(),
        **_INIT_PROJECT_LOCAL,
    )


def _install_connector_setup_success_mocks(monkeypatch, connector: str) -> None:
    from agentveil_mcp_proxy import claude_hook_setup, codex_setup, cursor_setup, gemini_setup

    def fake_connect(**kwargs):
        project = kwargs["project_root"]
        (project / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "agentveil-mcp-proxy": {
                            "command": "agentveil-mcp-proxy",
                            "args": ["run"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(proxy_cli, "init_proxy", _init_proxy_for_connector_setup)
    monkeypatch.setattr(proxy_cli, "run_connect_cli", fake_connect)
    monkeypatch.setattr("shutil.which", lambda _name: "agentveil-mcp-proxy")
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.ensure_managed_approval_center_for_cli",
        _fake_running_approval_center,
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
        lambda _home: SimpleNamespace(state="running", pid=1, port=8765),
    )
    connector_status = {
        "status": "advisory",
        "hook": "installed",
        "mcp_route": "present",
        "proxy_route": "present",
        "next_step": "reload client",
    }
    if connector == "cursor":
        monkeypatch.setattr(proxy_cli, "initialize_product_route_profile", lambda _prof: None)
        monkeypatch.setattr(
            proxy_cli,
            "build_product_route_downstream_config",
            lambda _prof: {"command": sys.executable, "args": ["downstream.py"]},
        )
        monkeypatch.setattr(cursor_setup, "prepare_proxy_home", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(cursor_setup, "profile_root", lambda home: home / "profiles" / "product_route")
        monkeypatch.setattr(cursor_setup, "proxy_config_path", lambda home: home / "mcp-proxy" / "config.json")
        monkeypatch.setattr(cursor_setup, "passphrase_path", cursor_setup.passphrase_path)
        monkeypatch.setattr(
            cursor_setup,
            "neutralize_competing_global_route",
            lambda *_args, **_kwargs: SimpleNamespace(changed=False),
        )
        monkeypatch.setattr(cursor_setup, "install_mcp_route", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            cursor_setup,
            "install_hooks",
            lambda *_args, **_kwargs: SimpleNamespace(created_hooks=["beforeSubmitPrompt"]),
        )
        monkeypatch.setattr(
            cursor_setup,
            "ensure_approval_center_running",
            _fake_running_approval_center,
        )
        monkeypatch.setattr(cursor_setup, "connector_status", lambda *_args, **_kwargs: connector_status)
    elif connector == "claude-code":
        monkeypatch.setattr(
            claude_hook_setup,
            "install_hook",
            lambda _target: SimpleNamespace(created_settings=True),
        )
        monkeypatch.setattr(
            claude_hook_setup,
            "connector_status",
            lambda *_args, **_kwargs: connector_status,
        )
    elif connector == "codex":
        monkeypatch.setattr(codex_setup, "validate_hook_config", lambda **_kwargs: None)
        monkeypatch.setattr(
            codex_setup,
            "install_hook",
            lambda **_kwargs: SimpleNamespace(applied=True),
        )
        monkeypatch.setattr(
            codex_setup,
            "connect_status",
            lambda **_kwargs: {"config_ref": "codex"},
        )
        monkeypatch.setattr(codex_setup, "managed_route_present", lambda _status: True)
        monkeypatch.setattr(codex_setup, "connector_status", lambda **_kwargs: connector_status)
    elif connector == "gemini-cli":
        monkeypatch.setattr(gemini_setup, "validate_hook_config", lambda **_kwargs: None)
        monkeypatch.setattr(
            gemini_setup,
            "install_hook",
            lambda **_kwargs: SimpleNamespace(applied=True),
        )
        monkeypatch.setattr(
            gemini_setup,
            "connect_status",
            lambda **_kwargs: {"config_ref": "gemini"},
        )
        monkeypatch.setattr(gemini_setup, "managed_route_present", lambda _status: True)
        monkeypatch.setattr(gemini_setup, "connector_status", lambda **_kwargs: connector_status)
    else:
        raise AssertionError(f"unsupported connector {connector!r}")


def _install_connector_status_mocks(monkeypatch, connector: str) -> None:
    from agentveil_mcp_proxy import claude_hook_setup, codex_setup, cursor_setup, gemini_setup

    monkeypatch.setattr(
        "agentveil_mcp_proxy.approval.server.inspect_managed_approval_center",
        lambda _home: SimpleNamespace(state="running", pid=1, port=8765),
    )
    status = {
        "status": "advisory",
        "connector": connector,
        "hook": "installed",
        "hook_state": "installed",
        "mcp_route": "present",
        "proxy_route": "present",
        "approval_center": "running",
        "route_launch_proved": False,
        "hook_trust_required": False,
        "restart_required": True,
        "next_step": "reload client",
        "user_mcp_route": "absent",
        "competing_global_route": "none",
        "mcp_route_observed": False,
    }
    if connector == "cursor":
        monkeypatch.setattr(cursor_setup, "connector_status", lambda *_args, **_kwargs: status)
    elif connector == "claude-code":
        monkeypatch.setattr(
            claude_hook_setup,
            "connector_status",
            lambda *_args, **_kwargs: {k: v for k, v in status.items() if k != "connector"},
        )
    elif connector == "codex":
        monkeypatch.setattr(codex_setup, "connector_status", lambda **_kwargs: status)
    elif connector == "gemini-cli":
        monkeypatch.setattr(gemini_setup, "connector_status", lambda **_kwargs: status)
    else:
        raise AssertionError(f"unsupported connector {connector!r}")


def _install_project_login_post_login_fences(monkeypatch) -> None:
    """Keep project-login tests off live Console sync and credential repair paths."""

    monkeypatch.setattr(
        proxy_cli,
        "_observe_project_connector_status_for_login",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        proxy_cli,
        "_best_effort_console_project_status_sync",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        proxy_cli,
        "_best_effort_console_free_builder_sync",
        lambda **_kwargs: None,
    )


def _install_seeded_console_credentials_must_not_pair(monkeypatch) -> _FakeConsoleClient:
    """Fail fast if setup/login falls through to live Console attach or pairing."""

    client = _FakeConsoleClient(fail_if_used=True)
    _install_console_client(monkeypatch, client)
    return client


def _install_guidance_registration_login_harness(monkeypatch) -> _FakeConsoleClient:
    """Keep guidance follow-up logins on seeded machine credentials, not live Console."""

    from nacl.pwhash import argon2id

    monkeypatch.setattr(argon2id, "OPSLIMIT_MODERATE", argon2id.OPSLIMIT_MIN)
    monkeypatch.setattr(argon2id, "MEMLIMIT_MODERATE", argon2id.MEMLIMIT_MIN)
    _install_project_login_post_login_fences(monkeypatch)
    monkeypatch.setattr(proxy_cli, "_best_effort_console_attach_credential", lambda **_kwargs: None)
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_free_builder_client.sync_free_builder_install",
        lambda **_kwargs: "skipped",
    )
    monkeypatch.setattr(
        "agentveil_mcp_proxy.console_project_status_client.sync_project_status",
        lambda **_kwargs: "accepted",
    )
    return _install_seeded_console_credentials_must_not_pair(monkeypatch)


_CONNECTOR_SETUP_STATUS_CASES = [
    ("cursor", ["setup", "cursor", "--workspace"], ["setup", "status", "--workspace"]),
    ("claude-code", ["setup", "claude-code", "--project-dir"], ["setup", "status", "--project-dir"]),
    ("codex", ["setup", "codex", "--project-dir"], ["setup", "status", "--client", "codex", "--project-dir"]),
    (
        "gemini-cli",
        ["setup", "gemini-cli", "--project-dir"],
        ["setup", "status", "--client", "gemini-cli", "--project-dir"],
    ),
]


@pytest.mark.parametrize(("connector", "setup_prefix", "status_prefix"), _CONNECTOR_SETUP_STATUS_CASES)
def test_setup_common_registration_guidance_for_unregistered_project_identity(
    tmp_path,
    monkeypatch,
    capsys,
    connector,
    setup_prefix,
    status_prefix,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, connector, registered=False)
    _install_connector_setup_success_mocks(monkeypatch, connector)
    _install_connector_status_mocks(monkeypatch, connector)

    setup_argv = [*setup_prefix, str(project), "--yes", "--json"]
    assert main(setup_argv) == 0
    setup_payload = json.loads(capsys.readouterr().out)
    _assert_backend_registration_guidance(setup_payload, home=home, connector=connector)

    status_argv = [*status_prefix, str(project), "--json"]
    assert main(status_argv) == 0
    status_payload = json.loads(capsys.readouterr().out)
    _assert_backend_registration_guidance(status_payload, home=home, connector=connector)


@pytest.mark.parametrize(("connector", "setup_prefix", "status_prefix"), _CONNECTOR_SETUP_STATUS_CASES)
def test_setup_common_registration_guidance_absent_when_registered(
    tmp_path,
    monkeypatch,
    capsys,
    connector,
    setup_prefix,
    status_prefix,
):
    project = tmp_path / "project"
    project.mkdir()
    _seed_project_proxy_identity(project, connector, registered=True)
    _install_connector_setup_success_mocks(monkeypatch, connector)
    _install_connector_status_mocks(monkeypatch, connector)

    setup_argv = [*setup_prefix, str(project), "--yes", "--json"]
    assert main(setup_argv) == 0
    setup_payload = json.loads(capsys.readouterr().out)
    assert "backend_registration" not in setup_payload

    status_argv = [*status_prefix, str(project), "--json"]
    assert main(status_argv) == 0
    status_payload = json.loads(capsys.readouterr().out)
    assert "backend_registration" not in status_payload


@pytest.mark.parametrize(("connector", "setup_prefix", "status_prefix"), _CONNECTOR_SETUP_STATUS_CASES)
def test_setup_common_registration_guidance_never_calls_register(
    tmp_path,
    monkeypatch,
    capsys,
    connector,
    setup_prefix,
    status_prefix,
):
    project = tmp_path / "project"
    project.mkdir()
    _seed_project_proxy_identity(project, connector, registered=False)
    _install_connector_setup_success_mocks(monkeypatch, connector)
    _install_connector_status_mocks(monkeypatch, connector)

    def forbidden_register(**_kwargs):
        raise AssertionError("register_proxy must not be invoked from setup/status guidance")

    monkeypatch.setattr(proxy_cli, "register_proxy", forbidden_register)

    assert main([*setup_prefix, str(project), "--yes", "--json"]) == 0
    capsys.readouterr()
    assert main([*status_prefix, str(project), "--json"]) == 0
    capsys.readouterr()


def test_setup_common_registration_guidance_json_has_no_identity_or_credential(
    tmp_path,
    monkeypatch,
    capsys,
):
    from agentveil_mcp_proxy import codex_setup

    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    identity = _load(proxy_paths(home).identity_path("proxy"))
    _install_connector_status_mocks(monkeypatch, "codex")
    monkeypatch.setattr(codex_setup, "connector_status", lambda **_kwargs: {
        "status": "advisory",
        "connector": "codex",
        "hook": "installed",
        "hook_state": "installed",
        "mcp_route": "present",
        "proxy_route": "present",
        "approval_center": "running",
        "route_launch_proved": False,
        "hook_trust_required": False,
        "restart_required": True,
        "next_step": "reload client",
    })

    assert main(["setup", "status", "--client", "codex", "--project-dir", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    _assert_backend_registration_guidance(payload, home=home, connector="codex")
    serialized = json.dumps(payload).lower()
    assert identity["did"].lower() not in serialized
    assert "private_key" not in serialized
    assert "public_key_hex" not in serialized


def test_setup_common_registration_guidance_cursor_encrypted_json_command_is_actionable(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "cursor", registered=False)
    identity = _load(proxy_paths(home).identity_path("proxy"))
    assert identity.get("encrypted") is True
    _install_connector_status_mocks(monkeypatch, "cursor")

    assert main(["setup", "status", "--workspace", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    _assert_backend_registration_guidance(payload, home=home, connector="cursor")
    cmd = payload["backend_registration"]["register_command"]
    assert cmd == (
        "agentveil-mcp-proxy login --project-dir selected_project_root --connector cursor"
    )


def test_setup_common_registration_guidance_cursor_advertised_register_reaches_backend_stub(
    tmp_path,
    monkeypatch,
    capsys,
):
    from agentveil_mcp_proxy import cursor_setup

    project = tmp_path / "project"
    project.mkdir()
    _install_connector_status_mocks(monkeypatch, "cursor")
    pairing_guard = _install_guidance_registration_login_harness(monkeypatch)
    home = _seed_project_proxy_identity(project, "cursor", registered=False)
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)

    assert main(["setup", "status", "--workspace", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["backend_registration"]["register_working_directory"] == "selected_project_root"
    monkeypatch.chdir(project)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    with _fake_avp_registration_backend() as (base_url, state):
        _seed_identity_on_fake_backend(state, home, passphrase_file=cursor_setup.passphrase_path(home))
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "cursor")) == 0
    out, _err = capsys.readouterr()
    assert "existing agent registered with the backend" in out
    assert "Runtime readiness is separate" in out
    _assert_bounded_project_login_output(out + _err, identity_before, home=home)
    identity_after = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_after.get("registered") is True
    assert pairing_guard.started is False
    assert pairing_guard.polled is False


def test_setup_common_registration_guidance_json_actionable_from_nonproject_cwd(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    _install_connector_status_mocks(monkeypatch, "cursor")
    pairing_guard = _install_guidance_registration_login_harness(monkeypatch)
    home = _seed_project_proxy_identity(project, "cursor", registered=False)
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    monkeypatch.delenv("AVP_PROXY_PASSPHRASE", raising=False)

    other_cwd = tmp_path / "elsewhere"
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)

    assert main(["setup", "status", "--workspace", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    _assert_backend_registration_guidance(payload, home=home, connector="cursor")

    assert main(_project_login_argv(Path("selected_project_root"), "cursor")) != 0
    capsys.readouterr()

    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    with _fake_avp_registration_backend() as (base_url, state):
        from agentveil_mcp_proxy import cursor_setup

        _seed_identity_on_fake_backend(state, home, passphrase_file=cursor_setup.passphrase_path(home))
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "cursor")) == 0
    out, _err = capsys.readouterr()
    assert "existing agent registered with the backend" in out
    assert "Runtime readiness is separate" in out
    _assert_bounded_project_login_output(out + _err, identity_before, home=home)
    assert pairing_guard.started is False
    assert pairing_guard.polled is False


def _seed_cursor_encrypted_with_external_passphrase_file(
    project: Path,
    passphrase_file: Path,
    *,
    registered: bool,
) -> Path:
    home = project / ".agentveil"
    home.mkdir(parents=True, exist_ok=True)
    _write_owner_only_passphrase_file(passphrase_file)
    init_proxy(
        home=home,
        agent_name="proxy",
        plaintext=False,
        passphrase_file=passphrase_file,
    )
    if registered:
        paths = proxy_paths(home)
        identity_path = paths.identity_path("proxy")
        identity = _load(identity_path)
        identity["registered"] = True
        identity["verified"] = True
        identity_path.write_text(json.dumps(identity), encoding="utf-8")
    return home


def test_setup_common_registration_guidance_external_passphrase_file_json(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    external_passphrase = tmp_path / "stored-passphrase"
    home = _seed_cursor_encrypted_with_external_passphrase_file(
        project,
        external_passphrase,
        registered=False,
    )
    _install_connector_status_mocks(monkeypatch, "cursor")

    assert main(["setup", "status", "--workspace", str(project), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    guidance = payload["backend_registration"]
    assert guidance["register_command"] == (
        "agentveil-mcp-proxy login --project-dir selected_project_root --connector cursor"
    )
    assert external_passphrase.name not in guidance["register_command"]
    _assert_backend_registration_guidance(payload, home=home, connector="cursor")


def test_setup_common_registration_guidance_human_output_shows_quoted_paths_without_secrets(
    tmp_path,
    monkeypatch,
    capsys,
):
    import shlex

    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "cursor", registered=False)
    _install_connector_status_mocks(monkeypatch, "cursor")

    assert main(["setup", "status", "--workspace", str(project)]) == 0
    captured = capsys.readouterr().out
    assert "Project connection:" in captured
    assert f"cwd: {shlex.quote(str(project.resolve()))}" in captured
    assert "--project-dir" in captured
    assert "--connector cursor" in captured
    assert TEST_PASSPHRASE not in captured
    identity = _load(proxy_paths(home).identity_path("proxy"))
    assert identity["did"] not in captured
    assert _secret_material(identity) not in captured


def _dual_console_pairing_token() -> PairingToken:
    return PairingToken(
        token=CONSOLE_TOKEN,
        scope=CREDENTIAL_SCOPE,
        runtime_binding_token=CONSOLE_BINDING_TOKEN,
        runtime_binding_scope=RUNTIME_BINDING_SCOPE,
    )


def _install_project_login_binding_stub(monkeypatch, *, fail: bool = False) -> dict:
    from agentveil_mcp_proxy.console_agent_binding_client import (
        AgentBindingClientError,
        ConsoleAgentBindingClient,
        RuntimeBindingIssuance,
    )

    state = {"calls": 0, "agents": []}

    def _fake_issue(self, *, agent, summary_token):
        state["calls"] += 1
        state["agents"].append(getattr(agent, "did", None))
        if fail:
            raise AgentBindingClientError("runtime_binding_failed")
        token = CONSOLE_BINDING_TOKEN if state["calls"] == 1 else "scoped-child-token-agent-b-0123456789ab"
        return RuntimeBindingIssuance(
            token=token,
            scope=RUNTIME_BINDING_SCOPE,
            result="issued",
        )

    monkeypatch.setattr(ConsoleAgentBindingClient, "issue", _fake_issue)
    return state


def _install_machine_dual_console_credentials(tmp_path, monkeypatch) -> Path:
    _ = tmp_path
    avp_home = Path(os.environ["HOME"]).expanduser() / ".avp"
    avp_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    save_runtime_binding_credential(CONSOLE_BINDING_TOKEN, home=avp_home)
    _install_project_login_binding_stub(monkeypatch)
    return avp_home


def _install_machine_summary_console_credentials(tmp_path, monkeypatch) -> Path:
    _ = tmp_path
    avp_home = Path(os.environ["HOME"]).expanduser() / ".avp"
    avp_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    save_credential(CONSOLE_TOKEN, home=avp_home)
    _install_project_login_binding_stub(monkeypatch)
    return avp_home


def _project_login_argv(project: Path, connector: str) -> list[str]:
    login_connector = {
        "cursor": "cursor",
        "claude-code": "claude_code",
        "codex": "codex",
        "gemini-cli": "gemini",
    }[connector]
    return [
        "login",
        "--project-dir",
        str(project),
        "--connector",
        login_connector,
        "--no-open",
    ]


def test_project_login_registers_selected_existing_identity_after_pairing(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    avp_home = tmp_path / "machine-avp"
    avp_home.mkdir()
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    client = _FakeConsoleClient(
        start=_console_start(),
        token=_dual_console_pairing_token(),
    )
    _install_console_client(monkeypatch, client)
    _install_connector_status_mocks(monkeypatch, "codex")
    _install_project_login_binding_stub(monkeypatch)
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home, passphrase=None)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "codex")) == 0
        assert state.agents[did]["is_verified"] is True
    out, err = capsys.readouterr()
    combined = out + err

    assert client.started is True
    identity_after = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_after["did"] == identity_before["did"]
    assert identity_after.get("registered") is True
    assert load_credential(home=avp_home) is not None
    assert load_runtime_binding_credential(home=avp_home) is not None
    assert "existing agent registered with the backend" in combined
    assert "Runtime readiness is separate" in combined
    assert "Active" not in combined
    assert CONSOLE_TOKEN not in combined
    assert CONSOLE_BINDING_TOKEN not in combined
    _assert_bounded_project_login_output(combined, identity_before, home=home)


def test_project_login_uses_existing_console_credential_without_repairing(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "claude-code", registered=False)
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    client = _FakeConsoleClient(fail_if_used=True)
    _install_console_client(monkeypatch, client)
    _install_connector_status_mocks(monkeypatch, "claude-code")
    _install_project_login_post_login_fences(monkeypatch)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))

    with _fake_avp_registration_backend() as (base_url, state):
        _seed_identity_on_fake_backend(state, home, passphrase=None)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "claude-code")) == 0
    out, _err = capsys.readouterr()

    assert client.started is False
    assert "Reusing existing AgentVeil Console connection" in out
    assert _load(proxy_paths(home).identity_path("proxy")).get("registered") is True
    _assert_bounded_project_login_output(out + _err, identity_before, home=home)


def test_projectless_login_setup_and_status_never_register_agent(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    _seed_project_proxy_identity(project, "codex", registered=False)
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_connector_status_mocks(monkeypatch, "codex")

    register_calls = {"count": 0}
    issuer_calls = {"count": 0}
    original_register = proxy_cli.register_proxy

    def counting_register(**kwargs):
        register_calls["count"] += 1
        return original_register(**kwargs)

    def forbidden_issuer(**kwargs):
        issuer_calls["count"] += 1
        raise AssertionError("issuer must not run outside project login")

    monkeypatch.setattr(proxy_cli, "register_proxy", counting_register)
    monkeypatch.setattr(proxy_cli, "issue_and_store_scoped_runtime_binding", forbidden_issuer)

    assert proxy_cli.run_console_login_cli(open_browser=False) == 0
    capsys.readouterr()
    assert main(["setup", "status", "--client", "codex", "--project-dir", str(project), "--json"]) == 0
    capsys.readouterr()
    assert register_calls["count"] == 0
    assert issuer_calls["count"] == 0


def test_project_login_encrypted_cursor_identity_preserves_custody_and_hides_secrets(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "cursor", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_before.get("encrypted") is True
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_connector_status_mocks(monkeypatch, "cursor")
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        from agentveil_mcp_proxy import cursor_setup

        _seed_identity_on_fake_backend(state, home, passphrase_file=cursor_setup.passphrase_path(home))
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "cursor")) == 0
    out, err = capsys.readouterr()
    combined = out + err

    identity_after = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_after.get("encrypted") is True
    assert identity_after["did"] == identity_before["did"]
    _assert_bounded_project_login_output(combined, identity_before, home=home)


def test_project_login_registration_failure_preserves_identity_credential_and_inactive_status(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "gemini-cli", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    avp_home = _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_project_login_post_login_fences(monkeypatch)
    _install_fake_register(
        monkeypatch,
        raises=AVPValidationError("rejected", status_code=403),
    )

    assert main(_project_login_argv(project, "gemini-cli")) == 1
    out, err = capsys.readouterr()
    combined = out + err

    identity_after = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_after == identity_before
    assert load_credential(home=avp_home).token == CONSOLE_TOKEN
    assert load_runtime_binding_credential(home=avp_home).token == CONSOLE_BINDING_TOKEN
    assert "Project connection incomplete" in combined
    assert "Active" not in combined


def test_project_login_repeat_is_idempotent_and_never_mints_new_identity(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_connector_status_mocks(monkeypatch, "codex")
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home, passphrase=None)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "codex")) == 0
        capsys.readouterr()
        state.register_status = 409
        state.agents[did]["is_verified"] = True
        assert main(_project_login_argv(project, "codex")) == 0
        capsys.readouterr()

    identity_after = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_after["did"] == identity_before["did"]


def test_project_login_409_malformed_is_verified_false_preserves_identity_and_credentials(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    avp_home = _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_connector_status_mocks(monkeypatch, "codex")
    _install_project_login_post_login_fences(monkeypatch)
    credential_before = load_credential(home=avp_home)
    binding_before = load_runtime_binding_credential(home=avp_home)

    with _fake_avp_registration_backend() as (base_url, state):
        did = _seed_identity_on_fake_backend(state, home, passphrase=None)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "codex")) == 0
        capsys.readouterr()
        identity_mid = _load(proxy_paths(home).identity_path("proxy"))
        state.register_status = 409
        state.agents[did]["is_verified"] = True
        state.lookup_is_verified[did] = "false"
        assert main(_project_login_argv(project, "codex")) == 1
        capsys.readouterr()

    identity_after = _load(proxy_paths(home).identity_path("proxy"))
    assert identity_after["did"] == identity_before["did"]
    assert identity_after.get("registered") is identity_mid.get("registered")
    assert identity_after.get("verified") is identity_mid.get("verified")
    assert load_credential(home=avp_home) == credential_before
    assert load_runtime_binding_credential(home=avp_home) == binding_before


def test_project_login_subprocess_cli_sequence(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    avp_home = tmp_path / "machine-avp"
    avp_home.mkdir()
    isolated_home = tmp_path / "isolated-home"
    isolated_home.mkdir()
    save_credential(CONSOLE_TOKEN, home=avp_home)
    save_runtime_binding_credential(CONSOLE_BINDING_TOKEN, home=avp_home)
    repo_root = Path(__file__).resolve().parents[3]
    script = tmp_path / "project_login_proof.py"
    script.write_text(
        f"""import hashlib
import json
import os
import re
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nacl.signing import VerifyKey

sys.path.insert(0, {str(repo_root)!r})
sys.path.insert(0, {str(repo_root / "packages" / "agentveil-mcp-proxy")!r})
isolated_home = Path({str(isolated_home)!r})
isolated_home.mkdir(parents=True, exist_ok=True)
os.environ["HOME"] = str(isolated_home)
os.environ["USERPROFILE"] = str(isolated_home)
os.environ["AVP_HOME"] = {str(avp_home)!r}

import agentveil_mcp_proxy.console_agent_binding_client as binding_mod
from agentveil_mcp_proxy.console_agent_binding_client import RawResponse, _REQUEST_BODY
from agentveil_mcp_proxy.console_credentials import RUNTIME_BINDING_SCOPE
from agentveil_mcp_proxy.cli import main, proxy_paths

_BINDING_PATH = "/v1/controlled-alternatives/av02/runtime/binding"
_SUBPROCESS_CHILD_TOKEN = "subprocess-scoped-child-token-0123456789ab"

def _parse_auth_v2(headers):
    authorization = headers["Authorization"]
    return dict(re.findall(r'(\\w+)=\"([^\"]+)\"', authorization))

def _binding_transport(method, url, *, headers, body, timeout):
    if body != _REQUEST_BODY:
        return RawResponse(status=503, content_types=("application/json",), body=b"{{}}", cache_control=("no-store",))
    parsed = _parse_auth_v2(dict(headers))
    message = (
        f"v2:POST:{{_BINDING_PATH}}::{{parsed['ts']}}:{{parsed['nonce']}}:"
        f"{{hashlib.sha256(body).hexdigest()}}"
    )
    VerifyKey(bytes.fromhex(State.public_key_hex)).verify(
        message.encode(),
        bytes.fromhex(parsed["sig"]),
    )
    response_body = json.dumps(
        {{
            "schema_version": "runtime/binding-response/1",
            "runtime_binding_token": _SUBPROCESS_CHILD_TOKEN,
            "scope": RUNTIME_BINDING_SCOPE,
            "result": "issued",
        }},
        separators=(",", ":"),
    ).encode("utf-8")
    return RawResponse(
        status=200,
        content_types=("application/json",),
        body=response_body,
        cache_control=("no-store",),
    )

binding_mod._urllib_transport = _binding_transport

import agentveil_mcp_proxy.cli as cli_mod
cli_mod._observe_project_connector_status_for_login = lambda **_kwargs: None
cli_mod._best_effort_console_project_status_sync = lambda **_kwargs: None
cli_mod._best_effort_console_free_builder_sync = lambda **_kwargs: None

POW_DIFFICULTY = {_FAKE_REGISTRATION_POW_DIFFICULTY}

class State:
    agents = {{}}
    challenges = {{}}
    public_key_hex = ""

def _pow_valid(challenge, nonce, difficulty):
    digest = hashlib.sha256((challenge + nonce).encode()).digest()
    full_bytes = difficulty // 8
    remaining_bits = difficulty % 8
    mask = (0xFF >> remaining_bits) ^ 0xFF if remaining_bits else 0
    for index in range(full_bytes):
        if digest[index] != 0:
            return False
    if remaining_bits > 0 and (digest[full_bytes] & mask) != 0:
        return False
    return True

def _verify_payload(payload):
    did = payload.get("did", "")
    agent = State.agents.get(did)
    if agent is None:
        return "unknown agent"
    public_key_hex = agent.get("public_key_hex", "")
    challenge_entry = State.challenges.get(public_key_hex)
    if not isinstance(challenge_entry, dict):
        return "missing registration challenge"
    challenge = payload.get("challenge", "")
    if challenge != challenge_entry.get("challenge"):
        return "challenge mismatch"
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            challenge.encode(),
            bytes.fromhex(payload.get("signature_hex", "")),
        )
    except Exception:
        return "invalid signature"
    if not _pow_valid(
        str(challenge_entry.get("pow_challenge", "")),
        str(payload.get("pow_nonce", "")),
        POW_DIFFICULTY,
    ):
        return "invalid pow"
    return None

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return
    def _send(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        if self.path.startswith("/v1/health"):
            self._send(200, {{"status": "ok"}})
            return
        did = self.path.split("/v1/agents/", 1)[-1]
        agent = State.agents.get(did)
        if agent is None:
            self._send(404, {{"detail": "missing"}})
            return
        self._send(
            200,
            {{
                "did": did,
                "is_verified": agent["is_verified"] is True,
                "status": "active",
            }},
        )
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.path == "/v1/agents/register":
            challenge = secrets.token_hex(8)
            State.challenges[payload["public_key_hex"]] = {{
                "challenge": challenge,
                "pow_challenge": challenge,
            }}
            self._send(
                200,
                {{
                    "challenge": challenge,
                    "pow_challenge": challenge,
                    "pow_difficulty": POW_DIFFICULTY,
                }},
            )
            return
        if self.path == "/v1/agents/verify":
            verify_error = _verify_payload(payload)
            if verify_error is not None:
                self._send(400, {{"detail": verify_error}})
                return
            did = payload["did"]
            State.agents[did]["is_verified"] = True
            self._send(200, {{"onboarding_pending": False}})
            return
        self._send(404, {{"detail": "missing"}})

home = Path({str(home)!r})
paths = proxy_paths(home)
config = json.loads(paths.config_path.read_text(encoding="utf-8"))
identity = json.loads(paths.identity_path(config["avp"]["agent_name"]).read_text(encoding="utf-8"))
from agentveil_mcp_proxy.identity import load_agent_from_identity
agent = load_agent_from_identity(
    identity,
    base_url=identity["base_url"],
    agent_name=identity["name"],
    passphrase=None,
)
State.public_key_hex = agent.public_key_hex
State.agents[agent.did] = {{"public_key_hex": agent.public_key_hex, "is_verified": False}}

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base_url = f"http://127.0.0.1:{{server.server_address[1]}}"
config["avp"]["base_url"] = base_url
paths.config_path.write_text(json.dumps(config), encoding="utf-8")
identity["base_url"] = base_url
paths.identity_path(config["avp"]["agent_name"]).write_text(json.dumps(identity), encoding="utf-8")

try:
    code = main([
        "login",
        "--project-dir",
        {str(project)!r},
        "--connector",
        "codex",
        "--no-open",
    ])
finally:
    server.shutdown()
    thread.join(timeout=5)
raise SystemExit(code)
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = str(isolated_home)
    env["USERPROFILE"] = str(isolated_home)
    env["PYTHONPATH"] = os.pathsep.join([
        str(repo_root),
        str(repo_root / "packages" / "agentveil-mcp-proxy"),
    ])
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    identity = _load(proxy_paths(home).identity_path("proxy"))
    assert identity.get("registered") is True
    assert identity.get("verified") is True
    assert identity["did"] == identity_before["did"]
    combined = result.stdout + result.stderr
    assert CONSOLE_TOKEN not in combined
    _assert_bounded_project_login_output(combined, identity_before, home=home)
    from agentveil_mcp_proxy.console_credentials import (
        load_runtime_binding_credential,
        load_scoped_runtime_binding_credential,
    )

    summary = load_credential(home=avp_home)
    assert summary is not None
    scoped = load_scoped_runtime_binding_credential(
        identity["did"],
        summary.token,
        home=avp_home,
    )
    assert scoped is not None
    assert scoped.token == "subprocess-scoped-child-token-0123456789ab"
    assert load_runtime_binding_credential(home=avp_home).token == CONSOLE_BINDING_TOKEN


def test_project_login_external_passphrase_file_registers_via_fake_backend(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    external_passphrase = tmp_path / "stored-passphrase"
    home = _seed_cursor_encrypted_with_external_passphrase_file(
        project,
        external_passphrase,
        registered=False,
    )
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_connector_status_mocks(monkeypatch, "cursor")
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        _seed_identity_on_fake_backend(state, home, passphrase_file=external_passphrase)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "cursor")) == 0
    out, err = capsys.readouterr()
    _assert_bounded_project_login_output(out + err, identity_before, home=home)
    assert external_passphrase.read_text(encoding="utf-8").strip() not in out + err


def test_project_login_two_home_selection_keeps_other_project_identity(
    tmp_path,
    monkeypatch,
    capsys,
):
    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()
    home_a = _seed_project_proxy_identity(project_a, "codex", registered=False)
    home_b = _seed_project_proxy_identity(project_b, "codex", registered=False)
    identity_b_before = _load(proxy_paths(home_b).identity_path("proxy"))
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)
    _install_connector_status_mocks(monkeypatch, "codex")
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        _seed_identity_on_fake_backend(state, home_a, passphrase=None)
        _set_proxy_home_base_url(home_a, base_url)
        assert main(_project_login_argv(project_a, "codex")) == 0
    capsys.readouterr()
    identity_b_after = _load(proxy_paths(home_b).identity_path("proxy"))
    assert identity_b_after == identity_b_before


def test_project_login_binding_failure_returns_incomplete_without_success_claim(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    _install_machine_summary_console_credentials(tmp_path, monkeypatch)
    _install_project_login_binding_stub(monkeypatch, fail=True)
    _install_connector_status_mocks(monkeypatch, "codex")
    _install_project_login_post_login_fences(monkeypatch)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))

    with _fake_avp_registration_backend() as (base_url, state):
        _seed_identity_on_fake_backend(state, home, passphrase=None)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, "codex")) == 1
    out, err = capsys.readouterr()
    combined = out + err
    assert "Project connection incomplete" in combined
    assert "existing agent registered with the backend" not in combined
    assert identity_before["did"] == _load(proxy_paths(home).identity_path("proxy"))["did"]


@pytest.mark.parametrize("connector", ["codex", "cursor", "claude-code", "gemini-cli"])
def test_project_login_summary_only_stores_scoped_child_per_connector(
    tmp_path,
    monkeypatch,
    connector: str,
):
    from agentveil_mcp_proxy.console_credentials import load_scoped_runtime_binding_credential

    project = tmp_path / f"project-{connector}"
    project.mkdir()
    home = _seed_project_proxy_identity(project, connector, registered=False)
    _install_machine_summary_console_credentials(tmp_path, monkeypatch)
    binding_state = _install_project_login_binding_stub(monkeypatch)
    _install_connector_status_mocks(monkeypatch, connector)
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        if connector == "cursor":
            from agentveil_mcp_proxy import cursor_setup

            _seed_identity_on_fake_backend(
                state,
                home,
                passphrase_file=cursor_setup.passphrase_path(home),
            )
        else:
            _seed_identity_on_fake_backend(state, home, passphrase=None)
        _set_proxy_home_base_url(home, base_url)
        assert main(_project_login_argv(project, connector)) == 0

    summary = load_credential()
    assert summary is not None
    token = load_scoped_runtime_binding_credential(
        _load(proxy_paths(home).identity_path("proxy"))["did"],
        summary.token,
        home=home,
    )
    assert token is not None
    assert binding_state["calls"] >= 1


def test_project_login_summary_only_stores_scoped_child_per_agent(
    tmp_path,
    monkeypatch,
):
    from agentveil_mcp_proxy.console_credentials import load_scoped_runtime_binding_credential

    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()
    home_a = _seed_project_proxy_identity(project_a, "codex", registered=False)
    home_b = _seed_project_proxy_identity(project_b, "codex", registered=False)
    _install_machine_summary_console_credentials(tmp_path, monkeypatch)
    binding_state = _install_project_login_binding_stub(monkeypatch)
    _install_connector_status_mocks(monkeypatch, "codex")
    _install_project_login_post_login_fences(monkeypatch)

    with _fake_avp_registration_backend() as (base_url, state):
        _seed_identity_on_fake_backend(state, home_a, passphrase=None)
        _set_proxy_home_base_url(home_a, base_url)
        assert main(_project_login_argv(project_a, "codex")) == 0
        _seed_identity_on_fake_backend(state, home_b, passphrase=None)
        _set_proxy_home_base_url(home_b, base_url)
        assert main(_project_login_argv(project_b, "codex")) == 0

    assert binding_state["calls"] == 2
    assert binding_state["agents"][0] != binding_state["agents"][1]
    summary = load_credential()
    token_a = load_scoped_runtime_binding_credential(
        _load(proxy_paths(home_a).identity_path("proxy"))["did"],
        summary.token,
        home=home_a,
    )
    token_b = load_scoped_runtime_binding_credential(
        _load(proxy_paths(home_b).identity_path("proxy"))["did"],
        summary.token,
        home=home_b,
    )
    assert token_a is not None and token_b is not None
    assert token_a.token != token_b.token


def test_project_login_partial_pairing_never_registers(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    home = _seed_project_proxy_identity(project, "codex", registered=False)
    identity_before = _load(proxy_paths(home).identity_path("proxy"))
    avp_home = tmp_path / "machine-avp"
    avp_home.mkdir()
    monkeypatch.setenv("AVP_HOME", str(avp_home))
    client = _FakeConsoleClient(
        start=_console_start(),
        poll_error=PairingClientError("transport_failed"),
    )
    _install_console_client(monkeypatch, client)
    _install_project_login_post_login_fences(monkeypatch)
    register_calls = {"count": 0}
    original_register = proxy_cli.register_proxy

    def counting_register(**kwargs):
        register_calls["count"] += 1
        return original_register(**kwargs)

    monkeypatch.setattr(proxy_cli, "register_proxy", counting_register)

    assert main(_project_login_argv(project, "codex")) != 0
    capsys.readouterr()
    assert register_calls["count"] == 0
    assert _load(proxy_paths(home).identity_path("proxy")) == identity_before


def test_upgrade_ca_policy_preview_never_registers(
    tmp_path,
    monkeypatch,
    capsys,
):
    project = tmp_path / "project"
    project.mkdir()
    _seed_project_proxy_identity(project, "codex", registered=False)
    _install_machine_dual_console_credentials(tmp_path, monkeypatch)

    def forbidden_register(**_kwargs):
        raise AssertionError("register_proxy must not run during upgrade-ca-policy preview")

    monkeypatch.setattr(proxy_cli, "register_proxy", forbidden_register)
    home = project / ".avp"
    assert main(["upgrade-ca-policy", "--home", str(home), "--json"]) in (0, 1)
    capsys.readouterr()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink custody")
def test_identity_force_rewrite_rejects_preplanted_temp_symlink(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    outside = tmp_path / "outside-target.txt"
    outside.write_text("preserve-me", encoding="utf-8")
    predictable_tmp = result.identity_path.with_name(".proxy.json.tmp")
    predictable_tmp.symlink_to(outside)
    proxy_cli._secure_write_json(
        result.identity_path,
        {"tampered": True},
        force=True,
    )
    assert outside.read_text(encoding="utf-8") == "preserve-me"
    assert _load(result.identity_path)["tampered"] is True


def test_project_secret_home_git_excluded_before_identity_creation(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    home = project / ".avp"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    dry_run = subprocess.run(
        ["git", "-C", str(project), "add", "-n", "--", ".avp"],
        capture_output=True,
        text=True,
        check=True,
    )
    staged = dry_run.stdout.strip()
    assert str(result.identity_path.relative_to(project)) not in staged
    assert str(result.control_grant_path.relative_to(project)) not in staged
    ignore = subprocess.run(
        ["git", "-C", str(project), "check-ignore", "-q", "--", ".avp/agents/probe.json"],
        check=False,
    )
    assert ignore.returncode == 0


def test_setup_rejects_pretracked_identity_without_modifying_it(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    identity_path = project / ".avp" / "agents" / "proxy.json"
    identity_path.parent.mkdir(parents=True)
    original = {"name": "proxy", "did": "did:example:tracked", "encrypted": False}
    identity_path.write_text(json.dumps(original), encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(project), "add", "--", ".avp/agents/proxy.json"],
        check=True,
    )
    before = identity_path.read_bytes()
    with pytest.raises(ProxyCliError, match="tracked"):
        init_proxy(
            home=project / ".avp",
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )
    assert identity_path.read_bytes() == before


def test_existing_project_secret_custody_is_preserved_on_repeat_setup(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    home = project / ".avp"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    before_identity = result.identity_path.read_bytes()
    before_grant = result.control_grant_path.read_bytes()
    project_root = proxy_cli._selected_project_root_for_home(home)
    project_root_fd = proxy_cli._open_owner_controlled_directory_fd(project_root)
    home_fd = proxy_cli._open_project_local_runtime_home(home)
    try:
        proxy_cli._prepare_project_local_secret_custody(
            home=home,
            home_fd=home_fd,
            project_root=project_root,
            project_root_fd=project_root_fd,
        )
    finally:
        os.close(home_fd)
        os.close(project_root_fd)
    proxy_cli._ensure_project_local_runtime_home(home)
    assert result.identity_path.read_bytes() == before_identity
    assert result.control_grant_path.read_bytes() == before_grant
    if os.name != "nt":
        assert _mode(result.identity_path) == 0o600
        assert _mode(home) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-local secret custody")
def test_secure_write_json_force_preserves_bytes_when_write_all_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "secret.json"
    proxy_cli._secure_write_json(path, {"keep": True})
    before = path.read_bytes()

    def failing_write_all(fd: int, data: bytes) -> None:
        raise control_artifacts.ControlArtifactError("control_artifact_write_failed")

    monkeypatch.setattr(control_artifacts, "_write_all", failing_write_all)
    with pytest.raises(proxy_cli.ProxyCliError):
        proxy_cli._secure_write_json(path, {"lost": True}, force=True)
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-local secret custody")
def test_secure_write_json_force_serializes_concurrent_rewrites(tmp_path: Path) -> None:
    import threading

    path = tmp_path / "secret.json"
    proxy_cli._secure_write_json(path, {"start": 0})
    errors: list[Exception] = []
    lock = threading.Lock()

    def rewrite(value: int) -> None:
        try:
            proxy_cli._secure_write_json(path, {"value": value}, force=True)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=rewrite, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload["value"], int)


def test_prepare_project_local_secret_git_custody_fails_closed_on_ls_files_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    home = project / ".avp"

    real_run = subprocess.run

    def guarded_run(args, **kwargs):
        if "ls-files" in args:
            return SimpleNamespace(returncode=2, stdout="", stderr="ls-files failed")
        return real_run(args, **kwargs)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.client_guidance.subprocess.run",
        guarded_run,
    )
    with pytest.raises(ProjectSecretGitCustodyError, match="tracked-path query"):
        prepare_project_local_secret_git_custody(project, home)


def test_prepare_project_local_secret_git_custody_fails_closed_on_git_detection_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    home = project / ".avp"
    calls = {"rev_parse": 0}

    real_run = subprocess.run

    def guarded_run(args, **kwargs):
        if args[:4] == ["git", "-C", str(project.resolve()), "rev-parse"]:
            calls["rev_parse"] += 1
            return SimpleNamespace(returncode=1, stdout="", stderr="fatal: git unavailable")
        return real_run(args, **kwargs)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.client_guidance.subprocess.run",
        guarded_run,
    )
    with pytest.raises(ProjectSecretGitCustodyError, match="unavailable"):
        prepare_project_local_secret_git_custody(project, home)
    assert calls["rev_parse"] == 1


def test_prepare_project_local_secret_git_custody_rejects_tracked_proxy_json(
    tmp_path: Path,
) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    tracked = project / ".avp" / "agents" / "proxy.json"
    tracked.parent.mkdir(parents=True)
    tracked.write_text('{"tracked": true}\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(project), "add", "--", ".avp/agents/proxy.json"], check=True)
    before = tracked.read_bytes()
    with pytest.raises(ProjectSecretGitCustodyError, match="tracked"):
        prepare_project_local_secret_git_custody(project, project / ".avp")
    assert tracked.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="Windows global init path")
def test_init_proxy_global_home_skips_project_local_windows_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = {"n": 0}
    real_require = proxy_cli._require_project_local_secret_custody_platform

    def tracked_require() -> None:
        calls["n"] += 1
        real_require()

    monkeypatch.setattr(
        proxy_cli,
        "_require_project_local_secret_custody_platform",
        tracked_require,
    )
    home = tmp_path / "global-avp-home"
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    assert calls["n"] == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows project-local custody branch")
def test_init_proxy_project_local_windows_gate_fails_closed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    with pytest.raises(ProxyCliError, match="Windows"):
        init_proxy(
            home=home,
            agent_name="proxy",
            plaintext=True,
            **_INIT_PROJECT_LOCAL,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows project-local custody branch")
def test_secure_write_json_windows_fail_closed_before_rewrite(tmp_path: Path) -> None:
    path = tmp_path / "secret.json"
    with pytest.raises(ProxyCliError, match="Windows"):
        # Negative test: synthetic payload key only; not an execution-blocking claim.
        proxy_cli._secure_write_json(
            path,
            {"rewrite_guard": True},
            project_local_secret_custody=True,
        )


def test_secure_write_json_project_local_gate_is_caller_controlled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = {"n": 0}
    real_require = proxy_cli._require_project_local_secret_custody_platform

    def tracked_require() -> None:
        calls["n"] += 1
        real_require()

    monkeypatch.setattr(
        proxy_cli,
        "_require_project_local_secret_custody_platform",
        tracked_require,
    )
    proxy_cli._secure_write_json(tmp_path / "global-config.json", {"global": True})
    assert calls["n"] == 0
    proxy_cli._secure_write_json(
        tmp_path / "project-config.json",
        {"project": True},
        project_local_secret_custody=True,
    )
    assert calls["n"] == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime-home parent swap")
def test_init_proxy_anchors_writes_when_home_path_is_swapped(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    external = tmp_path / "external-home"
    external.mkdir()
    external_marker = external / "must-stay-empty.txt"
    external_marker.write_bytes(b"keep\n")
    backup = project / ".avp-pinned-backup"
    real_open = proxy_cli._open_project_local_runtime_home
    swapped = {"done": False}

    def _open_with_swap(path: Path, **kwargs) -> int:
        fd = real_open(path, **kwargs)
        if not swapped["done"]:
            swapped["done"] = True
            home.rename(backup)
            os.symlink(external, home)
        return fd

    monkeypatch.setattr(proxy_cli, "_open_project_local_runtime_home", _open_with_swap)
    # Negative test: expects bounded runtime-home path rejection substring in CLI error.
    with pytest.raises(ProxyCliError, match="safe directory"):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )
    assert external_marker.read_bytes() == b"keep\n"
    assert not (backup / "agents" / "proxy.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX in-home identity symlink custody")
def test_init_proxy_force_rewrite_rejects_in_home_identity_symlink(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    identity_path = home / "agents" / "proxy.json"
    victim = home / "agents" / "victim.json"
    victim.write_text('{"keep": true}\n', encoding="utf-8")
    before = victim.read_bytes()
    identity_path.unlink()
    identity_path.symlink_to(victim)
    with pytest.raises(ProxyCliError, match="could not be written safely"):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            force=True,
            **_INIT_PROJECT_LOCAL,
        )
    assert victim.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinked intermediate directory custody")
def test_init_proxy_rejects_symlinked_agents_directory(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    outside_agents = tmp_path / "outside-agents"
    outside_agents.mkdir()
    marker = outside_agents / "marker.txt"
    marker.write_bytes(b"untouched\n")
    init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    agents_dir = home / "agents"
    backup = home / "agents-real"
    agents_dir.rename(backup)
    agents_dir.symlink_to(outside_agents)
    with pytest.raises(ProxyCliError):
        init_proxy(
            home=home,
            agent_name="other",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            force=True,
            **_INIT_PROJECT_LOCAL,
        )
    assert marker.read_bytes() == b"untouched\n"


def test_init_proxy_project_local_windows_gate_before_directory_open(
    tmp_path: Path,
    monkeypatch,
) -> None:
    directory_opens: list[str] = []
    real_open = os.open

    def _tracking_open(path, flags, mode=0o777, *, dir_fd=None, **kwargs):
        if dir_fd is None and flags & getattr(os, "O_DIRECTORY", 0):
            directory_opens.append(str(path))
        return real_open(path, flags, mode, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(os, "open", _tracking_open)
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    with pytest.raises(ProxyCliError, match="Windows"):
        init_proxy(
            home=home,
            agent_name="proxy",
            plaintext=True,
            **_INIT_PROJECT_LOCAL,
        )
    assert directory_opens == []


def test_init_proxy_closes_custody_home_fd_on_trusted_signer_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    tracked_fd = {"value": None}
    real_open_home = proxy_cli._open_project_local_runtime_home
    closed: list[int] = []
    real_close = os.close

    def _open_and_track(path: Path, **kwargs) -> int:
        fd = real_open_home(path, **kwargs)
        tracked_fd["value"] = fd
        return fd

    def _track_close(fd: int) -> None:
        if tracked_fd["value"] is not None and fd == tracked_fd["value"]:
            closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(proxy_cli, "_open_project_local_runtime_home", _open_and_track)
    monkeypatch.setattr(os, "close", _track_close)
    monkeypatch.setattr(proxy_cli, "trusted_signers_for_base_url", lambda _url: ())
    with pytest.raises(ProxyCliError, match="trusted signer"):
        init_proxy(
            home=home,
            agent_name="proxy",
            plaintext=True,
            **_INIT_PROJECT_LOCAL,
        )
    assert tracked_fd["value"] is not None
    assert closed == [tracked_fd["value"]]


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime-home parent swap")
def test_ensure_project_local_runtime_home_rejects_parent_directory_swap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    home.mkdir(mode=0o755)
    external = tmp_path / "external-home"
    external.mkdir(mode=0o755)
    backup = tmp_path / "project-pinned-backup"
    original_open = os.open
    swapped = {"done": False}

    def _opening(path, flags, mode=0o777, *, dir_fd=None, **kwargs):
        fd = original_open(path, flags, mode, dir_fd=dir_fd, **kwargs)
        if (
            dir_fd is None
            and not swapped["done"]
            and str(path) == str(project)
            and flags & os.O_DIRECTORY
        ):
            swapped["done"] = True
            project.rename(backup)
            os.symlink(external, project)
        return fd

    monkeypatch.setattr(os, "open", _opening)
    # Negative test: expects bounded runtime-home path rejection substring in CLI error.
    with pytest.raises(ProxyCliError, match="safe directory|unavailable"):
        proxy_cli._ensure_project_local_runtime_home(home)
    assert stat.S_IMODE(external.stat().st_mode) == 0o755
    assert backup.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX lock custody")
def test_local_secret_write_lock_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    target = result.identity_path
    lock_path = target.with_name(f".{target.name}.write-lock")
    victim = tmp_path / "victim-lock.txt"
    victim.write_text("keep\n", encoding="utf-8")

    if lock_path.exists():
        lock_path.unlink()
    lock_path.symlink_to(victim)
    with pytest.raises(ProxyCliError):
        proxy_cli._secure_write_json(target, {"x": 1}, force=True)
    assert victim.read_text(encoding="utf-8") == "keep\n"

    lock_path.unlink()
    real_lock = tmp_path / "real-lock"
    real_lock.write_text("lock\n", encoding="utf-8")
    os.link(real_lock, lock_path)
    with pytest.raises(ProxyCliError):
        proxy_cli._secure_write_json(target, {"x": 2}, force=True)
    assert real_lock.read_text(encoding="utf-8") == "lock\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX hardlink custody")
def test_secure_write_json_rejects_hardlinked_identity_target(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    home = project / ".avp"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    target = result.identity_path
    before = target.read_bytes()
    peer = home / "identity-hardlink"
    os.link(target, peer)
    try:
        # Negative test: expects bounded local secret file path rejection substring.
        with pytest.raises(ProxyCliError, match="safe file"):
            proxy_cli._secure_write_json(target, {"tampered": True}, force=True)
        assert target.read_bytes() == before
        assert peer.read_bytes() == before
    finally:
        peer.unlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime-home permissions")
def test_init_proxy_non_custody_creates_missing_runtime_home_0700(tmp_path: Path) -> None:
    home = tmp_path / "avp-home"
    assert not home.exists()
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
    )
    assert result.identity_path.is_file()
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert stat.S_IMODE((home / "agents").stat().st_mode) == 0o700
    assert stat.S_IMODE((home / "mcp-proxy").stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime-home permissions")
def test_init_proxy_non_custody_accepts_existing_owner_controlled_0755_runtime_home(
    tmp_path: Path,
) -> None:
    home = tmp_path / "avp-home"
    home.mkdir(mode=0o755)
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
    )
    assert result.identity_path.is_file()
    assert stat.S_IMODE(home.stat().st_mode) == 0o755
    assert (home / "agents" / "proxy.json").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink custody")
def test_init_proxy_rejects_symlinked_custom_runtime_home_without_target_writes(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external-runtime"
    external.mkdir(mode=0o700)
    marker = external / "must-stay-empty.txt"
    marker.write_bytes(b"keep\n")
    home = project / "custom-runtime-home"
    os.symlink(external, home, target_is_directory=True)
    with pytest.raises(
        ProxyCliError,
        match=proxy_cli._PROJECT_LOCAL_RUNTIME_HOME_NOT_ACCEPTABLE,
    ):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
        )
    assert marker.read_bytes() == b"keep\n"
    assert not (external / "agents").exists()
    assert not (external / "mcp-proxy").exists()
    assert not (project / "custom-runtime-home" / "agents").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink custody")
def test_init_proxy_rejects_symlinked_avp_without_external_git_mutation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    external = tmp_path / "external-git"
    external.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=external, check=True)
    external_exclude = external / ".git" / "info" / "exclude"
    before_exclude = (
        external_exclude.read_bytes() if external_exclude.is_file() else b""
    )
    external_avp = external / ".avp"
    external_avp.mkdir(mode=0o700)
    home = project / ".avp"
    os.symlink(external_avp, home, target_is_directory=True)
    with pytest.raises(ProxyCliError):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )
    assert external_exclude.read_bytes() == before_exclude


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime-home parent swap")
def test_init_proxy_home_swap_before_git_custody_skips_git_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    exclude_path = project / ".git" / "info" / "exclude"
    before_exclude = exclude_path.read_bytes() if exclude_path.is_file() else b""
    home = project / ".avp"
    external = tmp_path / "external-home"
    external.mkdir(mode=0o700)
    backup = project / ".avp-pinned-backup"
    real_prepare = proxy_cli._prepare_project_local_secret_custody
    swapped = {"done": False}

    def _prepare_with_swap(**kwargs):
        if not swapped["done"]:
            swapped["done"] = True
            home_path = Path(kwargs["home"])
            home_path.rename(backup)
            os.symlink(external, home_path)
        return real_prepare(**kwargs)

    monkeypatch.setattr(proxy_cli, "_prepare_project_local_secret_custody", _prepare_with_swap)
    # Negative test: expects bounded runtime-home path rejection substring in CLI error.
    with pytest.raises(ProxyCliError, match="safe directory"):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )
    assert exclude_path.read_bytes() == before_exclude


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-root parent swap")
def test_init_proxy_rejects_project_root_swap_without_external_avp_creation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external-project"
    external.mkdir(mode=0o755)
    external_marker = external / "must-stay-empty.txt"
    external_marker.write_bytes(b"keep\n")
    home = project / ".avp"
    backup = tmp_path / "project-pinned-backup"
    real_open_root = proxy_cli._open_owner_controlled_directory_fd
    swapped = {"done": False}

    def _open_root_with_swap(path: Path) -> int:
        fd = real_open_root(path)
        if not swapped["done"]:
            swapped["done"] = True
            project.rename(backup)
            os.symlink(external, project)
        return fd

    monkeypatch.setattr(proxy_cli, "_open_owner_controlled_directory_fd", _open_root_with_swap)
    # Negative test: expects bounded runtime-home path rejection substring in CLI error.
    with pytest.raises(ProxyCliError, match="safe directory"):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )
    assert external_marker.read_bytes() == b"keep\n"
    assert not (external / ".avp").exists()
    assert backup.is_dir()
    assert not (backup / "agents").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-root permissions")
def test_init_proxy_rejects_group_writable_project_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    os.chmod(project, 0o775)
    home = project / ".avp"
    with pytest.raises(ProxyCliError, match="writable by other users"):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-root permissions")
def test_init_proxy_rejects_world_writable_project_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    os.chmod(project, 0o777)
    home = project / ".avp"
    with pytest.raises(ProxyCliError, match="writable by other users"):
        init_proxy(
            home=home,
            agent_name="proxy",
            policy_pack="github",
            passphrase=TEST_PASSPHRASE,
            **_INIT_PROJECT_LOCAL,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX project-root permissions")
def test_init_proxy_allows_owner_controlled_0755_project_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o755)
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    home = project / ".avp"
    result = init_proxy(
        home=home,
        agent_name="proxy",
        policy_pack="github",
        passphrase=TEST_PASSPHRASE,
        **_INIT_PROJECT_LOCAL,
    )
    assert result.identity_path.is_file()
    assert stat.S_IMODE(home.stat().st_mode) == 0o700


def _seed_populated_external_proxy_home(external: Path) -> bytes:
    config_dir = external / "mcp-proxy"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.json"
    body = json.dumps({"approval": {"wait_for_decision": False}, "marker": "keep-bytes"}) + "\n"
    config_path.write_text(body, encoding="utf-8")
    if os.name != "nt":
        os.chmod(config_path, 0o600)
    return body.encode("utf-8")


_CONNECTOR_SYMLINK_HOME_CASES = [
    ("claude-code", ["setup", "claude-code", "--project-dir"]),
    ("codex", ["setup", "codex", "--project-dir"]),
    ("gemini-cli", ["setup", "gemini-cli", "--project-dir"]),
    ("cursor", ["setup", "cursor", "--workspace"]),
]


@pytest.mark.parametrize(("connector", "setup_prefix"), _CONNECTOR_SYMLINK_HOME_CASES)
@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink custody")
def test_connector_setup_rejects_populated_symlinked_runtime_home(
    tmp_path: Path,
    monkeypatch,
    connector: str,
    setup_prefix: list[str],
) -> None:
    from agentveil_mcp_proxy import agent_launcher

    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    exclude_path = project / ".git" / "info" / "exclude"
    before_exclude = exclude_path.read_bytes() if exclude_path.is_file() else b""

    external = tmp_path / "external-home"
    external.mkdir(mode=0o700)
    before_config = _seed_populated_external_proxy_home(external)

    home = _connector_runtime_home(project, connector)
    os.symlink(external, home, target_is_directory=True)

    init_calls: list[dict] = []

    def track_init_proxy(**kwargs):
        init_calls.append(kwargs)
        return _init_proxy_for_connector_setup(**kwargs)

    monkeypatch.setattr(proxy_cli, "init_proxy", track_init_proxy)
    defaults_calls: list[Path] = []
    real_defaults = agent_launcher.ensure_interactive_connector_defaults

    def track_defaults(config_path: Path) -> None:
        defaults_calls.append(config_path)
        return real_defaults(config_path)

    monkeypatch.setattr(agent_launcher, "ensure_interactive_connector_defaults", track_defaults)

    assert main([*setup_prefix, str(project), "--yes"]) != 0
    assert not init_calls
    assert not defaults_calls
    assert (external / "mcp-proxy" / "config.json").read_bytes() == before_config
    assert exclude_path.read_bytes() == before_exclude


@pytest.mark.parametrize("wait_for_decision", [False, True])
@pytest.mark.skipif(os.name == "nt", reason="POSIX hardlink custody")
def test_connector_setup_rejects_hardlinked_populated_proxy_config(
    tmp_path: Path,
    monkeypatch,
    wait_for_decision: bool,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    home = project / ".avp"
    _init_proxy_for_connector_setup(home=home)
    config_path = home / "mcp-proxy" / "config.json"
    before = json.dumps(
        {"approval": {"wait_for_decision": wait_for_decision}, "marker": "keep-bytes"}
    ) + "\n"
    config_path.write_text(before, encoding="utf-8")
    if os.name != "nt":
        os.chmod(config_path, 0o600)
    peer = config_path.parent / "config-peer.json"
    try:
        os.link(config_path, peer)
    except OSError:
        pytest.skip("hardlinks unavailable")

    _install_connector_setup_success_mocks(monkeypatch, "claude-code")

    assert main(["setup", "claude-code", "--project-dir", str(project), "--yes"]) != 0
    assert config_path.read_text(encoding="utf-8") == before
    assert peer.read_text(encoding="utf-8") == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX legacy mcp-proxy custody")
def test_configure_downstream_tightens_owner_controlled_0755_mcp_proxy(
    tmp_path: Path,
) -> None:
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    config_dir = home / "mcp-proxy"
    os.chmod(config_dir, 0o755)
    before_config = _load(result.config_path)
    before_config.setdefault("approval", {})["wait_for_decision"] = False
    result.config_path.write_text(json.dumps(before_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sandbox = tmp_path / "sandbox"

    configure_downstream(
        home=home,
        name="filesystem",
        command=sys.executable,
        args=("-m", "agentveil_mcp_proxy.quickstart_filesystem", str(sandbox)),
        response_timeout_seconds=5.0,
    )

    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    payload = json.loads(result.config_path.read_text(encoding="utf-8"))
    assert payload["downstream"]["name"] == "filesystem"
    assert payload["approval"]["wait_for_decision"] is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX legacy mcp-proxy custody")
def test_configure_downstream_rejects_symlinked_mcp_proxy_without_chmod(
    tmp_path: Path,
) -> None:
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    config_dir = home / "mcp-proxy"
    valid_config = (config_dir / "config.json").read_text(encoding="utf-8")
    external = tmp_path / "external-mcp-proxy"
    external.mkdir(mode=0o755)
    before_mode = stat.S_IMODE(external.stat().st_mode)
    (external / "config.json").write_text(valid_config, encoding="utf-8")
    shutil.rmtree(config_dir)
    os.symlink(external, config_dir, target_is_directory=True)
    sandbox = tmp_path / "sandbox"

    # Negative test: expects bounded storage-directory preparation failure substring.
    with pytest.raises(ProxyCliError, match="cannot secure local secret storage directory"):
        configure_downstream(
            home=home,
            name="filesystem",
            command=sys.executable,
            args=("-m", "agentveil_mcp_proxy.quickstart_filesystem", str(sandbox)),
        )

    assert stat.S_IMODE(external.stat().st_mode) == before_mode


@pytest.mark.skipif(os.name == "nt", reason="POSIX legacy mcp-proxy custody")
def test_configure_claude_setup_approval_ui_tightens_owner_controlled_0755_mcp_proxy(
    tmp_path: Path,
) -> None:
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    config_dir = home / "mcp-proxy"
    os.chmod(config_dir, 0o755)
    config_path = config_dir / "config.json"
    before = json.dumps({"approval": {"wait_for_decision": False}, "marker": "keep-bytes"}) + "\n"
    config_path.write_text(before, encoding="utf-8")

    proxy_cli._configure_claude_setup_approval_ui(config_path, home=home)

    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["approval"]["ui_open_mode"] == "terminal"
    assert payload["marker"] == "keep-bytes"


@pytest.mark.skipif(os.name == "nt", reason="POSIX legacy mcp-proxy custody")
def test_configure_claude_setup_approval_ui_rejects_symlinked_mcp_proxy_without_chmod(
    tmp_path: Path,
) -> None:
    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    external = tmp_path / "external-mcp-proxy"
    external.mkdir(mode=0o755)
    before_mode = stat.S_IMODE(external.stat().st_mode)
    victim = json.dumps({"approval": {"wait_for_decision": False}, "marker": "keep-bytes"}) + "\n"
    config_path = external / "config.json"
    config_path.write_text(victim, encoding="utf-8")
    config_dir = home / "mcp-proxy"
    shutil.rmtree(config_dir)
    os.symlink(external, config_dir, target_is_directory=True)

    # Negative test: expects bounded storage-directory preparation failure substring.
    with pytest.raises(ProxyCliError, match="cannot secure local secret storage directory"):
        proxy_cli._configure_claude_setup_approval_ui(config_dir / "config.json", home=home)

    assert stat.S_IMODE(external.stat().st_mode) == before_mode
    assert config_path.read_text(encoding="utf-8") == victim
