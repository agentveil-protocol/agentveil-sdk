"""P2 tests for minimal MCP proxy CLI init/run/doctor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

import agentveil_mcp_proxy.cli as proxy_cli
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
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, PendingApproval
from agentveil_mcp_proxy.identity import encrypted_identity_payload, load_agent_from_identity
from agentveil_mcp_proxy.policy import ProxyConfig
from agentveil_mcp_proxy.quickstart_filesystem import _tools as quickstart_filesystem_tools


TEST_PASSPHRASE = "correct horse battery staple"
WRONG_PASSPHRASE = "wrong horse battery staple"


def _quickstart_filesystem_tool_count() -> int:
    return len(quickstart_filesystem_tools())


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


def test_secure_write_json_fsyncs_before_close(tmp_path, monkeypatch):
    calls: list[int] = []

    def fake_fsync(fd: int) -> None:
        os.fstat(fd)
        calls.append(fd)

    monkeypatch.setattr(proxy_cli.os, "fsync", fake_fsync)

    proxy_cli._secure_write_json(tmp_path / "config.json", {"ok": True})

    assert calls


def test_secure_write_json_force_fsyncs_parent_directory_on_posix(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("directory fsync is POSIX-specific")
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


def test_register_already_registered_returns_ok(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity_before = _load(result.identity_path)
    _install_fake_register(
        monkeypatch,
        raises=AVPValidationError("agent already exists", 409, "conflict"),
    )

    out = io.StringIO()
    code = register_proxy(home=home, passphrase=TEST_PASSPHRASE, out=out)

    output = out.getvalue()
    assert code == 0
    assert "already registered" in output

    # The 409 path must keep the identity encrypted and update the
    # local `registered` / `verified` flags to True so the file is not
    # left in a stale state contradicting the CLI message.
    identity_after = _load(result.identity_path)
    assert identity_after["did"] == identity_before["did"]
    assert identity_after["encrypted"] is True
    assert "private_key_hex" not in identity_after
    assert identity_after.get("registered") is True
    assert identity_after.get("verified") is True
    if os.name != "nt":
        assert _mode(result.identity_path) == 0o600


def test_register_already_registered_json_reports_warning(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", passphrase=TEST_PASSPHRASE)
    identity = _load(result.identity_path)
    _install_fake_register(
        monkeypatch,
        raises=AVPValidationError("agent already exists", 409, "conflict"),
    )

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


def test_cli_setup_status_home_routes_to_wizard(tmp_path, capsys):
    # --home routes to the adaptive wizard, NOT the connector status.
    home = tmp_path / "avp-home"
    home.mkdir()
    rc = main(["setup", "status", "--home", str(home), "--json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    # wizard output must not carry the connector-only keys
    assert "mcp_route" not in payload
    assert "hook" not in payload or "next_step" not in payload


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
    from agentveil_mcp_proxy import claude_center_lifecycle

    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    seen: dict[str, object] = {}

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
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
    monkeypatch.setattr(claude_center_lifecycle, "ensure_running", fake_ensure_running)

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
    from agentveil_mcp_proxy import claude_center_lifecycle

    selected = tmp_path / "Selected Project"
    selected.mkdir()
    seen: dict[str, object] = {}

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")
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
        claude_center_lifecycle,
        "ensure_running",
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
    from agentveil_mcp_proxy import claude_center_lifecycle, gemini_setup

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

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
    monkeypatch.setattr(claude_center_lifecycle, "ensure_running", _fake_running_approval_center)

    rc = main(["setup", "gemini-cli", "--project-dir", str(tmp_path), "--yes", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    _assert_setup_enables_approval_wait_mode(tmp_path)


def test_cli_setup_codex_enables_approval_wait_mode(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import claude_center_lifecycle, codex_setup

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

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
    monkeypatch.setattr(claude_center_lifecycle, "ensure_running", _fake_running_approval_center)

    rc = main(["setup", "codex", "--project-dir", str(tmp_path), "--yes", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    _assert_setup_enables_approval_wait_mode(tmp_path)


def test_cli_setup_cursor_enables_approval_wait_mode(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy import cursor_setup

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

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
    from agentveil_mcp_proxy import claude_center_lifecycle

    def fake_init_proxy(**kwargs):
        home = kwargs["home"]
        (home / "mcp-proxy").mkdir(parents=True, exist_ok=True)
        (home / "mcp-proxy" / "config.json").write_text("{}", encoding="utf-8")

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
    monkeypatch.setattr(claude_center_lifecycle, "ensure_running", fake_ensure_running)

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
