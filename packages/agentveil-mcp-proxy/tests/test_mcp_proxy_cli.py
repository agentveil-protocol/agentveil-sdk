"""P2 tests for minimal MCP proxy CLI init/run/doctor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import stat
import sys

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


TEST_PASSPHRASE = "correct horse battery staple"
WRONG_PASSPHRASE = "wrong horse battery staple"


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


def test_read_passphrase_file_skips_perm_check_on_windows(tmp_path, monkeypatch):
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o644)
    monkeypatch.setattr(proxy_cli.os, "name", "nt")

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
    assert "OK: downstream filesystem answered initialize/tools/list (2 tools)" in out.getvalue()


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
    assert payload["downstream"]["tool_count"] == 2
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
    assert result.tool_count == 2
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
    assert result.tool_count == 2
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert payload["downstream"]["name"] == "filesystem"
    assert payload["downstream"]["tool_count"] == 2
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
    assert summary["record_count"] == 1
    assert summary["receipt_present_count"] == 1
    assert "req-events" not in summary_out.getvalue()


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
    assert payload["downstream"]["name"] == "filesystem"
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


def test_main_init_json_supports_noninteractive_downstream_flags(tmp_path, capsys):
    home = tmp_path / "avp-home"
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_text(TEST_PASSPHRASE, encoding="utf-8")
    os.chmod(passphrase_file, 0o600)
    sandbox = tmp_path / "sandbox"

    exit_code = main([
        "init",
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
    assert _load(proxy_paths(home).config_path)["downstream"]["args"][-1] == str(sandbox)


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
        "--home",
        str(home),
        "--agent-name",
        "proxy",
        "--passphrase",
        TEST_PASSPHRASE,
    ]) == 0
    created = capsys.readouterr()
    assert "Created MCP proxy identity:" in created.out
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
