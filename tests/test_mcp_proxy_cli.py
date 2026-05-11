"""P2 tests for minimal MCP proxy CLI init/run/doctor."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path

import pytest

from agentveil.delegation import verify_delegation
from agentveil_mcp_proxy.cli import (
    AGENTVEIL_DEV_SIGNER_DIDS,
    ProxyCliError,
    doctor_proxy,
    export_evidence,
    init_proxy,
    main,
    proxy_paths,
    reissue_grant,
    run_proxy,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, PendingApproval
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
