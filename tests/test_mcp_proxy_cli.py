"""P2 tests for minimal MCP proxy CLI init/run/doctor."""

from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path

from agentveil.delegation import verify_delegation
from agentveil_mcp_proxy.cli import (
    AGENTVEIL_DEV_SIGNER_DIDS,
    ProxyCliError,
    doctor_proxy,
    init_proxy,
    main,
    proxy_paths,
    run_proxy_stub,
)
from agentveil_mcp_proxy.policy import ProxyConfig


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_init_creates_identity_config_and_control_grant_with_0600(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy", policy_pack="github")

    assert result.identity_path == home / "agents" / "proxy.json"
    assert result.config_path == home / "mcp-proxy" / "config.json"
    assert result.control_grant_path == home / "mcp-proxy" / "proxy.control-grant.json"
    assert _mode(result.identity_path) == 0o600
    assert _mode(result.config_path) == 0o600
    assert _mode(result.control_grant_path) == 0o600
    assert _mode(result.identity_path.parent) == 0o700
    assert _mode(result.config_path.parent) == 0o700

    identity = _load(result.identity_path)
    assert identity["name"] == "proxy"
    assert identity["did"] == result.agent_did
    assert "private_key_hex" in identity
    assert identity["encrypted"] is False

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


def test_init_refuses_to_overwrite_existing_identity_without_force(tmp_path):
    home = tmp_path / "avp-home"
    first = init_proxy(home=home, agent_name="proxy")
    first_identity = _load(first.identity_path)

    try:
        init_proxy(home=home, agent_name="proxy")
    except ProxyCliError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected init to refuse overwrite")

    assert _load(first.identity_path)["did"] == first_identity["did"]

    second = init_proxy(home=home, agent_name="proxy", force=True)
    assert second.agent_did != first.agent_did
    assert _load(second.identity_path)["did"] == second.agent_did


def test_init_requires_explicit_trusted_signer_for_unknown_base_url(tmp_path):
    try:
        init_proxy(home=tmp_path / "avp-home", base_url="https://avp.example.test")
    except ProxyCliError as exc:
        assert "trusted signer DID" in str(exc)
    else:
        raise AssertionError("expected init to require trusted signer DID")

    result = init_proxy(
        home=tmp_path / "avp-home",
        base_url="https://avp.example.test",
        trusted_signer_dids=["did:key:z6MkcustomSigner"],
    )
    config = ProxyConfig.from_dict(_load(result.config_path))
    assert config.avp.trusted_signer_dids == ("did:key:z6MkcustomSigner",)


def test_doctor_fails_when_trusted_signers_empty(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy")
    config = _load(result.config_path)
    config["avp"]["trusted_signer_dids"] = []
    result.config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(result.config_path, 0o600)

    out = io.StringIO()
    code = doctor_proxy(home=home, out=out)

    assert code == 1
    assert "trusted_signer_dids" in out.getvalue()
    identity = _load(result.identity_path)
    assert identity["private_key_hex"] not in out.getvalue()


def test_doctor_fails_on_insecure_identity_permissions(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy")
    os.chmod(result.identity_path, 0o644)

    out = io.StringIO()
    code = doctor_proxy(home=home, out=out)

    assert code == 1
    assert "permissions must be 0600" in out.getvalue()


def test_doctor_passes_after_init_without_printing_secrets(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy")
    private_key = _load(result.identity_path)["private_key_hex"]

    out = io.StringIO()
    code = doctor_proxy(home=home, out=out)

    assert code == 0
    assert "OK: trusted signers 2" in out.getvalue()
    assert private_key not in out.getvalue()


def test_run_validates_config_then_refuses_until_p3_transport(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy")
    private_key = _load(result.identity_path)["private_key_hex"]

    out = io.StringIO()
    code = run_proxy_stub(home=home, out=out)

    assert code == 3
    assert "MCP transport is not implemented until P3" in out.getvalue()
    assert private_key not in out.getvalue()


def test_run_does_not_start_without_trusted_signer_config(tmp_path):
    home = tmp_path / "avp-home"
    result = init_proxy(home=home, agent_name="proxy")
    config = _load(result.config_path)
    config["avp"]["trusted_signer_dids"] = []
    result.config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(result.config_path, 0o600)

    try:
        run_proxy_stub(home=home)
    except ProxyCliError as exc:
        assert exc.exit_code == 1
        assert "trusted_signer_dids" in str(exc)
    else:
        raise AssertionError("expected run to refuse invalid trusted signer config")


def test_main_init_doctor_and_run_exit_codes(tmp_path, capsys):
    home = tmp_path / "avp-home"

    assert main(["init", "--home", str(home), "--agent-name", "proxy"]) == 0
    created = capsys.readouterr()
    assert "Created MCP proxy identity:" in created.out
    private_key = _load(proxy_paths(home).identity_path("proxy"))["private_key_hex"]
    assert private_key not in created.out

    assert main(["doctor", "--home", str(home)]) == 0
    doctor = capsys.readouterr()
    assert "OK: trusted signers" in doctor.out
    assert private_key not in doctor.out

    assert main(["run", "--home", str(home)]) == 3
    run = capsys.readouterr()
    assert "not implemented until P3" in run.out
    assert private_key not in run.out
