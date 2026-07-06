"""UX contract tests for agentveil-mcp-proxy verify."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.cli import verify_evidence
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.approval_grant import APPROVAL_GRANT_SCHEMA, build_approval_grant
from agentveil_mcp_proxy.evidence.proof import build_evidence_bundle
from agentveil_mcp_proxy.evidence.verify_output import (
    VERIFY_CHAIN_ONLY,
    VERIFY_FAILED_UNEXPECTED,
    VERIFY_NO_SIGNED_EVIDENCE,
    VERIFY_PASSED,
    VERIFY_REQUIRES_TRUST_ROOTS,
    classify_verify_payload,
    privacy_markers_in_text,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = PACKAGE_ROOT.parent.parent

GRANT_SEED = bytes.fromhex("33" * 32)
GRANT_DID = _public_key_to_did(bytes(SigningKey(GRANT_SEED).verify_key))
APPROVAL_TOKEN_HASH = "sha256:" + "e" * 64
PAYLOAD_HASH = "sha256:" + "a" * 64
RESOURCE_HASH = "sha256:" + "b" * 64


def _clean_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


def _record(request_id: str = "req-grant") -> PendingApproval:
    return PendingApproval(
        request_id=request_id,
        session_id="session-1",
        client_id="cursor:test",
        downstream_server="github-mcp",
        tool_name="github.create_issue",
        action_class="write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=PAYLOAD_HASH,
        policy_id="github-default",
        policy_rule_id="rule-write",
        policy_context_hash="c" * 64,
        status=ApprovalStatus.PENDING.value,
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
    )


def _store(tmp_path: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(tmp_path / "evidence.sqlite")


def _approve_with_grant(store: ApprovalEvidenceStore, *, request_id: str = "req-grant") -> PendingApproval:
    record = _record(request_id)
    store.write_pending(record)
    grant_jcs = build_approval_grant(
        {
            "schema_version": APPROVAL_GRANT_SCHEMA,
            "agent_did": GRANT_DID,
            "request_id": record.request_id,
            "downstream_server": record.downstream_server,
            "tool_name": record.tool_name,
            "action_class": record.action_class,
            "risk_class": record.risk_class,
            "resource_hash": record.resource_hash,
            "payload_hash": record.payload_hash,
            "policy_id": record.policy_id,
            "policy_rule_id": record.policy_rule_id,
            "policy_context_hash": record.policy_context_hash,
            "decision": "APPROVED",
            "approval_scope": "exact",
            "decided_by": "local-user",
            "issued_at": record.created_at,
            "expires_at": record.expires_at,
            "granted_by_request_id": record.granted_by_request_id,
        },
        GRANT_SEED,
    )
    return store.transition(
        request_id,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
        approval_decided_by="local-user",
        approval_scope="exact",
        user_decision_timestamp=record.created_at,
        approval_grant_jcs=grant_jcs,
    )


def _bundle_with_approval_grant(tmp_path: Path) -> dict:
    with _store(tmp_path) as store:
        _approve_with_grant(store)
        return build_evidence_bundle(
            store,
            proxy_identity_did=GRANT_DID,
            trusted_signer_dids=[GRANT_DID],
        )


def _assert_verify_privacy(*texts: str) -> None:
    combined = "\n".join(text for text in texts if text)
    assert privacy_markers_in_text(combined) == []
    assert "approval_grant_jcs" not in combined


def _build_wheel_installed_cli(tmp_path: Path) -> tuple[Path, Path]:
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    env = _clean_env()
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(SDK_ROOT), "-w", str(wheelhouse), "-q"],
        check=True,
        env=env,
        cwd=str(tmp_path),
    )
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(PACKAGE_ROOT), "-w", str(wheelhouse), "--no-deps", "-q"],
        check=True,
        env=env,
        cwd=str(tmp_path),
    )
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    pip = venv / ("Scripts/pip" if os.name == "nt" else "bin/pip")
    subprocess.run(
        [str(pip), "install", "--no-index", f"--find-links={wheelhouse}", "agentveil", "agentveil-mcp-proxy", "-q"],
        check=True,
        env=env,
        cwd=str(tmp_path),
    )
    show = subprocess.run(
        [str(pip), "show", "agentveil-mcp-proxy"],
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    assert "Editable project location" not in show.stdout
    python = venv / ("Scripts/python" if os.name == "nt" else "bin/python")
    module_probe = subprocess.run(
        [str(python), "-c", "import agentveil_mcp_proxy.cli as c; print(c.__file__)"],
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    assert "site-packages" in module_probe.stdout
    assert str(PACKAGE_ROOT.resolve()) not in module_probe.stdout
    cli = venv / ("Scripts/agentveil-mcp-proxy" if os.name == "nt" else "bin/agentveil-mcp-proxy")
    return cli, python


def test_verify_missing_trust_roots_is_bounded_and_classified(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle_with_approval_grant(tmp_path)), encoding="utf-8")

    human = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=human) == 1
    human_text = human.getvalue()
    _assert_verify_privacy(human_text)
    assert "VERIFY: requires_trust_roots" in human_text
    assert "trusted signer DIDs" in human_text
    assert "Export was parsed" in human_text
    assert "not completed" in human_text

    json_out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, output_format="json", out=json_out) == 1
    payload = json.loads(json_out.getvalue())
    _assert_verify_privacy(json_out.getvalue())
    assert payload["contract"] == VERIFY_REQUIRES_TRUST_ROOTS
    assert payload["status"] == "requires_trust_roots"
    assert payload["bundle_parsed"] is True
    assert payload["approval_grant_count"] == 1
    assert payload["trust_verification_completed"] is False
    assert "approval_grant_jcs" not in json.dumps(payload)


def test_verify_with_trusted_signer_passes_and_is_bounded(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle_with_approval_grant(tmp_path)), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        trusted_signer_dids=[GRANT_DID],
        out=out,
    ) == 0
    human = out.getvalue()
    _assert_verify_privacy(human)
    assert "VERIFY: passed" in human

    json_out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        output_format="json",
        trusted_signer_dids=[GRANT_DID],
        out=json_out,
    ) == 0
    payload = json.loads(json_out.getvalue())
    assert payload["contract"] == VERIFY_PASSED
    assert payload["trust_verification_completed"] is True
    assert payload["verified_approval_grant_count"] == 1
    assert payload["trusted_signer_count"] == 1
    assert payload["trusted_signer_refs"]


def test_verify_unexpected_failure_is_classified(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle = _bundle_with_approval_grant(tmp_path)
    bundle["records"][0]["record_hash"] = "sha256:" + "0" * 64
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        output_format="json",
        trusted_signer_dids=[GRANT_DID],
        out=out,
    ) == 1
    payload = json.loads(out.getvalue())
    _assert_verify_privacy(out.getvalue())
    assert payload["contract"] == VERIFY_FAILED_UNEXPECTED
    assert payload["status"] == "invalid"


def test_verify_contract_lib_classifies_verify_contracts() -> None:
    assert classify_verify_payload({"contract": VERIFY_PASSED}) == VERIFY_PASSED
    assert classify_verify_payload({"contract": VERIFY_NO_SIGNED_EVIDENCE}) == VERIFY_NO_SIGNED_EVIDENCE
    assert classify_verify_payload({"contract": VERIFY_CHAIN_ONLY}) == VERIFY_CHAIN_ONLY
    assert classify_verify_payload({"contract": VERIFY_REQUIRES_TRUST_ROOTS}) == VERIFY_REQUIRES_TRUST_ROOTS
    assert classify_verify_payload({"contract": VERIFY_FAILED_UNEXPECTED}) == VERIFY_FAILED_UNEXPECTED
    assert classify_verify_payload({"status": "ok"}) == VERIFY_PASSED
    assert classify_verify_payload({"status": "no_signed_evidence"}) == VERIFY_NO_SIGNED_EVIDENCE
    assert classify_verify_payload({"status": "chain_only"}) == VERIFY_CHAIN_ONLY
    assert classify_verify_payload({"status": "requires_trust_roots"}) == VERIFY_REQUIRES_TRUST_ROOTS


def test_verify_empty_bundle_is_honest_human_and_json(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=None,
            trusted_signer_dids=[],
        )
    bundle_path = tmp_path / "empty.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    human = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=human) == 0
    human_text = human.getvalue()
    _assert_verify_privacy(human_text)
    assert "VERIFY: no_signed_evidence" in human_text
    assert "VERIFY: passed" not in human_text
    assert "Records: 0; signed_receipt_count: 0" in human_text
    assert "Nothing to prove." in human_text

    json_out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, output_format="json", out=json_out) == 0
    payload = json.loads(json_out.getvalue())
    _assert_verify_privacy(json_out.getvalue())
    assert payload["contract"] == VERIFY_NO_SIGNED_EVIDENCE
    assert payload["status"] == "no_signed_evidence"
    assert payload["proof_grade"] == "none"
    assert payload["trust_verification_completed"] is False


def test_verify_chain_only_bundle_is_qualified_human_and_json(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.write_pending(_record("req-chain-only"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=GRANT_DID,
            trusted_signer_dids=[],
        )
    bundle_path = tmp_path / "chain-only.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    human = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=human) == 0
    human_text = human.getvalue()
    _assert_verify_privacy(human_text)
    assert "VERIFY: chain_only" in human_text
    assert "VERIFY: passed" not in human_text
    assert "signed_receipt_count: 0" in human_text
    assert "chain-only, not third-party signed proof" in human_text

    json_out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, output_format="json", out=json_out) == 0
    payload = json.loads(json_out.getvalue())
    assert payload["contract"] == VERIFY_CHAIN_ONLY
    assert payload["status"] == "chain_only"
    assert payload["proof_grade"] == "chain_only"
    assert payload["record_count"] == 1
    assert payload["signed_receipt_count"] == 0
    assert payload["trust_verification_completed"] is False


def test_wheel_installed_verify_cli_probe(tmp_path: Path) -> None:
    cli, _python = _build_wheel_installed_cli(tmp_path)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle_with_approval_grant(tmp_path)), encoding="utf-8")
    env = _clean_env()

    missing = subprocess.run(
        [str(cli), "verify", "--output", "json", str(bundle_path)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=str(tmp_path),
    )
    assert missing.returncode == 1
    _assert_verify_privacy(missing.stdout, missing.stderr)
    payload = json.loads(missing.stdout)
    assert payload["contract"] == VERIFY_REQUIRES_TRUST_ROOTS

    passed = subprocess.run(
        [
            str(cli),
            "verify",
            "--output",
            "json",
            "--trusted-signer-did",
            GRANT_DID,
            str(bundle_path),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=str(tmp_path),
    )
    assert passed.returncode == 0, passed.stderr
    _assert_verify_privacy(passed.stdout, passed.stderr)
    assert json.loads(passed.stdout)["contract"] == VERIFY_PASSED
