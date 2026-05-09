"""P7b tests for evidence proof export and offline verification."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import base58
import jcs
import pytest
from nacl.signing import SigningKey

from agentveil.delegation import _public_key_to_did
from agentveil_mcp_proxy.evidence import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceSchemaError,
    ApprovalEvidenceStore,
    ApprovalStatus,
    EvidenceVerificationError,
    PendingApproval,
    build_evidence_bundle,
    export_evidence_bundle,
    record_hash,
    verify_evidence_bundle,
)
from agentveil_mcp_proxy.evidence.proof import verify_evidence_bundle_file


PAYLOAD_HASH = "sha256:" + "a" * 64
OTHER_PAYLOAD_HASH = "sha256:" + "1" * 64
RESOURCE_HASH = "sha256:" + "b" * 64
POLICY_CONTEXT_HASH = "c" * 64
APPROVAL_TOKEN_HASH = "sha256:" + "d" * 64
RESULT_HASH = "sha256:" + "e" * 64
SECRET = "SECRET_PROOF_PAYLOAD"
BACKEND_SEED = bytes.fromhex("11" * 32)
OTHER_BACKEND_SEED = bytes.fromhex("22" * 32)
BACKEND_DID = _public_key_to_did(bytes(SigningKey(BACKEND_SEED).verify_key))
OTHER_BACKEND_DID = _public_key_to_did(bytes(SigningKey(OTHER_BACKEND_SEED).verify_key))


def _record(
    request_id: str = "req-1",
    *,
    created_at: int = 1_700_000_000,
    status: str = ApprovalStatus.PENDING.value,
    payload_hash: str = PAYLOAD_HASH,
    decision_receipt_sha256: str | None = None,
    decision_audit_id: str | None = None,
) -> PendingApproval:
    return PendingApproval(
        request_id=request_id,
        session_id="session-1",
        client_id="cursor:pid:123",
        downstream_server="github",
        tool_name="create_issue",
        action_class="write",
        risk_class="write",
        resource_hash=RESOURCE_HASH,
        payload_hash=payload_hash,
        policy_id="github-default",
        policy_rule_id="rule-write",
        policy_context_hash=POLICY_CONTEXT_HASH,
        status=status,
        created_at=created_at,
        expires_at=created_at + 300,
        decision_audit_id=decision_audit_id,
        decision_receipt_sha256=decision_receipt_sha256,
    )


def _store(tmp_path: Path) -> ApprovalEvidenceStore:
    return ApprovalEvidenceStore(tmp_path / "evidence.sqlite")


def _sign_jcs(body: dict, seed: bytes = BACKEND_SEED) -> str:
    key = SigningKey(seed)
    signer_did = _public_key_to_did(bytes(key.verify_key))
    signature = key.sign(jcs.canonicalize(body)).signature
    signed = {
        **body,
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": f"{signer_did}#{signer_did[len('did:key:'):]}",
            "proofValue": "z" + base58.b58encode(signature).decode("ascii"),
        },
    }
    return jcs.canonicalize(signed).decode("utf-8")


def _decision_receipt(payload_hash: str = PAYLOAD_HASH, seed: bytes = BACKEND_SEED) -> str:
    return _sign_jcs({
        "schema_version": "decision_receipt/2",
        "audit_id": "audit-1",
        "agent_did": "did:key:z6Mkagent",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "payload_hash": payload_hash,
        "client_risk_class": "write",
        "client_policy_context_hash": POLICY_CONTEXT_HASH,
    }, seed=seed)


def _bundle_with_receipt(
    tmp_path: Path,
    *,
    receipt_jcs: str | None = None,
    payload_hash: str = PAYLOAD_HASH,
    trusted_signers: list[str] | None = None,
) -> dict:
    receipt_jcs = receipt_jcs or _decision_receipt(payload_hash)
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-receipt",
            decision_audit_id="audit-1",
            decision_receipt_sha256=digest,
            payload_hash=payload_hash,
        ))
        return build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=trusted_signers or [BACKEND_DID],
            receipt_fetcher=lambda audit_id: receipt_jcs,
        )


def _make_terminal(store: ApprovalEvidenceStore, request_id: str) -> None:
    store.transition(
        request_id,
        ApprovalStatus.APPROVED.value,
        approval_token_hash=APPROVAL_TOKEN_HASH,
    )
    store.transition(request_id, ApprovalStatus.EXECUTED.value, result_hash=RESULT_HASH)


def test_genesis_record_uses_fixed_sentinel_prev_hash(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-1"))
        record = store.get_pending("req-1")

    assert record.prev_event_hash == GENESIS_PREV_EVENT_HASH


def test_chain_links_consecutive_records_correctly(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-1", created_at=10))
        first = store.get_pending("req-1")
        store.write_pending(_record("req-2", created_at=20))
        second = store.get_pending("req-2")

    assert second.prev_event_hash == record_hash(first)


def test_record_hash_excludes_prev_event_hash_and_record_hash_fields(tmp_path):
    data = asdict(_record("req-hash"))
    data["prev_event_hash"] = GENESIS_PREV_EVENT_HASH
    base = record_hash(data)

    data["prev_event_hash"] = "sha256:" + "f" * 64
    data["record_hash"] = "sha256:" + "0" * 64

    assert record_hash(data) == base


def test_chain_integrity_breaks_if_record_field_tampered(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-1", created_at=10))
        store.write_pending(_record("req-2", created_at=20))

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "UPDATE pending_approvals SET tool_name = ? WHERE request_id = ?",
            ("delete_repo", "req-1"),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(ApprovalEvidenceSchemaError, match="hash chain mismatch"):
        ApprovalEvidenceStore(db_path)


def test_schema_v1_migrates_to_v2_atomically_with_chain_backfill(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        columns = [column for column in asdict(_record()).keys() if column != "prev_event_hash"]
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (1)")
        conn.execute(
            "CREATE TABLE pending_approvals ("
            + ", ".join(f"{column} TEXT" for column in columns)
            + ", PRIMARY KEY(request_id))"
        )
        values = asdict(_record("req-v1", created_at=10))
        values.pop("prev_event_hash")
        conn.execute(
            f"INSERT INTO pending_approvals ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            [values[column] for column in columns],
        )
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)

    with ApprovalEvidenceStore(db_path) as store:
        migrated = store.get_pending("req-v1")

    assert migrated.prev_event_hash == GENESIS_PREV_EVENT_HASH
    conn = sqlite3.connect(str(db_path))
    try:
        version = conn.execute("SELECT version FROM evidence_schema_version").fetchone()[0]
    finally:
        conn.close()
    assert version == 2


def test_schema_v2_rejects_forward_incompatible_version(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (3)")
        conn.commit()
    finally:
        conn.close()
    os.chmod(db_path, 0o600)

    with pytest.raises(ApprovalEvidenceSchemaError):
        ApprovalEvidenceStore(db_path)


def test_export_evidence_creates_bundle_with_correct_schema_and_chain_root(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-1", created_at=10))
        store.write_pending(_record("req-2", created_at=20))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )

    assert bundle["evidence_export_schema_version"] == 1
    assert len(bundle["records"]) == 2
    assert bundle["chain_root_hash"] == bundle["records"][-1]["record_hash"]
    assert verify_evidence_bundle(bundle).valid is True


def test_export_filter_since_until_request_id_works(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-1", created_at=10))
        store.write_pending(_record("req-2", created_at=20))
        store.write_pending(_record("req-3", created_at=30))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            since_timestamp=15,
            until_timestamp=35,
            request_ids=["req-2", "req-3"],
        )

    assert [record["request_id"] for record in bundle["records"]] == ["req-2", "req-3"]


def test_export_bundle_has_0600_permissions(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX mode bits are not stable on Windows")
    output = tmp_path / "bundle.json"
    with _store(tmp_path) as store:
        store.write_pending(_record("req-1"))
        export_evidence_bundle(
            store,
            output,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )

    assert (output.stat().st_mode & 0o777) == 0o600


def test_export_does_not_include_raw_payload_or_secrets(tmp_path):
    raw_context = {
        "arguments": {"token": SECRET, "repo": "private-repo"},
        "prompt": "private prompt",
        "output": "private output",
        "source_code": "print('private')",
    }
    with _store(tmp_path) as store:
        store.write_pending(_record("req-private"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )

    rendered = json.dumps(bundle, sort_keys=True)
    assert SECRET not in rendered
    assert raw_context["arguments"]["repo"] not in rendered
    assert raw_context["prompt"] not in rendered
    assert raw_context["output"] not in rendered
    assert raw_context["source_code"] not in rendered


def test_export_includes_signed_receipts_when_decision_audit_id_present(tmp_path):
    receipt_jcs = _decision_receipt()
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=receipt_jcs)
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()

    assert bundle["signed_receipts"] == {digest: receipt_jcs}


def test_export_atomic_write_does_not_leave_partial_bundle_on_failure(tmp_path, monkeypatch):
    import agentveil_mcp_proxy.evidence.proof as proof_module

    output = tmp_path / "bundle.json"

    def fail_dump(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(proof_module.json, "dump", fail_dump)
    with _store(tmp_path) as store:
        store.write_pending(_record("req-1"))
        with pytest.raises(OSError):
            export_evidence_bundle(
                store,
                output,
                proxy_identity_did="did:key:z6Mkproxy",
                trusted_signer_dids=[BACKEND_DID],
            )

    assert not output.exists()
    assert not list(tmp_path.glob(".bundle.json.*.tmp"))


def test_verify_passes_on_valid_bundle(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)

    result = verify_evidence_bundle(bundle)

    assert result.valid is True
    assert result.record_count == 1
    assert result.signed_receipt_count == 1


def test_verify_fails_on_record_hash_mismatch(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["record_hash"] = "sha256:" + "0" * 64

    with pytest.raises(EvidenceVerificationError, match="record_hash"):
        verify_evidence_bundle(bundle)


def test_verify_fails_on_prev_event_hash_mismatch(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["prev_event_hash"] = "sha256:" + "0" * 64

    with pytest.raises(EvidenceVerificationError, match="prev_event_hash"):
        verify_evidence_bundle(bundle)


def test_verify_fails_on_signed_receipt_signature_invalid(tmp_path):
    receipt = json.loads(_decision_receipt())
    receipt["decision"] = "ALLOW"
    tampered = jcs.canonicalize(receipt).decode("utf-8")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=tampered)
    digest = hashlib.sha256(tampered.encode("utf-8")).hexdigest()
    bundle["records"][0]["decision_receipt_sha256"] = digest
    bundle["signed_receipts"] = {digest: tampered}

    with pytest.raises(EvidenceVerificationError, match="signer is not trusted"):
        verify_evidence_bundle(bundle)


def test_verify_fails_on_scope_mismatch_between_record_and_decision_receipt(tmp_path):
    receipt_jcs = _decision_receipt(OTHER_PAYLOAD_HASH)
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-mismatch",
            decision_audit_id="audit-1",
            decision_receipt_sha256=digest,
            payload_hash=PAYLOAD_HASH,
        ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=lambda _audit_id: receipt_jcs,
        )

    with pytest.raises(EvidenceVerificationError, match="payload_hash"):
        verify_evidence_bundle(bundle)


def test_verify_uses_only_pinned_trusted_signer_dids(tmp_path):
    receipt_jcs = _decision_receipt(seed=OTHER_BACKEND_SEED)
    bundle = _bundle_with_receipt(
        tmp_path,
        receipt_jcs=receipt_jcs,
        trusted_signers=[BACKEND_DID],
    )

    with pytest.raises(EvidenceVerificationError, match="signer is not trusted"):
        verify_evidence_bundle(bundle)


def test_verify_exit_code_zero_on_success_one_on_failure(tmp_path):
    from agentveil_mcp_proxy.cli import main

    valid_path = tmp_path / "valid.json"
    invalid_path = tmp_path / "invalid.json"
    bundle = _bundle_with_receipt(tmp_path)
    valid_path.write_text(json.dumps(bundle), encoding="utf-8")
    invalid = dict(bundle)
    invalid["chain_root_hash"] = "sha256:" + "0" * 64
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")

    assert verify_evidence_bundle_file(valid_path).valid is True
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle_file(invalid_path)
    assert main(["verify", str(valid_path)]) == 0
    assert main(["verify", str(invalid_path)]) == 1


def test_verify_human_and_json_output_formats(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    bundle_path = tmp_path / "bundle.json"
    bundle = _bundle_with_receipt(tmp_path)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    human = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=human) == 0
    assert "OK: bundle integrity verified" in human.getvalue()

    structured = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, output_format="json", out=structured) == 0
    assert json.loads(structured.getvalue())["status"] == "ok"


def test_verify_does_not_leak_payload_data_in_error_messages(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["record_hash"] = "sha256:" + "0" * 64
    rendered = json.dumps(bundle)
    assert SECRET not in rendered

    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle)

    assert SECRET not in str(exc.value)


def test_vacuum_removes_terminal_records_older_than_max_age(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("old", created_at=10))
        _make_terminal(store, "old")
        store.write_pending(_record("fresh", created_at=100))
        _make_terminal(store, "fresh")

        deleted = store.vacuum_terminal_records(before_timestamp=50)

        assert deleted == 1
        assert store.get_pending("old") is None
        assert store.get_pending("fresh") is not None


def test_vacuum_preserves_pending_and_approved_records_regardless_of_age(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("pending-old", created_at=10))
        store.write_pending(_record("approved-old", created_at=11))
        store.transition(
            "approved-old",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )

        deleted = store.vacuum_terminal_records(before_timestamp=50)

        assert deleted == 0
        assert store.get_pending("pending-old").status == ApprovalStatus.PENDING.value
        assert store.get_pending("approved-old").status == ApprovalStatus.APPROVED.value


def test_vacuum_reconstructs_chain_after_deletion(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("old", created_at=10))
        _make_terminal(store, "old")
        store.write_pending(_record("kept", created_at=20))

        store.vacuum_terminal_records(before_timestamp=15)
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )

    assert [record["request_id"] for record in bundle["records"]] == ["kept"]
    assert bundle["records"][0]["prev_event_hash"] == GENESIS_PREV_EVENT_HASH
    assert verify_evidence_bundle(bundle).valid is True


def test_vacuum_idempotent_repeated_runs_no_changes_after_first(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("old", created_at=10))
        _make_terminal(store, "old")

        assert store.vacuum_terminal_records(before_timestamp=50) == 1
        assert store.vacuum_terminal_records(before_timestamp=50) == 0


def test_proof_module_does_not_construct_avp_agent_or_call_backend_for_chain_ops(tmp_path, monkeypatch):
    import agentveil.agent as agent_module
    import httpx

    class ExplodingAgent:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("proof chain operations must not construct AVPAgent")

    class ExplodingClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("proof chain operations must not construct an HTTP client")

    monkeypatch.setattr(agent_module, "AVPAgent", ExplodingAgent)
    monkeypatch.setattr(httpx, "Client", ExplodingClient)

    with _store(tmp_path) as store:
        store.write_pending(_record("req-local"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )
        assert verify_evidence_bundle(bundle).valid is True


def test_no_raw_args_or_secrets_in_any_bundle_field_or_log_path(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-private"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )

    rendered = json.dumps(bundle, sort_keys=True)
    assert SECRET not in rendered
    assert "private-repo" not in rendered
    assert "raw_args" not in rendered
