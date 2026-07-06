"""P7b tests for evidence proof export and offline verification."""

from __future__ import annotations

from dataclasses import asdict, replace
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
    EvidenceExportError,
    EvidenceVerificationError,
    PendingApproval,
    build_evidence_bundle,
    export_evidence_bundle,
    record_hash,
    verify_evidence_bundle,
    verify_evidence_bundle_legacy,
)
from agentveil_mcp_proxy.evidence.proof import _bundle_records, verify_evidence_bundle_file
from agentveil_mcp_proxy.evidence.verify_output import (
    VERIFY_CHAIN_ONLY,
    VERIFY_FAILED_UNEXPECTED,
    VERIFY_NO_SIGNED_EVIDENCE,
    VERIFY_PASSED,
    VERIFY_REQUIRES_TRUST_ROOTS,
    build_verify_success_payload,
    bundle_parse_summary,
    classify_verify_success_contract,
    render_verify_human,
)


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


def _decision_receipt_body(
    payload_hash: str = PAYLOAD_HASH,
    *,
    audit_id: str = "audit-1",
    risk_class: str = "write",
    policy_context_hash: str = POLICY_CONTEXT_HASH,
) -> dict:
    return {
        "schema_version": "decision_receipt/2",
        "audit_id": audit_id,
        "agent_did": "did:key:z6Mkagent",
        "decision": "WAITING_FOR_HUMAN_APPROVAL",
        "payload_hash": payload_hash,
        "client_risk_class": risk_class,
        "client_policy_context_hash": policy_context_hash,
    }


def _decision_receipt(
    payload_hash: str = PAYLOAD_HASH,
    seed: bytes = BACKEND_SEED,
    *,
    audit_id: str = "audit-1",
    risk_class: str = "write",
    policy_context_hash: str = POLICY_CONTEXT_HASH,
) -> str:
    return _sign_jcs(
        _decision_receipt_body(
            payload_hash,
            audit_id=audit_id,
            risk_class=risk_class,
            policy_context_hash=policy_context_hash,
        ),
        seed=seed,
    )


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


def test_schema_v1_migrates_to_v4_atomically_with_chain_backfill(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        columns = [
            column
            for column in asdict(_record()).keys()
            if column not in {"prev_event_hash", "granted_by_request_id"}
        ]
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (1)")
        conn.execute(
            "CREATE TABLE pending_approvals ("
            + ", ".join(f"{column} TEXT" for column in columns)
            + ", PRIMARY KEY(request_id))"
        )
        values = asdict(_record("req-v1", created_at=10))
        values.pop("prev_event_hash")
        values.pop("granted_by_request_id")
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
    assert version == 4


def test_schema_v5_rejects_forward_incompatible_version(tmp_path):
    db_path = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE evidence_schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO evidence_schema_version (version) VALUES (5)")
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
    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_bundle_records_uses_stored_prev_event_hash():
    first = replace(_record("req-1", created_at=10), prev_event_hash=GENESIS_PREV_EVENT_HASH)
    second_prev = record_hash(first)
    second = replace(_record("req-2", created_at=20), prev_event_hash=second_prev)

    records = _bundle_records([first, second])

    assert records[0]["prev_event_hash"] == GENESIS_PREV_EVENT_HASH
    assert records[1]["prev_event_hash"] == second_prev


def test_bundle_records_adds_execution_record_id_for_executed_child(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-parent", created_at=10))
        store.transition(
            "req-parent",
            ApprovalStatus.APPROVED.value,
            approval_token_hash=APPROVAL_TOKEN_HASH,
        )
        child = PendingApproval(
            request_id="req-child",
            session_id="session-1",
            client_id="cursor:session-7",
            downstream_server="github-mcp",
            tool_name="github.create_issue",
            action_class="write",
            risk_class="write",
            resource_hash=RESOURCE_HASH,
            payload_hash=PAYLOAD_HASH,
            policy_id="github-default",
            policy_rule_id="rule-write",
            policy_context_hash=POLICY_CONTEXT_HASH,
            status=ApprovalStatus.PENDING.value,
            created_at=12,
            expires_at=312,
            granted_by_request_id="req-parent",
        )
        store.write_pending(child)
        store.transition(
            "req-child",
            ApprovalStatus.EXECUTED.value,
            result_status="executed",
            result_hash=RESULT_HASH,
        )
        exported = _bundle_records(store.list_records())

    parent = next(item for item in exported if item["request_id"] == "req-parent")
    child_row = next(item for item in exported if item["request_id"] == "req-child")
    assert parent["execution_record_id"] == "req-child"
    assert child_row["granted_by_request_id"] == "req-parent"
    assert "execution_record_id" not in child_row
    assert record_hash(parent) == parent["record_hash"]


def test_bundle_export_raises_on_broken_chain():
    broken = replace(_record("req-broken"), prev_event_hash="sha256:" + "0" * 64)

    with pytest.raises(EvidenceExportError, match="chain integrity broken at request_id req-broken"):
        _bundle_records([broken])


def test_export_evidence_cli_surfaces_chain_break_error(tmp_path, capsys):
    from agentveil_mcp_proxy.cli import init_proxy, main, proxy_paths

    home = tmp_path / "avp-home"
    init_proxy(home=home, agent_name="proxy", plaintext=True)
    db_path = proxy_paths(home).proxy_dir / "evidence.sqlite"
    with ApprovalEvidenceStore(db_path) as store:
        store.write_pending(_record("req-1", created_at=10))
        store.write_pending(_record("req-2", created_at=20))

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "UPDATE pending_approvals SET prev_event_hash = ? WHERE request_id = ?",
            ("sha256:" + "0" * 64, "req-2"),
        )
        conn.commit()
    finally:
        conn.close()

    assert main(["export-evidence", "--home", str(home), str(tmp_path / "bundle.json")]) == 1
    rendered = capsys.readouterr()
    assert "ERROR: evidence hash chain mismatch at request_id req-2" in rendered.err


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


def test_atomic_write_json_calls_fsync(tmp_path, monkeypatch):
    import agentveil_mcp_proxy.evidence.proof as proof_module

    calls: list[int] = []
    monkeypatch.setattr(proof_module.os, "fsync", lambda fd: calls.append(fd))

    proof_module._atomic_write_json(tmp_path / "bundle.json", {"ok": True})

    assert calls


def test_atomic_write_json_calls_directory_fsync_on_posix(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("directory fsync is POSIX-specific")
    import agentveil_mcp_proxy.evidence.proof as proof_module

    calls: list[int] = []
    monkeypatch.setattr(proof_module.os, "fsync", lambda fd: calls.append(fd))

    proof_module._atomic_write_json(tmp_path / "bundle.json", {"ok": True})

    assert len(calls) >= 2


def test_verify_passes_on_valid_bundle(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)

    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])

    assert result.valid is True
    assert result.record_count == 1
    assert result.signed_receipt_count == 1
    assert result.unverified_receipt_count == 0
    assert result.warnings == ()


def test_verify_rejects_receipt_with_missing_schema_version(tmp_path):
    body = _decision_receipt_body()
    body.pop("schema_version")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=_sign_jcs(body))

    with pytest.raises(EvidenceVerificationError, match="schema unsupported"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_rejects_receipt_with_missing_audit_id(tmp_path):
    body = _decision_receipt_body()
    body.pop("audit_id")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=_sign_jcs(body))

    with pytest.raises(EvidenceVerificationError, match="audit_id missing"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_rejects_receipt_missing_audit_id_when_record_has_one(tmp_path):
    body = _decision_receipt_body()
    body.pop("audit_id")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=_sign_jcs(body))
    assert bundle["records"][0]["decision_audit_id"] == "audit-1"

    with pytest.raises(EvidenceVerificationError, match="audit_id missing"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_rejects_receipt_missing_payload_hash_when_referenced(tmp_path):
    body = _decision_receipt_body()
    body.pop("payload_hash")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=_sign_jcs(body))

    with pytest.raises(EvidenceVerificationError, match="payload_hash missing"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_rejects_receipt_missing_client_risk_class_when_referenced(tmp_path):
    body = _decision_receipt_body()
    body.pop("client_risk_class")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=_sign_jcs(body))

    with pytest.raises(EvidenceVerificationError, match="client_risk_class missing"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_rejects_receipt_missing_client_policy_context_hash_when_referenced(tmp_path):
    body = _decision_receipt_body()
    body.pop("client_policy_context_hash")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=_sign_jcs(body))

    with pytest.raises(EvidenceVerificationError, match="client_policy_context_hash missing"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_rejects_receipt_audit_id_mismatch_with_record(tmp_path):
    receipt_jcs = _decision_receipt(audit_id="audit-Y")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=receipt_jcs)

    with pytest.raises(EvidenceVerificationError, match="audit_id mismatch"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_accepts_matching_audit_id(tmp_path):
    receipt_jcs = _decision_receipt(audit_id="audit-X")
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-audit-match",
            decision_audit_id="audit-X",
            decision_receipt_sha256=digest,
        ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=lambda _audit_id: receipt_jcs,
        )

    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_verify_skips_audit_id_check_for_cache_hit_records(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-cache-hit",
            decision_audit_id=None,
            decision_receipt_sha256=None,
        ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )

    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_verify_rejects_bundle_with_duplicate_receipt_references(tmp_path):
    receipt_jcs = _decision_receipt()
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-first",
            created_at=1_700_000_000,
            decision_audit_id="audit-1",
            decision_receipt_sha256=digest,
        ))
        store.write_pending(_record(
            "req-second",
            created_at=1_700_000_001,
            decision_audit_id="audit-1",
            decision_receipt_sha256=digest,
        ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=lambda _audit_id: receipt_jcs,
        )

    with pytest.raises(EvidenceVerificationError, match="referenced by multiple records"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_accepts_bundle_with_distinct_receipt_per_record(tmp_path):
    receipts = {
        "audit-1": _decision_receipt(audit_id="audit-1"),
        "audit-2": _decision_receipt(audit_id="audit-2"),
    }
    digests = {
        audit_id: hashlib.sha256(receipt.encode("utf-8")).hexdigest()
        for audit_id, receipt in receipts.items()
    }
    with _store(tmp_path) as store:
        for index, audit_id in enumerate(("audit-1", "audit-2")):
            store.write_pending(_record(
                f"req-{index}",
                created_at=1_700_000_000 + index,
                decision_audit_id=audit_id,
                decision_receipt_sha256=digests[audit_id],
            ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=receipts.__getitem__,
        )

    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_verify_accepts_bundle_with_cache_hit_records_no_receipt_reference(tmp_path):
    receipt_jcs = _decision_receipt()
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-receipt",
            created_at=1_700_000_000,
            decision_audit_id="audit-1",
            decision_receipt_sha256=digest,
        ))
        store.write_pending(_record(
            "req-cache-hit",
            created_at=1_700_000_001,
            decision_audit_id=None,
            decision_receipt_sha256=None,
        ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=lambda _audit_id: receipt_jcs,
        )

    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_verify_warns_on_orphan_signed_receipt_not_referenced(tmp_path):
    receipt_jcs = _decision_receipt()
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record("req-no-receipt"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )
    bundle["signed_receipts"] = {digest: receipt_jcs}

    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])

    assert result.valid is True
    assert result.warnings == (f"signed receipt {digest[:16]}... not referenced by any record",)


def test_verify_accepts_orphan_signed_receipt_if_warning_consumed_correctly(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    receipt_jcs = _decision_receipt()
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record("req-no-receipt"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )
    bundle["signed_receipts"] = {digest: receipt_jcs}
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    out = io.StringIO()

    assert verify_evidence(
        bundle_path=bundle_path,
        trusted_signer_dids=[BACKEND_DID],
        out=out,
    ) == 0
    assert f"WARN: signed receipt {digest[:16]}... not referenced by any record" in out.getvalue()


def test_export_surfaces_unverified_receipt_count_when_fetch_fails(tmp_path):
    receipt_jcs = _decision_receipt()
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        store.write_pending(_record(
            "req-fetch-fail",
            decision_audit_id="audit-1",
            decision_receipt_sha256=digest,
        ))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
            receipt_fetcher=lambda _audit_id: (_ for _ in ()).throw(RuntimeError("offline")),
        )

    assert bundle["signed_receipts"] == {}
    assert bundle["unverified_receipt_count"] == 1
    # A missing referenced receipt is a hard failure in strict/proof-grade mode;
    # surfacing it as a non-fatal count is the legacy (self-trusting) behavior.
    result = verify_evidence_bundle_legacy(bundle)
    assert result.valid is True
    assert result.unverified_receipt_count == 1
    assert result.warnings == ()


def _bundle_with_unverified_records(tmp_path: Path, *, count: int) -> dict:
    with _store(tmp_path) as store:
        for index in range(count):
            store.write_pending(_record(
                f"req-unverified-{index}",
                created_at=10 + index,
                decision_audit_id=f"audit-{index}",
                decision_receipt_sha256=f"{index:064x}",
            ))
        return build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )


def test_verify_bundle_warns_on_inflated_unverified_count(tmp_path):
    bundle = _bundle_with_unverified_records(tmp_path, count=2)
    bundle["unverified_receipt_count"] = 5

    result = verify_evidence_bundle_legacy(bundle)

    assert result.unverified_receipt_count == 2
    assert result.warnings == (
        "unverified_receipt_count mismatch: bundle claims 5, computed 2",
    )


def test_verify_bundle_warns_on_deflated_unverified_count(tmp_path):
    bundle = _bundle_with_unverified_records(tmp_path, count=3)
    bundle["unverified_receipt_count"] = 0

    result = verify_evidence_bundle_legacy(bundle)

    assert result.unverified_receipt_count == 3
    assert result.warnings == (
        "unverified_receipt_count mismatch: bundle claims 0, computed 3",
    )


def test_verify_bundle_no_warning_on_matching_count(tmp_path):
    bundle = _bundle_with_unverified_records(tmp_path, count=2)

    result = verify_evidence_bundle_legacy(bundle)

    assert result.unverified_receipt_count == 2
    assert result.warnings == ()


def test_verify_bundle_records_without_decision_audit_id_not_counted(tmp_path):
    with _store(tmp_path) as store:
        store.write_pending(_record("req-no-audit", decision_receipt_sha256="0" * 64))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[BACKEND_DID],
        )
    bundle["unverified_receipt_count"] = 0

    result = verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])

    assert result.unverified_receipt_count == 0
    assert result.warnings == ()


def test_verify_fails_on_record_hash_mismatch(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["record_hash"] = "sha256:" + "0" * 64

    with pytest.raises(EvidenceVerificationError, match="record_hash"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_fails_on_prev_event_hash_mismatch(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["prev_event_hash"] = "sha256:" + "0" * 64

    with pytest.raises(EvidenceVerificationError, match="prev_event_hash"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_fails_on_signed_receipt_signature_invalid(tmp_path):
    receipt = json.loads(_decision_receipt())
    receipt["decision"] = "ALLOW"
    tampered = jcs.canonicalize(receipt).decode("utf-8")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=tampered)
    digest = hashlib.sha256(tampered.encode("utf-8")).hexdigest()
    bundle["records"][0]["decision_receipt_sha256"] = digest
    bundle["signed_receipts"] = {digest: tampered}

    with pytest.raises(EvidenceVerificationError, match="signer is not trusted"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


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
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_bundle_rejects_risk_class_mismatch(tmp_path):
    receipt_jcs = _decision_receipt(risk_class="destructive")
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=receipt_jcs)

    with pytest.raises(EvidenceVerificationError, match="client_risk_class"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_bundle_rejects_policy_context_hash_mismatch(tmp_path):
    receipt_jcs = _decision_receipt(policy_context_hash="f" * 64)
    bundle = _bundle_with_receipt(tmp_path, receipt_jcs=receipt_jcs)

    with pytest.raises(EvidenceVerificationError, match="client_policy_context_hash"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_bundle_accepts_matching_expanded_fields(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)

    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_verify_bundle_skips_expanded_cross_check_when_record_field_missing(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["risk_class"] = None
    bundle["records"][0]["record_hash"] = record_hash(bundle["records"][0])
    bundle["chain_root_hash"] = bundle["records"][0]["record_hash"]

    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


def test_verify_uses_only_pinned_trusted_signer_dids(tmp_path):
    receipt_jcs = _decision_receipt(seed=OTHER_BACKEND_SEED)
    bundle = _bundle_with_receipt(
        tmp_path,
        receipt_jcs=receipt_jcs,
        trusted_signers=[BACKEND_DID],
    )

    with pytest.raises(EvidenceVerificationError, match="signer is not trusted"):
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])


def test_verify_exit_code_zero_on_success_one_on_failure(tmp_path):
    from agentveil_mcp_proxy.cli import main

    valid_path = tmp_path / "valid.json"
    invalid_path = tmp_path / "invalid.json"
    bundle = _bundle_with_receipt(tmp_path)
    valid_path.write_text(json.dumps(bundle), encoding="utf-8")
    invalid = dict(bundle)
    invalid["chain_root_hash"] = "sha256:" + "0" * 64
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")

    assert verify_evidence_bundle_file(
        valid_path, trusted_signer_dids=[BACKEND_DID]
    ).valid is True
    with pytest.raises(EvidenceVerificationError):
        verify_evidence_bundle_file(invalid_path, trusted_signer_dids=[BACKEND_DID])
    # CLI verify is strict: proof-grade verification requires an externally
    # pinned signer DID; the in-bundle signer list is not an accepted anchor.
    assert main(["verify", str(valid_path), "--trusted-signer-did", BACKEND_DID]) == 0
    assert main(["verify", str(invalid_path), "--trusted-signer-did", BACKEND_DID]) == 1


def test_verify_human_and_json_output_formats(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    bundle_path = tmp_path / "bundle.json"
    bundle = _bundle_with_receipt(tmp_path)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    human = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path, trusted_signer_dids=[BACKEND_DID], out=human
    ) == 0
    assert "VERIFY: passed" in human.getvalue()

    structured = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        output_format="json",
        trusted_signer_dids=[BACKEND_DID],
        out=structured,
    ) == 0
    payload = json.loads(structured.getvalue())
    assert payload["contract"] == VERIFY_PASSED
    assert payload["status"] == "ok"
    assert payload["unverified_receipt_count"] == 0
    assert payload["warnings"] == []

    bundle["unverified_receipt_count"] = 1
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    warn = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path, trusted_signer_dids=[BACKEND_DID], out=warn
    ) == 0
    assert "WARN: unverified_receipt_count mismatch: bundle claims 1, computed 0" in warn.getvalue()


def test_verify_empty_bundle_does_not_claim_passed(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    with _store(tmp_path) as store:
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=None,
            trusted_signer_dids=[],
        )
    bundle_path = tmp_path / "empty.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=out) == 0
    text = out.getvalue()
    assert "VERIFY: no_signed_evidence" in text
    assert "VERIFY: passed" not in text
    assert "Nothing to prove." in text


def test_verify_chain_only_bundle_is_not_proof_grade_passed(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    with _store(tmp_path) as store:
        store.write_pending(_record("req-chain-only"))
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[],
        )
    bundle_path = tmp_path / "chain-only.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=out) == 0
    text = out.getvalue()
    assert "VERIFY: chain_only" in text
    assert "VERIFY: passed" not in text
    assert "chain-only, not third-party signed proof" in text

    structured = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        output_format="json",
        out=structured,
    ) == 0
    payload = json.loads(structured.getvalue())
    assert payload["contract"] == VERIFY_CHAIN_ONLY
    assert payload["proof_grade"] == "chain_only"


def test_verify_empty_records_with_orphan_receipt_is_not_proof_grade(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    receipt_jcs = _decision_receipt()
    digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
    with _store(tmp_path) as store:
        bundle = build_evidence_bundle(
            store,
            proxy_identity_did=None,
            trusted_signer_dids=[BACKEND_DID],
        )
    bundle["signed_receipts"] = {digest: receipt_jcs}
    bundle_path = tmp_path / "orphan-empty.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        trusted_signer_dids=[BACKEND_DID],
        out=out,
    ) == 0
    text = out.getvalue()
    assert "VERIFY: no_signed_evidence" in text
    assert "VERIFY: passed" not in text
    assert digest[:16] in text
    assert "not referenced by any record" in text

    structured = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        output_format="json",
        trusted_signer_dids=[BACKEND_DID],
        out=structured,
    ) == 0
    payload = json.loads(structured.getvalue())
    assert payload["contract"] == VERIFY_NO_SIGNED_EVIDENCE
    assert payload["proof_grade"] == "none"
    assert payload["record_count"] == 0
    assert payload["signed_receipt_count"] == 1
    assert payload["trust_verification_completed"] is False


def test_classify_verify_success_contract_distinguishes_proof_grades(tmp_path):
    with _store(tmp_path) as store:
        empty = build_evidence_bundle(
            store,
            proxy_identity_did=None,
            trusted_signer_dids=[],
        )
        store.write_pending(_record("req-chain-only"))
        chain_only = build_evidence_bundle(
            store,
            proxy_identity_did="did:key:z6Mkproxy",
            trusted_signer_dids=[],
        )
    signed = _bundle_with_receipt(tmp_path)

    empty_result = verify_evidence_bundle(empty, trusted_signer_dids=[])
    chain_result = verify_evidence_bundle(chain_only, trusted_signer_dids=[])
    signed_result = verify_evidence_bundle(signed, trusted_signer_dids=[BACKEND_DID])

    assert classify_verify_success_contract(result=empty_result) == VERIFY_NO_SIGNED_EVIDENCE
    assert classify_verify_success_contract(result=chain_result) == VERIFY_CHAIN_ONLY
    assert classify_verify_success_contract(result=signed_result) == VERIFY_PASSED

    empty_payload = build_verify_success_payload(
        result=empty_result,
        parse_summary={
            "bundle_parsed": True,
            "record_count": 0,
            "approval_grant_count": 0,
            "signed_receipt_count": 0,
        },
        trusted_signer_dids=(),
    )
    assert render_verify_human(empty_payload).startswith("VERIFY: no_signed_evidence")


def test_verify_cli_fails_closed_when_trusted_signer_did_absent_human(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle_with_receipt(tmp_path)), encoding="utf-8")

    # Strict CLI: a receipt-bearing bundle with no externally pinned signer must
    # fail closed instead of self-trusting the bundle's embedded signer list.
    out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, out=out) == 1

    assert "VERIFY: requires_trust_roots" in out.getvalue()
    assert "trusted signer DIDs" in out.getvalue()


def test_verify_cli_fails_closed_when_trusted_signer_did_absent_json(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle_with_receipt(tmp_path)), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(bundle_path=bundle_path, output_format="json", out=out) == 1
    payload = json.loads(out.getvalue())

    assert payload["contract"] == VERIFY_REQUIRES_TRUST_ROOTS
    assert payload["status"] == "requires_trust_roots"
    assert payload["reason_code"] == "signed_receipts_require_trust_roots"


def test_verify_cli_no_warning_when_explicit_trusted_signer_did_provided(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle_with_receipt(tmp_path)), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        trusted_signer_dids=[BACKEND_DID],
        out=out,
    ) == 0

    assert "default_trust_from_bundle" not in out.getvalue()


def test_verify_cli_fails_on_missing_referenced_receipt_human(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    # A record references a decision receipt that is absent from the bundle.
    # Legacy mode downgrades this to a warning; strict CLI must fail closed.
    bundle = _bundle_with_unverified_records(tmp_path, count=1)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        trusted_signer_dids=[BACKEND_DID],
        out=out,
    ) == 1

    assert "VERIFY: failed_unexpected" in out.getvalue()
    assert "Reason code: signed_receipts_missing" in out.getvalue()


def test_verify_cli_fails_on_missing_referenced_receipt_json(tmp_path):
    from agentveil_mcp_proxy.cli import verify_evidence
    import io

    bundle = _bundle_with_unverified_records(tmp_path, count=1)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    out = io.StringIO()
    assert verify_evidence(
        bundle_path=bundle_path,
        output_format="json",
        trusted_signer_dids=[BACKEND_DID],
        out=out,
    ) == 1
    payload = json.loads(out.getvalue())

    assert payload["contract"] == VERIFY_FAILED_UNEXPECTED
    assert payload["status"] == "invalid"
    assert payload["reason_code"] == "signed_receipts_missing"


def test_verify_does_not_leak_payload_data_in_error_messages(tmp_path):
    bundle = _bundle_with_receipt(tmp_path)
    bundle["records"][0]["record_hash"] = "sha256:" + "0" * 64
    rendered = json.dumps(bundle)
    assert SECRET not in rendered

    with pytest.raises(EvidenceVerificationError) as exc:
        verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID])

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
    assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


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
        assert verify_evidence_bundle(bundle, trusted_signer_dids=[BACKEND_DID]).valid is True


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
