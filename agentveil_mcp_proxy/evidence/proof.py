"""Proof export and offline verification for local approval evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Iterable, Mapping

from agentveil.proof import ProofVerificationError, verify_signed_jcs
from agentveil_mcp_proxy.evidence.store import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceStore,
    PendingApproval,
    record_hash,
)


EVIDENCE_EXPORT_SCHEMA_VERSION = 1


class EvidenceProofError(RuntimeError):
    """Base class for evidence proof failures."""


class EvidenceExportError(EvidenceProofError):
    """Raised when an evidence bundle cannot be exported safely."""


class EvidenceVerificationError(EvidenceProofError):
    """Raised when an evidence bundle fails offline verification."""


@dataclass(frozen=True)
class EvidenceVerificationResult:
    """Structured verification result for an evidence export bundle."""

    valid: bool
    record_count: int
    signed_receipt_count: int
    chain_root_hash: str


def utc_now_iso() -> str:
    """Return current UTC time in second-precision ISO form."""

    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_timestamp(value: str) -> int:
    """Parse an ISO UTC timestamp into Unix-time seconds."""

    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise EvidenceExportError("timestamp must use YYYY-MM-DDTHH:MM:SSZ") from exc
    return int(parsed.timestamp())


def build_evidence_bundle(
    store: ApprovalEvidenceStore,
    *,
    proxy_identity_did: str | None,
    trusted_signer_dids: Iterable[str],
    client_id: str | None = None,
    since_timestamp: int | None = None,
    until_timestamp: int | None = None,
    request_ids: Iterable[str] | None = None,
    receipt_fetcher: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Build a privacy-preserving evidence export bundle."""

    records = store.list_records(
        since_timestamp=since_timestamp,
        until_timestamp=until_timestamp,
        request_ids=request_ids,
    )
    signed_receipts: dict[str, str] = {}
    export_records = _bundle_records(records)
    if receipt_fetcher is not None:
        for record in records:
            if not record.decision_audit_id or not record.decision_receipt_sha256:
                continue
            try:
                receipt_jcs = receipt_fetcher(record.decision_audit_id)
            except Exception:
                continue
            if not isinstance(receipt_jcs, str) or not receipt_jcs:
                continue
            digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
            if digest == record.decision_receipt_sha256:
                signed_receipts[digest] = receipt_jcs
    chain_root_hash = (
        export_records[-1]["record_hash"] if export_records else GENESIS_PREV_EVENT_HASH
    )
    return {
        "evidence_export_schema_version": EVIDENCE_EXPORT_SCHEMA_VERSION,
        "exported_at": utc_now_iso(),
        "proxy_identity_did": proxy_identity_did,
        "trusted_signer_dids": list(trusted_signer_dids),
        "chain_root_hash": chain_root_hash,
        "records": export_records,
        "signed_receipts": signed_receipts,
        "client_id": client_id,
        "filter": {
            "since_timestamp": since_timestamp,
            "until_timestamp": until_timestamp,
            "request_ids": list(request_ids) if request_ids is not None else None,
        },
    }


def export_evidence_bundle(
    store: ApprovalEvidenceStore,
    output_path: Path,
    *,
    proxy_identity_did: str | None,
    trusted_signer_dids: Iterable[str],
    client_id: str | None = None,
    since_timestamp: int | None = None,
    until_timestamp: int | None = None,
    request_ids: Iterable[str] | None = None,
    receipt_fetcher: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Atomically write an evidence export bundle with owner-only permissions."""

    bundle = build_evidence_bundle(
        store,
        proxy_identity_did=proxy_identity_did,
        trusted_signer_dids=trusted_signer_dids,
        client_id=client_id,
        since_timestamp=since_timestamp,
        until_timestamp=until_timestamp,
        request_ids=request_ids,
        receipt_fetcher=receipt_fetcher,
    )
    _atomic_write_json(output_path, bundle)
    return bundle


def verify_evidence_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_signer_dids: Iterable[str] | None = None,
) -> EvidenceVerificationResult:
    """Verify an evidence export bundle without calling the AVP backend."""

    if bundle.get("evidence_export_schema_version") != EVIDENCE_EXPORT_SCHEMA_VERSION:
        raise EvidenceVerificationError("evidence export schema version unsupported")
    records = bundle.get("records")
    if not isinstance(records, list):
        raise EvidenceVerificationError("records must be a list")
    expected_prev = GENESIS_PREV_EVENT_HASH
    last_hash = GENESIS_PREV_EVENT_HASH
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise EvidenceVerificationError("record must be a JSON object")
        request_id = _record_label(record, index)
        if record.get("prev_event_hash") != expected_prev:
            raise EvidenceVerificationError(f"prev_event_hash mismatch for {request_id}")
        computed = record_hash(record)
        if record.get("record_hash") != computed:
            raise EvidenceVerificationError(f"record_hash mismatch for {request_id}")
        expected_prev = computed
        last_hash = computed
    if bundle.get("chain_root_hash") != last_hash:
        raise EvidenceVerificationError("chain_root_hash mismatch")

    receipts = bundle.get("signed_receipts", {})
    if not isinstance(receipts, dict):
        raise EvidenceVerificationError("signed_receipts must be a JSON object")
    pinned_signers = tuple(trusted_signer_dids or bundle.get("trusted_signer_dids") or ())
    if receipts and not pinned_signers:
        raise EvidenceVerificationError("trusted signer DID(s) are required")
    verified_bodies: dict[str, dict[str, Any]] = {}
    for digest, receipt_jcs in receipts.items():
        if not isinstance(digest, str) or not isinstance(receipt_jcs, str):
            raise EvidenceVerificationError("signed receipt entries must be strings")
        actual_digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
        if digest != actual_digest:
            raise EvidenceVerificationError("signed receipt digest mismatch")
        verified_bodies[digest] = _verify_receipt_with_pinned_signers(
            receipt_jcs,
            pinned_signers,
        )

    for record in records:
        if not isinstance(record, dict):
            continue
        receipt_digest = record.get("decision_receipt_sha256")
        if receipt_digest is None:
            continue
        if receipt_digest not in verified_bodies:
            continue
        receipt_body = verified_bodies[receipt_digest]
        expected_payload = record.get("payload_hash")
        receipt_payload = receipt_body.get("payload_hash")
        if receipt_payload is not None and receipt_payload != expected_payload:
            raise EvidenceVerificationError("DecisionReceipt payload_hash mismatch")

    return EvidenceVerificationResult(
        valid=True,
        record_count=len(records),
        signed_receipt_count=len(receipts),
        chain_root_hash=str(bundle.get("chain_root_hash")),
    )


def verify_evidence_bundle_file(
    bundle_path: Path,
    *,
    trusted_signer_dids: Iterable[str] | None = None,
) -> EvidenceVerificationResult:
    """Load and verify one evidence export bundle file."""

    try:
        with bundle_path.open("r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError("evidence bundle unavailable") from exc
    if not isinstance(bundle, dict):
        raise EvidenceVerificationError("evidence bundle must be a JSON object")
    return verify_evidence_bundle(bundle, trusted_signer_dids=trusted_signer_dids)


def _bundle_records(records: list[PendingApproval]) -> list[dict[str, Any]]:
    export_records: list[dict[str, Any]] = []
    prev_hash = GENESIS_PREV_EVENT_HASH
    for record in records:
        data = asdict(record)
        data["prev_event_hash"] = prev_hash
        data["record_hash"] = record_hash(data)
        prev_hash = data["record_hash"]
        export_records.append(data)
    return export_records


def _verify_receipt_with_pinned_signers(
    receipt_jcs: str,
    trusted_signer_dids: Iterable[str],
) -> dict[str, Any]:
    last_error: ProofVerificationError | None = None
    for signer_did in trusted_signer_dids:
        try:
            return verify_signed_jcs(receipt_jcs, expected_signer_did=signer_did)["body"]
        except ProofVerificationError as exc:
            last_error = exc
    raise EvidenceVerificationError("signed receipt signer is not trusted") from last_error


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def _record_label(record: Mapping[str, Any], index: int) -> str:
    request_id = record.get("request_id")
    if isinstance(request_id, str) and request_id:
        return request_id
    return f"record[{index}]"


__all__ = [
    "EVIDENCE_EXPORT_SCHEMA_VERSION",
    "EvidenceExportError",
    "EvidenceProofError",
    "EvidenceVerificationError",
    "EvidenceVerificationResult",
    "build_evidence_bundle",
    "export_evidence_bundle",
    "parse_utc_timestamp",
    "utc_now_iso",
    "verify_evidence_bundle",
    "verify_evidence_bundle_file",
]
