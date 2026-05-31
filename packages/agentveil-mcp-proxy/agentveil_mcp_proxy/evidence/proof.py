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

from agentveil.data_integrity import DataIntegrityError, verify_eddsa_jcs_2022
from agentveil.proof import ProofVerificationError, verify_signed_jcs
from agentveil_mcp_proxy.evidence.approval_grant import (
    APPROVAL_SCOPE_SIMILAR_5M,
    ApprovalGrantError,
    verify_approval_grant,
)
from agentveil_mcp_proxy.evidence.store import (
    GENESIS_PREV_EVENT_HASH,
    ApprovalEvidenceStore,
    ApprovalStatus,
    PendingApproval,
    record_hash,
)


EVIDENCE_EXPORT_SCHEMA_VERSION = 1
_DECISION_RECEIPT_SCHEMAS = frozenset(
    {"decision_receipt/1", "decision_receipt/2", "decision_receipt/3"}
)
# decision_receipt/3 is verified via the W3C Data Integrity (eddsa-jcs-2022)
# path; /1 and /2 stay on the legacy raw-JCS verifier.
_W3C_DI_RECEIPT_SCHEMAS = frozenset({"decision_receipt/3"})
_RECEIPT_RECORD_CROSS_CHECK_FIELDS = (
    ("payload_hash", "payload_hash"),
    ("risk_class", "client_risk_class"),
    ("policy_context_hash", "client_policy_context_hash"),
    ("decision_audit_id", "audit_id"),
)


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
    unverified_receipt_count: int = 0
    verified_approval_grant_count: int = 0
    warnings: tuple[str, ...] = ()


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
    has_filter = since_timestamp is not None or until_timestamp is not None or request_ids is not None
    export_records = _bundle_records(records, require_genesis=not has_filter)
    unverified_receipt_count = 0
    for record in records:
        if not record.decision_audit_id or not record.decision_receipt_sha256:
            continue
        if receipt_fetcher is None:
            unverified_receipt_count += 1
            continue
        try:
            receipt_jcs = receipt_fetcher(record.decision_audit_id)
        except Exception:
            unverified_receipt_count += 1
            continue
        if not isinstance(receipt_jcs, str) or not receipt_jcs:
            unverified_receipt_count += 1
            continue
        digest = hashlib.sha256(receipt_jcs.encode("utf-8")).hexdigest()
        if digest == record.decision_receipt_sha256:
            signed_receipts[digest] = receipt_jcs
        else:
            unverified_receipt_count += 1
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
        "unverified_receipt_count": unverified_receipt_count,
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
    strict: bool = True,
    now: int | None = None,
) -> EvidenceVerificationResult:
    """Verify an evidence export bundle without calling the AVP backend.

    ``strict`` selects the trust model and now defaults to ``True``
    (proof-grade, fail-closed). Decision receipts are routed by
    ``schema_version``: ``decision_receipt/3`` is verified with the W3C Data
    Integrity ``eddsa-jcs-2022`` verifier; ``/1`` and ``/2`` keep the legacy
    raw-JCS verifier.

    Strict mode (proof-grade, the default):

    1. Trust is established ONLY from the externally supplied
       ``trusted_signer_dids``. The bundle's own ``trusted_signer_dids``
       field is never used as a trust anchor, so a forged bundle cannot
       vouch for itself (Conformance Pass finding F2).
    2. If the bundle carries signed receipts but no external signer DID is
       supplied, verification fails closed rather than self-trusting.
    3. If a record references a signed receipt that is absent from the
       bundle, verification fails instead of downgrading to a warning
       (finding F3).

    Legacy mode (``strict=False``) is the historical, NON-proof-grade
    behavior: the in-bundle ``trusted_signer_dids`` is used as a fallback
    trust anchor and a missing referenced receipt is only a warning. It is
    reachable only by explicit opt-in — prefer the loudly named
    :func:`verify_evidence_bundle_legacy`. Do not use legacy mode to back any
    proof, security, or compliance claim.
    """

    if bundle.get("evidence_export_schema_version") != EVIDENCE_EXPORT_SCHEMA_VERSION:
        raise EvidenceVerificationError("evidence export schema version unsupported")
    records = bundle.get("records")
    if not isinstance(records, list):
        raise EvidenceVerificationError("records must be a list")
    has_filter = _bundle_uses_filter(bundle.get("filter"))
    expected_prev = (
        records[0].get("prev_event_hash")
        if records and has_filter and isinstance(records[0], dict)
        else GENESIS_PREV_EVENT_HASH
    )
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
    unverified_receipt_count = bundle.get("unverified_receipt_count", 0)
    if (
        not isinstance(unverified_receipt_count, int)
        or isinstance(unverified_receipt_count, bool)
        or unverified_receipt_count < 0
    ):
        raise EvidenceVerificationError("unverified_receipt_count must be a non-negative integer")
    computed_unverified_receipt_count = _compute_unverified_receipt_count(records, receipts)
    warnings: list[str] = []
    if computed_unverified_receipt_count != unverified_receipt_count:
        warnings.append(
            "unverified_receipt_count mismatch: "
            f"bundle claims {unverified_receipt_count}, "
            f"computed {computed_unverified_receipt_count}"
        )
    if strict and computed_unverified_receipt_count:
        raise EvidenceVerificationError(
            "strict verification failed: "
            f"{computed_unverified_receipt_count} referenced signed receipt(s) "
            "missing from bundle"
        )
    if strict:
        # Proof-grade: trust only what the caller pinned out-of-band. The
        # bundle's self-declared trusted_signer_dids is intentionally ignored
        # so a re-signed forge cannot vouch for itself.
        pinned_signers = tuple(
            did for did in (trusted_signer_dids or ()) if isinstance(did, str) and did
        )
        if receipts and not pinned_signers:
            raise EvidenceVerificationError(
                "strict verification requires externally supplied trusted_signer_dids; "
                "the in-bundle trusted_signer_dids field is not an accepted trust anchor"
            )
    else:
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
        receipt_body = _verify_receipt_with_pinned_signers(
            receipt_jcs,
            pinned_signers,
        )
        _verify_decision_receipt_semantics(receipt_body)
        verified_bodies[digest] = receipt_body

    referenced_receipt_digests: set[str] = set()
    seen_record_references: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        receipt_digest = record.get("decision_receipt_sha256")
        if receipt_digest is None:
            continue
        if receipt_digest not in verified_bodies:
            continue
        if receipt_digest in seen_record_references:
            raise EvidenceVerificationError(
                f"DecisionReceipt {receipt_digest[:16]}... referenced by multiple records"
            )
        seen_record_references.add(receipt_digest)
        referenced_receipt_digests.add(receipt_digest)
        receipt_body = verified_bodies[receipt_digest]
        for record_field, receipt_field in _RECEIPT_RECORD_CROSS_CHECK_FIELDS:
            record_value = record.get(record_field)
            receipt_value = receipt_body.get(receipt_field)
            if record_value is None:
                continue
            if receipt_value is None:
                raise EvidenceVerificationError(
                    f"DecisionReceipt {receipt_field} missing for referenced record"
                )
            if receipt_value != record_value:
                raise EvidenceVerificationError(
                    f"DecisionReceipt {receipt_field} mismatch with record {record_field}"
                )
    for digest in sorted(set(verified_bodies) - referenced_receipt_digests):
        warnings.append(f"signed receipt {digest[:16]}... not referenced by any record")

    # Approval-grant trust is external-pinning only and does not consult the
    # in-bundle trusted_signer_dids fallback (or any signer field embedded in a
    # grant), regardless of strict/legacy mode.
    external_pins = tuple(
        did for did in (trusted_signer_dids or ()) if isinstance(did, str) and did
    )
    verified_approval_grant_count = _verify_approval_grants(
        records,
        external_pins=external_pins,
        strict=strict,
        now=now,
        warnings=warnings,
    )

    return EvidenceVerificationResult(
        valid=True,
        record_count=len(records),
        signed_receipt_count=len(receipts),
        chain_root_hash=str(bundle.get("chain_root_hash")),
        unverified_receipt_count=computed_unverified_receipt_count,
        verified_approval_grant_count=verified_approval_grant_count,
        warnings=tuple(warnings),
    )


def verify_evidence_bundle_file(
    bundle_path: Path,
    *,
    trusted_signer_dids: Iterable[str] | None = None,
    strict: bool = True,
    now: int | None = None,
) -> EvidenceVerificationResult:
    """Load and verify one evidence export bundle file.

    See :func:`verify_evidence_bundle` for the meaning of ``strict`` (default
    ``True``, proof-grade). Proof-claim callers pass externally pinned
    ``trusted_signer_dids``; the historical self-trusting behavior is reachable
    only via :func:`verify_evidence_bundle_legacy`.
    """

    try:
        with bundle_path.open("r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError("evidence bundle unavailable") from exc
    if not isinstance(bundle, dict):
        raise EvidenceVerificationError("evidence bundle must be a JSON object")
    return verify_evidence_bundle(
        bundle, trusted_signer_dids=trusted_signer_dids, strict=strict, now=now
    )


def verify_evidence_bundle_legacy(
    bundle: Mapping[str, Any],
    *,
    trusted_signer_dids: Iterable[str] | None = None,
) -> EvidenceVerificationResult:
    """NON-PROOF-GRADE, self-trusting verification (legacy compatibility only).

    WARNING: this is the historical behavior that finding F2 flagged as unsafe.
    With no external ``trusted_signer_dids`` it falls back to the signer list
    embedded IN the bundle, so a re-signed forgery can vouch for itself, and a
    referenced-but-missing receipt is only a warning. Use this ONLY for
    backward-compatible inspection of old bundles, never to back a proof,
    security, or compliance claim. For anything externally meaningful use
    :func:`verify_evidence_bundle` (strict/proof-grade by default).
    """
    return verify_evidence_bundle(
        bundle, trusted_signer_dids=trusted_signer_dids, strict=False
    )


def _bundle_records(records: list[PendingApproval], *, require_genesis: bool = True) -> list[dict[str, Any]]:
    export_records: list[dict[str, Any]] = []
    expected_prev_hash = (
        GENESIS_PREV_EVENT_HASH
        if require_genesis or not records
        else records[0].prev_event_hash
    )
    for record in records:
        if record.prev_event_hash != expected_prev_hash:
            raise EvidenceExportError(
                f"chain integrity broken at request_id {record.request_id}: "
                "stored prev_event_hash diverges from expected chain link; "
                "run doctor or inspect evidence DB integrity"
            )
        data = asdict(record)
        data["record_hash"] = record_hash(data)
        expected_prev_hash = data["record_hash"]
        export_records.append(data)
    return export_records


def _bundle_uses_filter(filter_value: Any) -> bool:
    if not isinstance(filter_value, Mapping):
        return False
    return any(
        filter_value.get(key) is not None
        for key in ("since_timestamp", "until_timestamp", "request_ids")
    )


def _verify_receipt_with_pinned_signers(
    receipt_jcs: str,
    trusted_signer_dids: Iterable[str],
) -> dict[str, Any]:
    # Route by the signature-protected schema_version: decision_receipt/3 uses
    # the W3C Data Integrity (eddsa-jcs-2022) verifier; /1 and /2 keep the legacy
    # raw-JCS verifier. A receipt that claims one schema but was signed for the
    # other fails closed because the signature does not reproduce under the wrong
    # path (and schema_version is itself inside the signed body).
    try:
        parsed = json.loads(receipt_jcs)
    except json.JSONDecodeError as exc:
        raise EvidenceVerificationError("signed receipt is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise EvidenceVerificationError("signed receipt must be a JSON object")
    is_w3c = parsed.get("schema_version") in _W3C_DI_RECEIPT_SCHEMAS

    last_error: Exception | None = None
    for signer_did in trusted_signer_dids:
        try:
            if is_w3c:
                return verify_eddsa_jcs_2022(
                    receipt_jcs, expected_signer_did=signer_did
                )["document"]
            return verify_signed_jcs(receipt_jcs, expected_signer_did=signer_did)["body"]
        except (ProofVerificationError, DataIntegrityError) as exc:
            last_error = exc
    raise EvidenceVerificationError("signed receipt signer is not trusted") from last_error


def _verify_decision_receipt_semantics(body: Mapping[str, Any]) -> None:
    if body.get("schema_version") not in _DECISION_RECEIPT_SCHEMAS:
        raise EvidenceVerificationError("signed receipt schema unsupported")
    if not isinstance(body.get("audit_id"), str) or not body.get("audit_id"):
        raise EvidenceVerificationError("signed receipt audit_id missing")


def _compute_unverified_receipt_count(
    records: Iterable[Mapping[str, Any]],
    receipts: Mapping[str, Any],
) -> int:
    count = 0
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if record.get("decision_audit_id") is None:
            continue
        receipt_digest = record.get("decision_receipt_sha256")
        if receipt_digest is None:
            continue
        if not isinstance(receipt_digest, str) or receipt_digest not in receipts:
            count += 1
    return count


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
        _fsync_parent_directory(path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def _fsync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _record_label(record: Mapping[str, Any], index: int) -> str:
    request_id = record.get("request_id")
    if isinstance(request_id, str) and request_id:
        return request_id
    return f"record[{index}]"


# Grant-body fields that must equal their same-named approval-record field.
_GRANT_RECORD_EQUAL_FIELDS = (
    "request_id",
    "downstream_server",
    "tool_name",
    "action_class",
    "risk_class",
    "resource_hash",
    "policy_id",
    "policy_rule_id",
    "policy_context_hash",
    "decision_audit_id",
    "decision_receipt_sha256",
)

# Statuses that do not carry a locally minted approval grant. A record that was
# denied, timed out (expired), or is still pending was not granted, so strict
# mode does not require approval_grant_jcs for it. Runtime Gate ALLOW / backend
# decision records are exempted separately by the absence of a local approval
# decision (see _record_requires_approval_grant).
_GRANT_EXEMPT_STATUSES = frozenset(
    {
        ApprovalStatus.DENIED.value,
        ApprovalStatus.EXPIRED.value,
        ApprovalStatus.PENDING.value,
    }
)


def _record_requires_approval_grant(record: Mapping[str, Any]) -> bool:
    """Return True when a record reflects a local approval decision that should
    carry a signed approval grant.

    A grant is minted only for a local APPROVED decision, which stamps both
    ``approval_decided_by`` and ``approval_scope`` on the record. Later
    execution outcomes are written on top of that decision without re-stamping
    those fields, so an approved-then-executed
    record keeps them while its ``status`` moves past ``approved``. The grant
    requirement therefore tracks the original local decision rather than the
    current status -- otherwise a grant-less approval that executed would slip
    past strict verification.

    Runtime Gate ALLOW / backend-only records leave ``approval_decided_by`` and
    ``approval_scope`` unset (they mint no local grant) and are exempt;
    denied/expired/pending records are exempt by status.
    """

    if record.get("approval_decided_by") is None:
        return False
    if record.get("approval_scope") is None:
        return False
    return record.get("status") not in _GRANT_EXEMPT_STATUSES


def _verify_approval_grants(
    records: Iterable[Any],
    *,
    external_pins: tuple[str, ...],
    strict: bool,
    now: int | None,
    warnings: list[str],
) -> int:
    """Verify each persisted ``approval_grant_jcs`` against the SG-2 primitive.

    Trust is external-pinning only: neither the bundle's ``trusted_signer_dids``
    nor any signer field embedded in a grant is consulted. Strict mode rejects a
    local-approval record (in ``approved`` or any later execution status) that is
    missing a grant, and requires external pins to verify a
    present grant; legacy mode records both situations as warnings. A present
    grant on any record status is verified and cross-checked against the record.
    """

    verified = 0
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        request_id = _record_label(record, index)
        grant_jcs = record.get("approval_grant_jcs")
        requires_grant = _record_requires_approval_grant(record)
        if grant_jcs is None:
            if requires_grant:
                if strict:
                    raise EvidenceVerificationError(
                        f"strict verification: locally approved record {request_id} "
                        "is missing approval_grant_jcs"
                    )
                warnings.append(
                    f"locally approved record {request_id} has no signed approval grant"
                )
            continue
        if not isinstance(grant_jcs, str) or not grant_jcs:
            raise EvidenceVerificationError(
                f"approval_grant_jcs must be a non-empty string for {request_id}"
            )
        if not external_pins:
            if strict:
                raise EvidenceVerificationError(
                    "strict verification of approval grants requires externally "
                    "supplied trusted_signer_dids; the in-bundle and in-grant signer "
                    "fields are not accepted trust anchors"
                )
            warnings.append(
                f"approval grant for {request_id} not verified: "
                "no external signer pins supplied"
            )
            continue
        try:
            grant_body = verify_approval_grant(
                grant_jcs, expected_signer_dids=external_pins, now=now
            )
        except (ApprovalGrantError, ValueError) as exc:
            # Any grant verification failure is converted to a bundle
            # verification error. ValueError covers malformed signatures (e.g. a
            # truncated/oversized proofValue) that the underlying verifier surfaces
            # as a raw value error rather than a domain error.
            raise EvidenceVerificationError(
                f"approval grant verification failed for {request_id}: {type(exc).__name__}"
            ) from exc
        _cross_check_grant_against_record(grant_body, record, request_id)
        verified += 1
    return verified


def _cross_check_grant_against_record(
    grant_body: Mapping[str, Any],
    record: Mapping[str, Any],
    request_id: str,
) -> None:
    """Confirm the signed grant body binds the same approval as the record."""

    if grant_body.get("decision") != "APPROVED":
        raise EvidenceVerificationError(
            f"approval grant decision is not APPROVED for {request_id}"
        )
    for field in _GRANT_RECORD_EQUAL_FIELDS:
        if grant_body.get(field) != record.get(field):
            raise EvidenceVerificationError(
                f"approval grant {field} mismatch with record for {request_id}"
            )
    scope = grant_body.get("approval_scope")
    if scope != record.get("approval_scope"):
        raise EvidenceVerificationError(
            f"approval grant approval_scope mismatch with record for {request_id}"
        )
    if grant_body.get("decided_by") != record.get("approval_decided_by"):
        raise EvidenceVerificationError(
            f"approval grant decided_by does not match record approval_decided_by "
            f"for {request_id}"
        )
    if scope == APPROVAL_SCOPE_SIMILAR_5M:
        if grant_body.get("payload_hash") is not None:
            raise EvidenceVerificationError(
                f"similar_5m approval grant must not bind payload_hash for {request_id}"
            )
        expected_expiry = record.get("granted_scope_expires_at")
    else:
        if grant_body.get("payload_hash") != record.get("payload_hash"):
            raise EvidenceVerificationError(
                f"approval grant payload_hash mismatch with record for {request_id}"
            )
        expected_expiry = record.get("expires_at")
    if grant_body.get("expires_at") != expected_expiry:
        raise EvidenceVerificationError(
            f"approval grant expires_at mismatch with record for {request_id}"
        )


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
    "verify_evidence_bundle_legacy",
]
