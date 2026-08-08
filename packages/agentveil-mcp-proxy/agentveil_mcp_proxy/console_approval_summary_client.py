# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Bounded Console approval-summary upload client and background dispatcher."""

from __future__ import annotations

import hashlib
import json
import queue
import re
import socket
import ssl
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from agentveil_mcp_proxy.classification import infer_action_family
from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    CredentialError,
    StoredCredential,
    load_credential,
)
from agentveil_mcp_proxy.evidence import ApprovalEvidenceStore, ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import (
    bounded_approval_resource_display,
    parse_action_gate_metadata,
)

CONSOLE_ORIGIN = "https://agentveil.dev"
_ORIGIN_HOST = "agentveil.dev"
_INGEST_PATH = "/console/approval-summaries/ingest"

_REQUEST_TIMEOUT_SECONDS = 3.0
_MAX_RESPONSE_BYTES = 16 * 1024
_SCHEMA_VERSION = "1"
_DEFAULT_QUEUE_CAPACITY = 256
_SHUTDOWN_JOIN_TIMEOUT_SECONDS = _REQUEST_TIMEOUT_SECONDS + 0.25
_MAX_LIST_ITEMS = 100

_ACTION_FAMILIES = frozenset({
    "read",
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "exec",
    "shell",
    "list",
    "get",
    "search",
    "fetch",
    "filesystem_write",
    "shell_like",
})

_RESOLUTION_APPROVED = "approved"
_RESOLUTION_DENIED = "denied"
_RESOLUTION_EXPIRED = "expired"
_RESOLUTION_RESOLVED = "resolved"
_RESOLUTION_STATUSES = frozenset({
    _RESOLUTION_APPROVED,
    _RESOLUTION_DENIED,
    _RESOLUTION_EXPIRED,
    _RESOLUTION_RESOLVED,
})

_REQUEST_KEYS = frozenset({
    "schema_version",
    "snapshot_id",
    "observed_at",
    "pending",
    "resolutions",
    "idempotency_key",
})
_RESPONSE_KEYS = frozenset({
    "schema_version",
    "observed_at",
    "pending_count",
    "status",
})
_ACK_STATUSES = frozenset({"accepted", "duplicate"})

_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_IDEMPOTENCY_KEY_RE = _OPAQUE_ID_RE
_SAFE_BASENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
_PATH_FRAGMENT_RE = re.compile(
    r"(^[/~\\])|([A-Za-z]:\\)|(/Users/)|(/home/)|(\.\./)"
)
_SECRETISH_RE = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|private[_-]?key|bearer)"
)
_FORBIDDEN_OPAQUE_FRAGMENTS = ("/Users/", "/home/", "../", "..\\", "C:\\")
_FORBIDDEN_OPAQUE_SUBSTRINGS = (
    "secret",
    "token",
    "password",
    "apikey",
    "api_key",
    "private",
    "bearer",
)

_APPROVAL_ID_DOMAIN = b"avp.console.approval_summary.approval_id.v1"
_SNAPSHOT_ID_DOMAIN = b"avp.console.approval_summary.snapshot_id.v1"
_IDEMPOTENCY_DOMAIN = b"avp.console.approval_summary.idempotency.v1"

_TERMINAL_RESOLUTION_STATUSES = frozenset({
    ApprovalStatus.APPROVED.value,
    ApprovalStatus.DENIED.value,
    ApprovalStatus.EXPIRED.value,
    ApprovalStatus.CANCELLED.value,
    ApprovalStatus.INVALIDATED.value,
    ApprovalStatus.EXECUTED.value,
    ApprovalStatus.ERROR.value,
    ApprovalStatus.BLOCKED.value,  # claim-check: allow enum member, not a coverage claim
})


class ApprovalSummaryClientError(RuntimeError):
    """Bounded client failure with a short stable code only."""

    def __init__(self, code: str = "approval_summary_failed"):
        self.code = str(code)
        super().__init__(self.code)


class TransportError(Exception):
    """Low-level transport failure without detail leak."""


@dataclass(frozen=True)
class RawResponse:
    status: int
    content_types: tuple[str, ...]
    body: bytes


@dataclass(frozen=True)
class ApprovalPendingItem:
    approval_id: str
    action_family: str
    target_basename: str
    opened_at: str


@dataclass(frozen=True)
class ApprovalResolutionItem:
    approval_id: str
    status: str
    resolved_at: str


@dataclass(frozen=True)
class ApprovalSummaryPayload:
    schema_version: str
    snapshot_id: str
    observed_at: str
    pending: tuple[ApprovalPendingItem, ...]
    resolutions: tuple[ApprovalResolutionItem, ...]
    idempotency_key: str | None = None


Transport = Callable[..., RawResponse]
LoadCredential = Callable[..., StoredCredential | None]
SnapshotSource = Callable[[], ApprovalSummaryPayload | None]
UploadSummary = Callable[[ApprovalSummaryPayload], str]
ApprovalStateObserver = Callable[[], None]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib contract
        return None


def _urllib_transport(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> RawResponse:
    request = urllib.request.Request(
        url, data=body, method=method, headers=dict(headers)
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        raw = _read_bounded(exc)
        return RawResponse(
            status=int(exc.code),
            content_types=_content_types(exc.headers),
            body=raw,
        )
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        raise TransportError() from exc
    try:
        raw = _read_bounded(response)
        return RawResponse(
            status=int(response.status),
            content_types=_content_types(response.headers),
            body=raw,
        )
    finally:
        try:
            response.close()
        except OSError:
            pass


def _content_types(headers) -> tuple[str, ...]:
    try:
        values = headers.get_all("Content-Type")
    except AttributeError:
        value = headers.get("Content-Type") if headers else None
        values = [value] if value else []
    return tuple(v for v in (values or ()) if v is not None)


def _read_bounded(response) -> bytes:
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise ApprovalSummaryClientError("response_too_large")
    return raw


def _validate_json_content_type(value: str) -> None:
    if "," in value:
        raise ApprovalSummaryClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        raise ApprovalSummaryClientError("bad_content_type")
    if len(parts) > 2:
        raise ApprovalSummaryClientError("bad_content_type")
    if len(parts) == 2 and not parts[1].lower().startswith("charset="):
        raise ApprovalSummaryClientError("bad_content_type")
    if len(parts) == 2 and len(parts[1].split("=", 1)[1].strip()) == 0:
        raise ApprovalSummaryClientError("bad_content_type")
    if len(parts) == 2:
        charset = parts[1].split("=", 1)[1].strip().lower()
        if charset not in {"utf-8", "utf8"}:
            raise ApprovalSummaryClientError("bad_content_type")


def _parse_rfc3339_utc(value: str) -> datetime:
    text = str(value).strip()
    if not text or "T" not in text:
        raise ApprovalSummaryClientError("invalid_timestamp")
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ApprovalSummaryClientError("invalid_timestamp") from exc
    if parsed.tzinfo is None:
        raise ApprovalSummaryClientError("invalid_timestamp")
    return parsed.astimezone(timezone.utc)


def _canonical_timestamp(value: datetime | int) -> str:
    if isinstance(value, int):
        utc = datetime.fromtimestamp(value, timezone.utc)
    else:
        utc = value.astimezone(timezone.utc)
    text = utc.strftime("%Y-%m-%dT%H:%M:%S")
    micros = utc.microsecond
    if micros:
        text += f".{micros:06d}"
    return f"{text}Z"


def _validate_opaque_id(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    if not _OPAQUE_ID_RE.fullmatch(value):
        return None
    lowered = value.lower()
    for fragment in _FORBIDDEN_OPAQUE_FRAGMENTS:
        if fragment.lower() in lowered:
            return None
    for forbidden in _FORBIDDEN_OPAQUE_SUBSTRINGS:
        if forbidden in lowered:
            return None
    return value


def validate_target_basename(value: str | None) -> str | None:
    """Return a basename accepted by the bounded grammar, otherwise None."""

    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or not _SAFE_BASENAME_RE.fullmatch(candidate):
        return None
    if "/" in candidate or "\\" in candidate:
        return None
    if _PATH_FRAGMENT_RE.search(candidate):
        return None
    if _SECRETISH_RE.search(candidate):
        return None
    return candidate


def target_basename_from_resource_plain(resource_plain: str | None) -> str | None:
    """Derive a bounded basename label from one classified resource string."""

    bounded = bounded_approval_resource_display(resource_plain)
    if bounded is None:
        return None
    return validate_target_basename(bounded)


def derive_approval_id(request_id: str) -> str:
    """Return a stable domain-separated correlation for one local request id."""

    digest = hashlib.sha256(
        _APPROVAL_ID_DOMAIN + request_id.encode("utf-8")
    ).hexdigest()
    validated = _validate_opaque_id(digest)
    if validated is None:
        raise ApprovalSummaryClientError("invalid_approval_id")
    return validated


def _resolve_action_family(record: PendingApproval) -> str | None:
    metadata = parse_action_gate_metadata(record)
    if metadata is not None:
        raw = metadata.get("action_family")
        if isinstance(raw, str) and raw in _ACTION_FAMILIES:
            return raw
    inferred = infer_action_family(record.tool_name)
    if inferred in _ACTION_FAMILIES:
        return inferred
    return None


def _resolve_target_basename(record: PendingApproval) -> str | None:
    metadata = parse_action_gate_metadata(record)
    if metadata is None:
        return None
    raw = metadata.get("target_basename")
    if isinstance(raw, str):
        return validate_target_basename(raw)
    return None


def _is_operator_approval_row(record: PendingApproval) -> bool:
    if record.granted_by_request_id is not None:
        return False
    if record.approval_token_hash is None:
        return False
    return True


def _resolution_status(record: PendingApproval) -> str | None:
    status = record.status
    if status == ApprovalStatus.DENIED.value:
        return _RESOLUTION_DENIED
    if status == ApprovalStatus.EXPIRED.value:
        return _RESOLUTION_EXPIRED
    if status in {
        ApprovalStatus.APPROVED.value,
        ApprovalStatus.EXECUTED.value,
    }:
        return _RESOLUTION_APPROVED
    if status == ApprovalStatus.ERROR.value:
        if record.approval_decided_at or record.approval_grant_jcs:
            return _RESOLUTION_APPROVED
        return None
    if status in {
        ApprovalStatus.CANCELLED.value,
        ApprovalStatus.INVALIDATED.value,
        ApprovalStatus.BLOCKED.value,  # claim-check: allow enum member, not a coverage claim
    }:
        return _RESOLUTION_RESOLVED
    return None


def _resolved_at_timestamp(record: PendingApproval) -> int | None:
    if record.status == ApprovalStatus.EXPIRED.value:
        if record.expires_at is not None:
            return int(record.expires_at)
        return None
    if record.user_decision_timestamp is not None:
        return int(record.user_decision_timestamp)
    if record.approval_decided_at is not None:
        return int(record.approval_decided_at)
    return None


def _resolution_sort_key(record: PendingApproval) -> tuple[int, str]:
    resolved = _resolved_at_timestamp(record)
    if resolved is None:
        return (0, record.request_id)
    return (-resolved, record.request_id)


def _map_pending_item(record: PendingApproval) -> ApprovalPendingItem | None:
    approval_id = derive_approval_id(record.request_id)
    action_family = _resolve_action_family(record)
    target_basename = _resolve_target_basename(record)
    if action_family is None or target_basename is None:
        return None
    return ApprovalPendingItem(
        approval_id=approval_id,
        action_family=action_family,
        target_basename=target_basename,
        opened_at=_canonical_timestamp(record.created_at),
    )


def _map_resolution_item(record: PendingApproval) -> ApprovalResolutionItem | None:
    approval_id = derive_approval_id(record.request_id)
    status = _resolution_status(record)
    resolved_at_ts = _resolved_at_timestamp(record)
    if status is None or resolved_at_ts is None:
        return None
    return ApprovalResolutionItem(
        approval_id=approval_id,
        status=status,
        resolved_at=_canonical_timestamp(resolved_at_ts),
    )


def build_approval_summary_snapshot(
    store: ApprovalEvidenceStore,
    *,
    observed_at: datetime | None = None,
) -> ApprovalSummaryPayload | None:
    """Build a bounded snapshot or return None when any row is rejected."""

    try:
        records = store.list_records()
    except Exception:
        return None

    operator_rows = [record for record in records if _is_operator_approval_row(record)]
    pending_records = [
        record for record in operator_rows if record.status == ApprovalStatus.PENDING.value
    ]
    if len(pending_records) > _MAX_LIST_ITEMS:
        return None

    pending_items: list[ApprovalPendingItem] = []
    for record in sorted(pending_records, key=lambda item: (item.created_at, item.request_id)):
        mapped = _map_pending_item(record)
        if mapped is None:
            return None
        pending_items.append(mapped)

    resolution_records = [
        record
        for record in operator_rows
        if record.status != ApprovalStatus.PENDING.value
        and record.status in _TERMINAL_RESOLUTION_STATUSES
    ]
    resolution_items: list[ApprovalResolutionItem] = []
    for record in sorted(resolution_records, key=_resolution_sort_key)[:_MAX_LIST_ITEMS]:
        mapped = _map_resolution_item(record)
        if mapped is None:
            continue
        resolution_items.append(mapped)

    observed = observed_at or datetime.now(timezone.utc)
    observed_text = _canonical_timestamp(observed)
    snapshot_id, idempotency_key = _derive_payload_identity(
        observed_at=observed_text,
        pending=tuple(pending_items),
        resolutions=tuple(resolution_items),
    )
    return ApprovalSummaryPayload(
        schema_version=_SCHEMA_VERSION,
        snapshot_id=snapshot_id,
        observed_at=observed_text,
        pending=tuple(pending_items),
        resolutions=tuple(resolution_items),
        idempotency_key=idempotency_key,
    )


def _pending_item_payload(item: ApprovalPendingItem) -> dict[str, str]:
    return {
        "approval_id": item.approval_id,
        "action_family": item.action_family,
        "target_basename": item.target_basename,
        "opened_at": item.opened_at,
    }


def _resolution_item_payload(item: ApprovalResolutionItem) -> dict[str, str]:
    return {
        "approval_id": item.approval_id,
        "status": item.status,
        "resolved_at": item.resolved_at,
    }


def _canonical_request_content(
    *,
    schema_version: str,
    observed_at: str,
    pending: tuple[ApprovalPendingItem, ...],
    resolutions: tuple[ApprovalResolutionItem, ...],
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "observed_at": observed_at,
        "pending": [_pending_item_payload(item) for item in pending],
        "resolutions": [_resolution_item_payload(item) for item in resolutions],
    }


def _bounded_state_fingerprint(payload: ApprovalSummaryPayload) -> str:
    """Return a stable digest for pending/resolution content without observed_at."""

    content = {
        "schema_version": payload.schema_version,
        "pending": [_pending_item_payload(item) for item in payload.pending],
        "resolutions": [_resolution_item_payload(item) for item in payload.resolutions],
    }
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _canonical_request_digest(
    *,
    schema_version: str,
    observed_at: str,
    pending: tuple[ApprovalPendingItem, ...],
    resolutions: tuple[ApprovalResolutionItem, ...],
) -> str:
    payload = _canonical_request_content(
        schema_version=schema_version,
        observed_at=observed_at,
        pending=pending,
        resolutions=resolutions,
    )
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _derive_payload_identity(
    *,
    observed_at: str,
    pending: tuple[ApprovalPendingItem, ...],
    resolutions: tuple[ApprovalResolutionItem, ...],
) -> tuple[str, str]:
    digest = _canonical_request_digest(
        schema_version=_SCHEMA_VERSION,
        observed_at=observed_at,
        pending=pending,
        resolutions=resolutions,
    )
    snapshot_id = _validate_opaque_id(
        hashlib.sha256(_SNAPSHOT_ID_DOMAIN + digest.encode("utf-8")).hexdigest()
    )
    if snapshot_id is None:
        raise ApprovalSummaryClientError("invalid_snapshot_id")
    idempotency_key = _validate_opaque_id(
        hashlib.sha256(
            _IDEMPOTENCY_DOMAIN + digest.encode("utf-8") + observed_at.encode("utf-8")
        ).hexdigest()
    )
    if idempotency_key is None:
        raise ApprovalSummaryClientError("invalid_idempotency_key")
    return snapshot_id, idempotency_key


def _validate_timestamp_string(value: object) -> str:
    if not isinstance(value, str):
        raise ApprovalSummaryClientError("invalid_request")
    return _canonical_timestamp(_parse_rfc3339_utc(value))


def _validate_pending_item(item: object) -> ApprovalPendingItem:
    if not isinstance(item, ApprovalPendingItem):
        raise ApprovalSummaryClientError("invalid_request")
    approval_id = _validate_opaque_id(item.approval_id)
    if approval_id is None:
        raise ApprovalSummaryClientError("invalid_request")
    if not isinstance(item.action_family, str) or item.action_family not in _ACTION_FAMILIES:
        raise ApprovalSummaryClientError("invalid_request")
    target_basename = validate_target_basename(item.target_basename)
    if target_basename is None:
        raise ApprovalSummaryClientError("invalid_request")
    opened_at = _validate_timestamp_string(item.opened_at)
    return ApprovalPendingItem(
        approval_id=approval_id,
        action_family=item.action_family,
        target_basename=target_basename,
        opened_at=opened_at,
    )


def _validate_resolution_item(item: object) -> ApprovalResolutionItem:
    if not isinstance(item, ApprovalResolutionItem):
        raise ApprovalSummaryClientError("invalid_request")
    approval_id = _validate_opaque_id(item.approval_id)
    if approval_id is None:
        raise ApprovalSummaryClientError("invalid_request")
    if not isinstance(item.status, str) or item.status not in _RESOLUTION_STATUSES:
        raise ApprovalSummaryClientError("invalid_request")
    resolved_at = _validate_timestamp_string(item.resolved_at)
    return ApprovalResolutionItem(
        approval_id=approval_id,
        status=item.status,
        resolved_at=resolved_at,
    )


def _validate_payload_lists(
    pending: tuple[ApprovalPendingItem, ...],
    resolutions: tuple[ApprovalResolutionItem, ...],
) -> tuple[tuple[ApprovalPendingItem, ...], tuple[ApprovalResolutionItem, ...]]:
    if not isinstance(pending, tuple) or not isinstance(resolutions, tuple):
        raise ApprovalSummaryClientError("invalid_request")
    if len(pending) > _MAX_LIST_ITEMS or len(resolutions) > _MAX_LIST_ITEMS:
        raise ApprovalSummaryClientError("invalid_request")
    validated_pending = tuple(_validate_pending_item(item) for item in pending)
    validated_resolutions = tuple(_validate_resolution_item(item) for item in resolutions)
    pending_ids = [item.approval_id for item in validated_pending]
    resolution_ids = [item.approval_id for item in validated_resolutions]
    if len(set(pending_ids)) != len(pending_ids):
        raise ApprovalSummaryClientError("invalid_request")
    if len(set(resolution_ids)) != len(resolution_ids):
        raise ApprovalSummaryClientError("invalid_request")
    overlap = set(pending_ids) & set(resolution_ids)
    if overlap:
        raise ApprovalSummaryClientError("invalid_request")
    return validated_pending, validated_resolutions


def payload_to_request_body(payload: ApprovalSummaryPayload) -> dict[str, Any]:
    if not isinstance(payload, ApprovalSummaryPayload):
        raise ApprovalSummaryClientError("invalid_request")
    if payload.schema_version != _SCHEMA_VERSION:
        raise ApprovalSummaryClientError("invalid_request")
    observed_at = _validate_timestamp_string(payload.observed_at)
    pending, resolutions = _validate_payload_lists(payload.pending, payload.resolutions)
    snapshot_id = _validate_opaque_id(payload.snapshot_id)
    if snapshot_id is None:
        raise ApprovalSummaryClientError("invalid_request")
    idempotency_key = None
    if payload.idempotency_key is not None:
        idempotency_key = _validate_opaque_id(payload.idempotency_key)
        if idempotency_key is None:
            raise ApprovalSummaryClientError("invalid_request")
    expected_digest = _canonical_request_digest(
        schema_version=_SCHEMA_VERSION,
        observed_at=observed_at,
        pending=pending,
        resolutions=resolutions,
    )
    expected_snapshot_id, expected_idempotency_key = _derive_payload_identity(
        observed_at=observed_at,
        pending=pending,
        resolutions=resolutions,
    )
    if snapshot_id != expected_snapshot_id:
        raise ApprovalSummaryClientError("invalid_request")
    if idempotency_key is not None and idempotency_key != expected_idempotency_key:
        raise ApprovalSummaryClientError("invalid_request")
    body: dict[str, Any] = _canonical_request_content(
        schema_version=_SCHEMA_VERSION,
        observed_at=observed_at,
        pending=pending,
        resolutions=resolutions,
    )
    body["snapshot_id"] = snapshot_id
    if idempotency_key is not None:
        body["idempotency_key"] = idempotency_key
    if set(body.keys()) - _REQUEST_KEYS:
        raise ApprovalSummaryClientError("invalid_request")
    if _canonical_request_digest(
        schema_version=body["schema_version"],
        observed_at=body["observed_at"],
        pending=pending,
        resolutions=resolutions,
    ) != expected_digest:
        raise ApprovalSummaryClientError("invalid_request")
    return body


def _require_response_string(value: object) -> str:
    if not isinstance(value, str):
        raise ApprovalSummaryClientError("malformed_body")
    return value


def _decode_response_object(
    response: RawResponse,
    *,
    request: ApprovalSummaryPayload,
) -> None:
    if response.status != 200:
        raise ApprovalSummaryClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise ApprovalSummaryClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise ApprovalSummaryClientError("response_too_large")
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ApprovalSummaryClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise ApprovalSummaryClientError("malformed_body")
    if set(parsed) != _RESPONSE_KEYS:
        raise ApprovalSummaryClientError("malformed_body")

    if _require_response_string(parsed["schema_version"]) != request.schema_version:
        raise ApprovalSummaryClientError("malformed_body")
    response_observed = _canonical_timestamp(
        _parse_rfc3339_utc(_require_response_string(parsed["observed_at"]))
    )
    if response_observed != request.observed_at:
        raise ApprovalSummaryClientError("malformed_body")
    pending_count = parsed["pending_count"]
    if isinstance(pending_count, bool) or not isinstance(pending_count, int):
        raise ApprovalSummaryClientError("malformed_body")
    if pending_count != len(request.pending):
        raise ApprovalSummaryClientError("malformed_body")
    status = _require_response_string(parsed["status"])
    if status not in _ACK_STATUSES:
        raise ApprovalSummaryClientError("malformed_body")
    return status


class ConsoleApprovalSummaryClient:
    """Fixed-origin client for bounded approval-summary ingest."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
    ) -> None:
        self._transport = transport or _urllib_transport

    def upload(
        self,
        payload: ApprovalSummaryPayload,
        *,
        bearer_token: str,
    ) -> str:
        body_obj = payload_to_request_body(payload)
        body = json.dumps(body_obj, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        }
        url = CONSOLE_ORIGIN + _INGEST_PATH
        split = urlsplit(url)
        if split.scheme != "https" or split.netloc != _ORIGIN_HOST:
            raise ApprovalSummaryClientError("invalid_origin")
        try:
            response = self._transport(
                "POST",
                url,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except TransportError as exc:
            raise ApprovalSummaryClientError("transport_failed") from exc
        return _decode_response_object(response, request=payload)


def _resolve_credential(
    *,
    home: Path | None,
    load_credential_fn: LoadCredential,
) -> tuple[StoredCredential | None, str | None]:
    try:
        credential = load_credential_fn(home=home)
    except CredentialError:
        return None, "skipped_unsafe_credential"
    if credential is None:
        return None, "skipped_no_credential"
    if credential.scope != CREDENTIAL_SCOPE:
        return None, "skipped_unsafe_credential"
    return credential, None


def sync_approval_summary(
    payload: ApprovalSummaryPayload,
    *,
    home: Path | None = None,
    load_credential_fn: LoadCredential = load_credential,
    transport: Transport | None = None,
) -> str:
    """Upload one bounded approval snapshot; return a short stable outcome code."""

    credential, skip = _resolve_credential(home=home, load_credential_fn=load_credential_fn)
    if skip is not None:
        return skip
    assert credential is not None
    client = ConsoleApprovalSummaryClient(transport=transport)
    try:
        return client.upload(payload, bearer_token=credential.token)
    except ApprovalSummaryClientError as exc:
        if exc.code in {"transport_failed", "unexpected_status"}:
            return "unavailable"
        return "rejected"
    return "accepted"


class ConsoleApprovalSummaryDispatcher:
    """Bounded in-process background uploader for approval snapshots."""

    def __init__(
        self,
        *,
        snapshot_source: SnapshotSource,
        queue_capacity: int = _DEFAULT_QUEUE_CAPACITY,
        home: Path | None = None,
        load_credential_fn: LoadCredential = load_credential,
        transport: Transport | None = None,
        upload_fn: UploadSummary | None = None,
    ) -> None:
        self._snapshot_source = snapshot_source
        self._queue: queue.Queue[bool] = queue.Queue(maxsize=queue_capacity)
        self._home = home
        self._load_credential_fn = load_credential_fn
        self._transport = transport
        self._upload_fn = upload_fn or sync_approval_summary
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._active = False
        self._last_uploaded_state_fingerprint: str | None = None
        self._startup_upload_pending = True

    @property
    def is_active(self) -> bool:
        return self._active

    def start(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        _, skip = _resolve_credential(
            home=self._home,
            load_credential_fn=self._load_credential_fn,
        )
        if skip is not None:
            self._active = False
            return
        self._active = True
        self._stop.clear()
        self._last_uploaded_state_fingerprint = None
        self._startup_upload_pending = True
        self._worker = threading.Thread(
            target=self._run,
            name="console-approval-summary",
            daemon=True,
        )
        self._worker.start()

    def stop(
        self,
        *,
        timeout: float = _SHUTDOWN_JOIN_TIMEOUT_SECONDS,
    ) -> None:
        if not self._active:
            return
        self._stop.set()
        self._drop_pending_queue()
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=timeout)
        self._active = False

    def request_snapshot(self) -> None:
        if not self._active or self._stop.is_set():
            return
        try:
            self._queue.put_nowait(True)
        except queue.Full:
            return

    def _drop_pending_queue(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if self._stop.is_set():
                return
            self._drain_queue()
            try:
                self._process()
            except Exception:
                continue

    def _drain_queue(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def _process(self) -> None:
        if self._stop.is_set():
            return
        payload = self._snapshot_source()
        if payload is None:
            return
        fingerprint = _bounded_state_fingerprint(payload)
        if (
            not self._startup_upload_pending
            and self._last_uploaded_state_fingerprint is not None
            and fingerprint == self._last_uploaded_state_fingerprint
        ):
            return
        try:
            outcome = self._upload_fn(
                payload,
                home=self._home,
                load_credential_fn=self._load_credential_fn,
                transport=self._transport,
            )
        except Exception:
            return
        if outcome in _ACK_STATUSES:
            self._last_uploaded_state_fingerprint = fingerprint
            self._startup_upload_pending = False


def attach_approval_state_observer(
    manager: Any,
    dispatcher: ConsoleApprovalSummaryDispatcher,
) -> None:
    """Register the bounded approval snapshot dispatcher on one manager."""

    manager.approval_state_observer = dispatcher.request_snapshot


__all__ = [
    "CONSOLE_ORIGIN",
    "ApprovalPendingItem",
    "ApprovalResolutionItem",
    "ApprovalSummaryClientError",
    "ApprovalSummaryPayload",
    "ConsoleApprovalSummaryClient",
    "ConsoleApprovalSummaryDispatcher",
    "RawResponse",
    "Transport",
    "TransportError",
    "attach_approval_state_observer",
    "build_approval_summary_snapshot",
    "derive_approval_id",
    "payload_to_request_body",
    "sync_approval_summary",
    "target_basename_from_resource_plain",
    "validate_target_basename",
]
