# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Bounded Console decision-summary upload client and background dispatcher."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
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
    console_credential_home_for_runtime,
    load_credential,
)
from agentveil_mcp_proxy.evidence import ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.evidence.observability import parse_action_gate_metadata

CONSOLE_ORIGIN = "https://agentveil.dev"
_ORIGIN_HOST = "agentveil.dev"
_INGEST_PATH = "/console/decision-summaries/ingest"

_REQUEST_TIMEOUT_SECONDS = 3.0
_MAX_RESPONSE_BYTES = 16 * 1024
_SCHEMA_VERSION = "1"
_DEFAULT_QUEUE_CAPACITY = 256
_MAX_DEDUP_KEYS = 4096
_SHUTDOWN_JOIN_TIMEOUT_SECONDS = _REQUEST_TIMEOUT_SECONDS + 0.25
_HOOK_DENIED_UPLOAD_QUEUE_CAPACITY = 256
_MAX_HOOK_WORKER_INPUT_BYTES = 4096

_DECISION_ALLOWED = "allowed"
_DECISION_DENIED = "denied"
_PROOF_INTACT = "intact"
_PROOF_UNAVAILABLE = "unavailable"

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

_HOOK_NATIVE_TOOL_ACTION_FAMILIES: dict[str, str] = {
    "bash": "shell_like",
    "shell": "shell_like",
    "run_shell_command": "shell_like",
}

_REQUEST_KEYS = frozenset({
    "schema_version",
    "event_id",
    "action_family",
    "decision",
    "occurred_at",
    "target_reached",
    "proof_status",
    "proof_hash",
    "idempotency_key",
})
_RESPONSE_KEYS = frozenset({
    "schema_version",
    "decision",
    "action_family",
    "occurred_at",
    "target_reached",
    "proof_status",
    "status",
})
_ACK_STATUSES = frozenset({"accepted", "duplicate"})
_HOOK_DENIED_UPLOAD_ACK_STATUSES = frozenset({"accepted", "duplicate"})

_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PROOF_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_FORBIDDEN_EVENT_ID_FRAGMENTS = ("/Users/", "/home/", "../", "..\\", "C:\\")
_FORBIDDEN_EVENT_ID_SUBSTRINGS = (
    "secret",
    "token",
    "password",
    "apikey",
    "api_key",
    "private",
    "bearer",
)

_UPLOADABLE_STATUSES = frozenset({
    ApprovalStatus.EXECUTED.value,
    ApprovalStatus.ERROR.value,
    ApprovalStatus.DENIED.value,
    ApprovalStatus.BLOCKED.value,  # claim-check: allow terminal evidence status enum value
})

_hook_denied_deduper_lock = threading.Lock()
_hook_denied_seen_event_ids: set[str] = set()
_hook_denied_seen_order: list[str] = []
_hook_denied_pending_event_ids: set[str] = set()
_hook_denied_upload_queue: queue.Queue["_HookDeniedUploadJob"] = queue.Queue(
    maxsize=_HOOK_DENIED_UPLOAD_QUEUE_CAPACITY
)
_hook_denied_worker_lock = threading.Lock()
_hook_denied_worker: threading.Thread | None = None


class DecisionSummaryClientError(RuntimeError):
    """Bounded client failure with a short stable code only."""

    def __init__(self, code: str = "decision_summary_failed"):
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
class DecisionSummaryPayload:
    schema_version: str
    event_id: str
    action_family: str
    decision: str
    occurred_at: str
    target_reached: bool | None
    proof_status: str
    proof_hash: str | None = None
    idempotency_key: str | None = None


Transport = Callable[..., RawResponse]
LoadCredential = Callable[..., StoredCredential | None]
TerminalEvidenceObserver = Callable[[PendingApproval], None]
UploadSummary = Callable[[DecisionSummaryPayload], str]


@dataclass(frozen=True)
class _HookDeniedUploadJob:
    payload: DecisionSummaryPayload
    home: Path | None
    load_credential_fn: LoadCredential
    upload_fn: UploadSummary | None
    transport: Transport | None


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
        raise DecisionSummaryClientError("response_too_large")
    return raw


def _validate_json_content_type(value: str) -> None:
    if "," in value:
        raise DecisionSummaryClientError("bad_content_type")
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        raise DecisionSummaryClientError("bad_content_type")
    if len(parts) > 2:
        raise DecisionSummaryClientError("bad_content_type")
    if len(parts) == 2 and not parts[1].lower().startswith("charset="):
        raise DecisionSummaryClientError("bad_content_type")
    if len(parts) == 2 and len(parts[1].split("=", 1)[1].strip()) == 0:
        raise DecisionSummaryClientError("bad_content_type")
    if len(parts) == 2:
        charset = parts[1].split("=", 1)[1].strip().lower()
        if charset not in {"utf-8", "utf8"}:
            raise DecisionSummaryClientError("bad_content_type")


def _parse_rfc3339_utc(value: str) -> datetime:
    text = str(value).strip()
    if not text or "T" not in text:
        raise DecisionSummaryClientError("invalid_occurred_at")
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DecisionSummaryClientError("invalid_occurred_at") from exc
    if parsed.tzinfo is None:
        raise DecisionSummaryClientError("invalid_occurred_at")
    return parsed.astimezone(timezone.utc)


def _canonical_occurred_at(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    text = utc.strftime("%Y-%m-%dT%H:%M:%S")
    micros = utc.microsecond
    if micros:
        text += f".{micros:06d}".rstrip("0").rstrip(".")
    return f"{text}Z"


def _occurred_at_from_record(record: PendingApproval) -> str:
    timestamp = record.approval_decided_at or record.created_at
    return _canonical_occurred_at(
        datetime.fromtimestamp(int(timestamp), timezone.utc)
    )


def _validate_event_id(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    if not _EVENT_ID_RE.fullmatch(value):
        return None
    lowered = value.lower()
    for fragment in _FORBIDDEN_EVENT_ID_FRAGMENTS:
        if fragment.lower() in lowered:
            return None
    for forbidden in _FORBIDDEN_EVENT_ID_SUBSTRINGS:
        if forbidden in lowered:
            return None
    return value


def _validate_idempotency_key(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    if not _IDEMPOTENCY_KEY_RE.fullmatch(value):
        return None
    return value


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


def _resolve_target_reached(record: PendingApproval) -> bool | None:
    metadata = parse_action_gate_metadata(record)
    if metadata is None or "target_reached" not in metadata:
        return None
    value = metadata.get("target_reached")
    if isinstance(value, bool):
        return value
    return None


def _runtime_gate_receipt_binding(record: PendingApproval) -> bool:
    audit_id = record.decision_audit_id
    digest = record.decision_receipt_sha256
    if not isinstance(audit_id, str) or not audit_id.strip():
        return False
    if not isinstance(digest, str) or not _PROOF_HASH_RE.fullmatch(digest):
        return False
    return True


def _resolve_proof(record: PendingApproval) -> tuple[str, str | None]:
    if not _runtime_gate_receipt_binding(record):
        return _PROOF_UNAVAILABLE, None
    return _PROOF_INTACT, record.decision_receipt_sha256


def _approved_execution_error(record: PendingApproval) -> bool:
    if record.status != ApprovalStatus.ERROR.value:
        return False
    if record.approval_decided_at or record.approval_grant_jcs:
        return True
    return _runtime_gate_receipt_binding(record)


def build_decision_summary_payload(
    record: PendingApproval,
) -> DecisionSummaryPayload | None:
    """Map one terminal evidence record to a bounded ingest payload or skip."""

    if record.status not in _UPLOADABLE_STATUSES:
        return None

    event_id = _validate_event_id(record.request_id)
    if event_id is None:
        return None

    action_family = _resolve_action_family(record)
    if action_family is None:
        return None

    if record.status == ApprovalStatus.EXECUTED.value:
        decision = _DECISION_ALLOWED
        target_reached = _resolve_target_reached(record)
    elif record.status == ApprovalStatus.ERROR.value:
        if not _approved_execution_error(record):
            return None
        decision = _DECISION_ALLOWED
        target_reached = False
    elif record.status in {
        ApprovalStatus.DENIED.value,
        ApprovalStatus.BLOCKED.value,  # claim-check: allow terminal evidence status enum value
    }:
        decision = _DECISION_DENIED
        target_reached = False
    else:
        return None

    proof_status, proof_hash = _resolve_proof(record)
    idempotency_key = _validate_idempotency_key(event_id)
    return DecisionSummaryPayload(
        schema_version=_SCHEMA_VERSION,
        event_id=event_id,
        action_family=action_family,
        decision=decision,
        occurred_at=_occurred_at_from_record(record),
        target_reached=target_reached,
        proof_status=proof_status,
        proof_hash=proof_hash,
        idempotency_key=idempotency_key,
    )


def _hook_denied_idempotency_material(record: Mapping[str, Any]) -> dict[str, str]:
    input_ref = record.get("input_ref")
    input_hash = ""
    if isinstance(input_ref, Mapping):
        raw = input_ref.get("input_hash")
        if isinstance(raw, str):
            input_hash = raw
    hook_event = str(
        record.get("hook_event")
        or record.get("hook_event_name")
        or ""
    )
    session_id = str(record.get("session_id") or "")
    return {
        "hook_event": hook_event,
        "server": str(record.get("server") or ""),
        "tool": str(record.get("tool") or record.get("tool_name") or ""),
        "reason_code": str(record.get("reason_code") or ""),
        "input_hash": input_hash,
        "session_digest": hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16],
    }


def _hook_denied_event_id(record: Mapping[str, Any]) -> str | None:
    material = _hook_denied_idempotency_material(record)
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _validate_event_id(f"hook.denied.{digest[:32]}")


def _hook_denied_action_family(record: Mapping[str, Any]) -> str | None:
    raw = record.get("action_family")
    if isinstance(raw, str) and raw in _ACTION_FAMILIES:
        return raw
    tool = record.get("tool") or record.get("tool_name")
    if isinstance(tool, str):
        mapped = _HOOK_NATIVE_TOOL_ACTION_FAMILIES.get(tool.lower())
        if mapped in _ACTION_FAMILIES:
            return mapped
        inferred = infer_action_family(tool)
        if inferred in _ACTION_FAMILIES:
            return inferred
    return None


def reset_hook_denied_upload_dedupe_for_tests() -> None:
    """Clear in-process hook-deny upload dedupe (test isolation only)."""

    if not wait_for_hook_denied_uploads_for_tests():
        raise RuntimeError("hook_denied_upload_worker_busy")
    with _hook_denied_deduper_lock:
        _hook_denied_seen_event_ids.clear()
        _hook_denied_seen_order.clear()
        _hook_denied_pending_event_ids.clear()
    while True:
        try:
            _hook_denied_upload_queue.get_nowait()
        except queue.Empty:
            break
        _hook_denied_upload_queue.task_done()


def wait_for_hook_denied_uploads_for_tests(timeout: float = 5.0) -> bool:
    """Wait for queued hook-deny uploads to finish (test isolation only)."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _hook_denied_upload_queue.all_tasks_done:
            if _hook_denied_upload_queue.unfinished_tasks == 0:
                return True
        time.sleep(0.005)
    return False


def _hook_denied_occurred_at(record: Mapping[str, Any]) -> str:
    ts = record.get("ts")
    if isinstance(ts, str) and ts.strip():
        try:
            return _canonical_occurred_at(_parse_rfc3339_utc(ts))
        except DecisionSummaryClientError:
            pass
    return _canonical_occurred_at(datetime.now(timezone.utc))


def build_hook_denied_decision_summary_payload(
    evidence_record: Mapping[str, Any],
) -> DecisionSummaryPayload | None:
    """Map one bounded hook deny evidence record to an ingest payload or skip."""

    if evidence_record.get("hook_action") != "deny":
        return None

    event_id = _hook_denied_event_id(evidence_record)
    if event_id is None:
        return None

    action_family = _hook_denied_action_family(evidence_record)
    if action_family is None:
        return None

    idempotency_key = _validate_idempotency_key(event_id)
    return DecisionSummaryPayload(
        schema_version=_SCHEMA_VERSION,
        event_id=event_id,
        action_family=action_family,
        decision=_DECISION_DENIED,
        occurred_at=_hook_denied_occurred_at(evidence_record),
        target_reached=False,
        proof_status=_PROOF_UNAVAILABLE,
        proof_hash=None,
        idempotency_key=idempotency_key,
    )


def _is_hook_denied_event_seen(event_id: str) -> bool:
    with _hook_denied_deduper_lock:
        return event_id in _hook_denied_seen_event_ids


def _mark_hook_denied_event_seen(event_id: str) -> None:
    with _hook_denied_deduper_lock:
        if event_id in _hook_denied_seen_event_ids:
            return
        _hook_denied_seen_event_ids.add(event_id)
        _hook_denied_seen_order.append(event_id)
        if len(_hook_denied_seen_order) > _MAX_DEDUP_KEYS:
            oldest = _hook_denied_seen_order.pop(0)
            _hook_denied_seen_event_ids.discard(oldest)


def _mark_hook_denied_event_pending(event_id: str) -> bool:
    with _hook_denied_deduper_lock:
        if event_id in _hook_denied_seen_event_ids:
            return False
        if event_id in _hook_denied_pending_event_ids:
            return False
        _hook_denied_pending_event_ids.add(event_id)
        return True


def _clear_hook_denied_event_pending(event_id: str) -> None:
    with _hook_denied_deduper_lock:
        _hook_denied_pending_event_ids.discard(event_id)


def _ensure_hook_denied_upload_worker() -> None:
    global _hook_denied_worker
    with _hook_denied_worker_lock:
        if _hook_denied_worker is not None and _hook_denied_worker.is_alive():
            return
        _hook_denied_worker = threading.Thread(
            target=_run_hook_denied_upload_worker,
            name="console-hook-denied-upload",
            daemon=True,
        )
        _hook_denied_worker.start()


def _run_hook_denied_upload_worker() -> None:
    while True:
        job = _hook_denied_upload_queue.get()
        try:
            _process_hook_denied_upload_job(job)
        finally:
            _clear_hook_denied_event_pending(job.payload.event_id)
            _hook_denied_upload_queue.task_done()


def _process_hook_denied_upload_job(job: _HookDeniedUploadJob) -> None:
    try:
        if _is_hook_denied_event_seen(job.payload.event_id):
            return
        uploader = job.upload_fn or sync_decision_summary
        result = uploader(
            job.payload,
            home=job.home,
            load_credential_fn=job.load_credential_fn,
            transport=job.transport,
        )
        if isinstance(result, str) and result in _HOOK_DENIED_UPLOAD_ACK_STATUSES:
            _mark_hook_denied_event_seen(job.payload.event_id)
    except Exception:
        return


def best_effort_upload_hook_denied_summary(
    evidence_record: Mapping[str, Any],
    *,
    home: Path | None = None,
    load_credential_fn: LoadCredential = load_credential,
    upload_fn: UploadSummary | None = None,
    transport: Transport | None = None,
) -> None:
    """Queue one hook-deny upload without blocking the hook response path."""

    try:
        payload = build_hook_denied_decision_summary_payload(evidence_record)
        if payload is None:
            return
        if not _mark_hook_denied_event_pending(payload.event_id):
            return
        _ensure_hook_denied_upload_worker()
        _hook_denied_upload_queue.put_nowait(
            _HookDeniedUploadJob(
                payload=payload,
                home=home,
                load_credential_fn=load_credential_fn,
                upload_fn=upload_fn,
                transport=transport,
            )
        )
    except queue.Full:
        if "payload" in locals():
            _clear_hook_denied_event_pending(payload.event_id)
    except Exception:
        return


def _hook_worker_payload_from_body(body: Mapping[str, Any]) -> DecisionSummaryPayload:
    expected = {
        "schema_version",
        "event_id",
        "action_family",
        "decision",
        "occurred_at",
        "target_reached",
        "proof_status",
        "idempotency_key",
    }
    if set(body) != expected:
        raise DecisionSummaryClientError("invalid_worker_payload")
    event_id = _validate_event_id(body.get("event_id"))
    idempotency_key = _validate_idempotency_key(body.get("idempotency_key"))
    action_family = body.get("action_family")
    if event_id is None or idempotency_key != event_id:
        raise DecisionSummaryClientError("invalid_worker_payload")
    if action_family not in _ACTION_FAMILIES:
        raise DecisionSummaryClientError("invalid_worker_payload")
    if body.get("schema_version") != _SCHEMA_VERSION:
        raise DecisionSummaryClientError("invalid_worker_payload")
    if body.get("decision") != _DECISION_DENIED:
        raise DecisionSummaryClientError("invalid_worker_payload")
    if body.get("target_reached") is not False:
        raise DecisionSummaryClientError("invalid_worker_payload")
    if body.get("proof_status") != _PROOF_UNAVAILABLE:
        raise DecisionSummaryClientError("invalid_worker_payload")
    occurred_at = body.get("occurred_at")
    if not isinstance(occurred_at, str):
        raise DecisionSummaryClientError("invalid_worker_payload")
    canonical_occurred_at = _canonical_occurred_at(_parse_rfc3339_utc(occurred_at))
    if canonical_occurred_at != occurred_at:
        raise DecisionSummaryClientError("invalid_worker_payload")
    return DecisionSummaryPayload(
        schema_version=_SCHEMA_VERSION,
        event_id=event_id,
        action_family=action_family,
        decision=_DECISION_DENIED,
        occurred_at=occurred_at,
        target_reached=False,
        proof_status=_PROOF_UNAVAILABLE,
        proof_hash=None,
        idempotency_key=idempotency_key,
    )


def run_hook_denied_upload_worker(
    *,
    stdin: Any = None,
    upload_fn: UploadSummary | None = None,
) -> int:
    """Consume one bounded summary from stdin and upload it synchronously."""

    source = stdin or sys.stdin.buffer
    try:
        raw = source.read(_MAX_HOOK_WORKER_INPUT_BYTES + 1)
        if not isinstance(raw, bytes) or len(raw) > _MAX_HOOK_WORKER_INPUT_BYTES:
            return 2
        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, Mapping):
            return 2
        payload = _hook_worker_payload_from_body(decoded)
        uploader = upload_fn or sync_decision_summary
        outcome = uploader(payload)
    except Exception:
        return 2
    return 0 if outcome in _HOOK_DENIED_UPLOAD_ACK_STATUSES else 1


def _hook_denied_worker_environment(
    runtime_home: Path | None,
) -> tuple[dict[str, str], Path | None]:
    env = dict(os.environ)
    credential_home = console_credential_home_for_runtime(runtime_home)
    configured_home = env.get("AVP_HOME")
    if configured_home and runtime_home is not None:
        if Path(configured_home).expanduser() == runtime_home.expanduser():
            env.pop("AVP_HOME", None)
    return env, credential_home


def best_effort_spawn_hook_denied_summary(
    evidence_record: Mapping[str, Any],
    *,
    runtime_home: Path | None = None,
    load_credential_fn: LoadCredential = load_credential,
) -> None:
    """Detach one bounded hook-deny upload so the hook can return immediately."""

    try:
        payload = build_hook_denied_decision_summary_payload(evidence_record)
        if payload is None:
            return
        env, credential_home = _hook_denied_worker_environment(runtime_home)
        _, skip = _resolve_credential(
            home=credential_home,
            load_credential_fn=load_credential_fn,
        )
        if skip is not None:
            return
        encoded = json.dumps(
            payload_to_request_body(payload),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > _MAX_HOOK_WORKER_INPUT_BYTES:
            return
        process = subprocess.Popen(
            [sys.executable, "-m", __name__, "--hook-denied-upload-worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        assert process.stdin is not None
        process.stdin.write(encoded)
        process.stdin.close()
        threading.Thread(target=process.wait, daemon=True).start()
    except Exception:
        return


def payload_to_request_body(payload: DecisionSummaryPayload) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": payload.schema_version,
        "event_id": payload.event_id,
        "action_family": payload.action_family,
        "decision": payload.decision,
        "occurred_at": payload.occurred_at,
        "target_reached": payload.target_reached,
        "proof_status": payload.proof_status,
    }
    if payload.proof_hash is not None:
        body["proof_hash"] = payload.proof_hash
    if payload.idempotency_key is not None:
        body["idempotency_key"] = payload.idempotency_key
    if set(body.keys()) - _REQUEST_KEYS:
        raise DecisionSummaryClientError("invalid_request")
    if payload.proof_status == _PROOF_UNAVAILABLE and "proof_hash" in body:
        raise DecisionSummaryClientError("invalid_request")
    return body


def _require_response_string(value: object) -> str:
    if not isinstance(value, str):
        raise DecisionSummaryClientError("malformed_body")
    return value


def _decode_response_object(
    response: RawResponse,
    *,
    request: DecisionSummaryPayload,
) -> str:
    if response.status != 200:
        raise DecisionSummaryClientError("unexpected_status")
    if len(response.content_types) != 1:
        raise DecisionSummaryClientError("bad_content_type")
    _validate_json_content_type(response.content_types[0])
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise DecisionSummaryClientError("response_too_large")
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecisionSummaryClientError("malformed_body") from exc
    if not isinstance(parsed, dict):
        raise DecisionSummaryClientError("malformed_body")
    if set(parsed) != _RESPONSE_KEYS:
        raise DecisionSummaryClientError("malformed_body")

    if _require_response_string(parsed["schema_version"]) != request.schema_version:
        raise DecisionSummaryClientError("malformed_body")
    if _require_response_string(parsed["decision"]) != request.decision:
        raise DecisionSummaryClientError("malformed_body")
    if _require_response_string(parsed["action_family"]) != request.action_family:
        raise DecisionSummaryClientError("malformed_body")
    response_occurred = _canonical_occurred_at(
        _parse_rfc3339_utc(_require_response_string(parsed["occurred_at"]))
    )
    if response_occurred != request.occurred_at:
        raise DecisionSummaryClientError("malformed_body")
    target = parsed["target_reached"]
    if target is not None and not isinstance(target, bool):
        raise DecisionSummaryClientError("malformed_body")
    if target != request.target_reached:
        raise DecisionSummaryClientError("malformed_body")
    if _require_response_string(parsed["proof_status"]) != request.proof_status:
        raise DecisionSummaryClientError("malformed_body")
    status = _require_response_string(parsed["status"])
    if status not in _ACK_STATUSES:
        raise DecisionSummaryClientError("malformed_body")
    return status


class ConsoleDecisionSummaryClient:
    """Fixed-origin client for bounded decision-summary ingest."""

    def __init__(
        self,
        *,
        transport: Transport | None = None,
    ) -> None:
        self._transport = transport or _urllib_transport

    def upload(
        self,
        payload: DecisionSummaryPayload,
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
            raise DecisionSummaryClientError("invalid_origin")
        try:
            response = self._transport(
                "POST",
                url,
                headers=headers,
                body=body,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except TransportError as exc:
            raise DecisionSummaryClientError("transport_failed") from exc
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


def sync_decision_summary(
    payload: DecisionSummaryPayload,
    *,
    home: Path | None = None,
    load_credential_fn: LoadCredential = load_credential,
    transport: Transport | None = None,
) -> str:
    """Best-effort upload returning a short non-secret result code."""

    credential, skip = _resolve_credential(
        home=home,
        load_credential_fn=load_credential_fn,
    )
    if skip is not None:
        return skip

    client = ConsoleDecisionSummaryClient(transport=transport)
    try:
        assert credential is not None
        return client.upload(payload, bearer_token=credential.token)
    except DecisionSummaryClientError as exc:
        if exc.code in {"transport_failed", "unexpected_status"}:
            return "unavailable"
        return "rejected"


class ConsoleDecisionSummaryDispatcher:
    """Bounded in-process background uploader for terminal evidence."""

    def __init__(
        self,
        *,
        queue_capacity: int = _DEFAULT_QUEUE_CAPACITY,
        home: Path | None = None,
        load_credential_fn: LoadCredential = load_credential,
        transport: Transport | None = None,
        upload_fn: UploadSummary | None = None,
    ) -> None:
        self._queue: queue.Queue[PendingApproval] = queue.Queue(maxsize=queue_capacity)
        self._home = home
        self._load_credential_fn = load_credential_fn
        self._transport = transport
        self._upload_fn = upload_fn or sync_decision_summary
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()
        self._seen_event_ids: set[str] = set()
        self._seen_order: list[str] = []
        self._active = False

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
        self._worker = threading.Thread(
            target=self._run,
            name="console-decision-summary",
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

    def notify_terminal_record(self, record: PendingApproval) -> None:
        if not self._active or self._stop.is_set():
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            return

    def _drop_pending_queue(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def _event_seen(self, event_id: str) -> bool:
        with self._lock:
            return event_id in self._seen_event_ids

    def _remember_event(self, event_id: str) -> None:
        with self._lock:
            if event_id in self._seen_event_ids:
                return
            self._seen_event_ids.add(event_id)
            self._seen_order.append(event_id)
            if len(self._seen_order) > _MAX_DEDUP_KEYS:
                oldest = self._seen_order.pop(0)
                self._seen_event_ids.discard(oldest)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                record = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if self._stop.is_set():
                return
            try:
                self._process(record)
            except Exception:
                continue

    def _process(self, record: PendingApproval) -> None:
        if self._stop.is_set():
            return
        payload = build_decision_summary_payload(record)
        if payload is None:
            return
        if self._event_seen(payload.event_id):
            return
        if self._stop.is_set():
            return
        outcome = self._upload_fn(
            payload,
            home=self._home,
            load_credential_fn=self._load_credential_fn,
            transport=self._transport,
        )
        if outcome in _ACK_STATUSES:
            self._remember_event(payload.event_id)


def attach_terminal_evidence_observer(
    manager: Any,
    dispatcher: ConsoleDecisionSummaryDispatcher,
) -> None:
    """Register the bounded dispatcher on one approval manager instance."""

    manager.terminal_evidence_observer = dispatcher.notify_terminal_record


__all__ = [
    "CONSOLE_ORIGIN",
    "ConsoleDecisionSummaryClient",
    "ConsoleDecisionSummaryDispatcher",
    "DecisionSummaryClientError",
    "DecisionSummaryPayload",
    "RawResponse",
    "Transport",
    "TransportError",
    "attach_terminal_evidence_observer",
    "best_effort_spawn_hook_denied_summary",
    "best_effort_upload_hook_denied_summary",
    "build_decision_summary_payload",
    "build_hook_denied_decision_summary_payload",
    "payload_to_request_body",
    "reset_hook_denied_upload_dedupe_for_tests",
    "run_hook_denied_upload_worker",
    "sync_decision_summary",
    "wait_for_hook_denied_uploads_for_tests",
]


if __name__ == "__main__":
    if sys.argv[1:] == ["--hook-denied-upload-worker"]:
        raise SystemExit(run_hook_denied_upload_worker())
    raise SystemExit(2)
