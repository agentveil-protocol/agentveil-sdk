"""Bounded evidence-summary output for default CLI artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from typing import Any

from agentveil_mcp_proxy.authority_boundary import parse_authority_from_metadata
from agentveil_mcp_proxy.redirect_playbooks import redirect_metadata_from_action_gate
from agentveil_mcp_proxy.evidence.observability import execution_record_id_by_parent
from agentveil_mcp_proxy.evidence.observability import parse_action_gate_metadata
from agentveil_mcp_proxy.evidence.store import ApprovalStatus, PendingApproval
from agentveil_mcp_proxy.passthrough import DownstreamConfig, PassthroughError
from agentveil_mcp_proxy.policy import ProxyConfig

_PRIVACY_FAIL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/tmp/\S+"), "/tmp"),
    (re.compile(r"/Users/\S+"), "/Users"),
    (re.compile(r"/private/\S+"), "/private"),
    (re.compile(r"/var/folders/\S+"), "/var/folders"),
    (re.compile(r"(?i)\bpassphrase\b"), "passphrase"),
    (re.compile(r"\bTOKEN\b"), "TOKEN"),
    (re.compile(r"\bSECRET\b"), "SECRET"),
    (re.compile(r"\bPASSWORD\b"), "PASSWORD"),
    (re.compile(r'"command"\s*:'), "raw command key"),
    (re.compile(r'"args"\s*:'), "raw args key"),
    (re.compile(r"\bPYTHONPATH\b"), "PYTHONPATH"),
)


def _bounded_ref(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _path_basename(value: str) -> str:
    return re.split(r"[\\/]", str(value))[-1]


def _resource_ref(resource_hash: str | None) -> str | None:
    if not resource_hash:
        return None
    digest = str(resource_hash)
    if digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    return digest[:16] if digest else None


def bounded_downstream_info(config: ProxyConfig) -> dict[str, Any]:
    """Return bounded downstream metadata without runnable command/args."""

    if not config.downstream:
        return {"configured": False}
    try:
        downstream = DownstreamConfig.from_proxy_config(config)
    except PassthroughError:
        return {"configured": False, "reason": "downstream_invalid"}
    env = dict(downstream.env or {})
    return {
        "configured": True,
        "downstream_kind": downstream.name,
        "command_ref": _bounded_ref(downstream.command),
        "command_basename": _path_basename(downstream.command),
        "args_count": len(downstream.args),
        "has_env": bool(env or downstream.env_passthrough),
        "env_keys_count": len(env) + len(downstream.env_passthrough),
        "response_timeout_seconds": downstream.response_timeout_seconds,
    }


def _target_reached(record: PendingApproval) -> bool:
    if record.status == ApprovalStatus.EXECUTED.value:
        return True
    return record.result_status == "executed"


def _summary_reason(record: PendingApproval) -> str | None:
    if record.error_class:
        return record.error_class
    if record.result_status:
        return record.result_status
    if record.policy_rule_id:
        return record.policy_rule_id
    return None


def evidence_summary_record(
    record: PendingApproval,
    *,
    execution_record_id: str | None = None,
) -> dict[str, Any]:
    """Build one bounded evidence-summary row."""

    payload: dict[str, Any] = {
        "evidence_id": record.request_id,
        "request_id": record.request_id,
        "tool_name": record.tool_name,
        "action_family": record.action_class,
        "decision": record.status,
        "target_reached": _target_reached(record),
        "risk_class": record.risk_class,
    }
    target_ref = _resource_ref(record.resource_hash)
    if target_ref:
        payload["target_ref"] = target_ref
    reason = _summary_reason(record)
    if reason:
        payload["reason"] = reason
    if record.client_id:
        payload["client_name"] = record.client_id.split(":", 1)[0]
    if execution_record_id:
        payload["execution_record_id"] = execution_record_id
    metadata = parse_action_gate_metadata(record)
    authority = parse_authority_from_metadata(metadata)
    if authority is not None:
        payload["authority"] = authority
    redirect_fields = redirect_metadata_from_action_gate(metadata)
    if redirect_fields:
        payload.update(redirect_fields)
    return payload


def build_evidence_summary(
    records: Sequence[PendingApproval],
    *,
    downstream: dict[str, Any] | None,
    latest_record_at: str | None,
) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    receipt_present = 0
    receipt_missing = 0
    execution_by_parent = execution_record_id_by_parent(records)
    for record in records:
        by_status[record.status] = by_status.get(record.status, 0) + 1
        if record.decision_receipt_sha256:
            receipt_present += 1
        elif record.decision_audit_id:
            receipt_missing += 1
    return {
        "ok": True,
        "errors": [],
        "warnings": [],
        "downstream": downstream,
        "record_count": len(records),
        "evidence_count": len(records),
        "by_status": by_status,
        "receipt_present_count": receipt_present,
        "receipt_missing_count": receipt_missing,
        "latest_record_at": latest_record_at,
        "records": [
            evidence_summary_record(
                record,
                execution_record_id=execution_by_parent.get(record.request_id),
            )
            for record in records
        ],
    }


def bounded_evidence_summary_error(*, code: str) -> dict[str, Any]:
    return {
        "ok": False,
        "errors": [code],
        "warnings": [],
        "downstream": None,
        "record_count": 0,
        "evidence_count": 0,
        "by_status": {},
        "receipt_present_count": 0,
        "receipt_missing_count": 0,
        "latest_record_at": None,
        "records": [],
    }


def privacy_markers_in_text(text: str) -> list[str]:
    findings: list[str] = []
    for pattern, label in _PRIVACY_FAIL_PATTERNS:
        if pattern.search(text or ""):
            findings.append(label)
    return findings


def assert_bounded_evidence_cli_output(*texts: str) -> None:
    for text in texts:
        if not text:
            continue
        findings = privacy_markers_in_text(text)
        assert findings == [], findings
        stripped = text.strip()
        if not stripped.startswith("{"):
            continue
        payload = json.loads(stripped)
        downstream = payload.get("downstream") or {}
        assert "command" not in downstream
        assert "args" not in downstream
        assert "env" not in downstream
