"""AVP Runtime Gate integration for the MCP proxy.

P5 is intentionally narrow: it submits privacy-filtered metadata to Runtime
Gate, verifies signed DecisionReceipt JCS against pinned signer DIDs, and
returns the verified backend decision to the passthrough layer. It does not
create approval UI, write WAL evidence, or implement a circuit breaker.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from agentveil.agent import AVPAgent
from agentveil.delegation import DelegationInvalid, verify_delegation
from agentveil.proof import ProofVerificationError, verify_signed_jcs
from agentveil_mcp_proxy.classification import ClassifiedToolCall
from agentveil_mcp_proxy.policy import ProxyConfig


DEFAULT_RUNTIME_GATE_TIMEOUT_SECONDS = 2.0
DEFAULT_RUNTIME_ENVIRONMENT = "mcp_proxy"
DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"
DECISION_WAITING = "WAITING_FOR_HUMAN_APPROVAL"

_DECISION_RECEIPT_SCHEMAS = {"decision_receipt/1", "decision_receipt/2"}
_RUNTIME_DECISIONS = {DECISION_ALLOW, DECISION_BLOCK, DECISION_WAITING}


class RuntimeGateError(RuntimeError):
    """Base class for sanitized Runtime Gate failures."""


class RuntimeGateUnavailableError(RuntimeGateError):
    """Raised when Runtime Gate cannot return a usable response in time."""


class RuntimeGateUntrustedError(RuntimeGateError):
    """Raised when a backend decision cannot be cryptographically trusted."""


@dataclass(frozen=True)
class RuntimeGateDecision:
    """Verified Runtime Gate decision returned to the passthrough layer."""

    decision: str
    audit_id: str | None
    approval_id: str | None
    receipt_digest: str
    receipt_body: Mapping[str, Any]


@dataclass(frozen=True)
class _RuntimeGateRequest:
    action: str
    resource: str
    environment: str
    payload_hash: str
    risk_class: str
    policy_context_hash: str


class RuntimeGateClient:
    """Call AVP Runtime Gate with privacy-safe metadata and verify receipts."""

    def __init__(
        self,
        *,
        agent: Any,
        config: ProxyConfig,
        control_grant: Mapping[str, Any],
        environment: str = DEFAULT_RUNTIME_ENVIRONMENT,
    ):
        self.agent = agent
        self.config = config
        self.control_grant = dict(control_grant)
        self.environment = environment
        self.trusted_signer_dids = tuple(config.avp.trusted_signer_dids)

    @classmethod
    def from_files(
        cls,
        *,
        identity_path: Path,
        control_grant_path: Path,
        config: ProxyConfig,
        agent_cls: Callable[..., Any] = AVPAgent,
        timeout: float = DEFAULT_RUNTIME_GATE_TIMEOUT_SECONDS,
        environment: str = DEFAULT_RUNTIME_ENVIRONMENT,
    ) -> "RuntimeGateClient":
        """Load local proxy identity/control grant and build a Runtime Gate client."""

        identity = _read_json_object(identity_path, "agent identity")
        control_grant = _read_json_object(control_grant_path, "control grant")
        private_key_hex = identity.get("private_key_hex")
        if not isinstance(private_key_hex, str) or not private_key_hex:
            raise RuntimeGateUnavailableError("proxy identity private key unavailable")
        try:
            private_key = bytes.fromhex(private_key_hex)
        except ValueError as exc:
            raise RuntimeGateUnavailableError("proxy identity private key invalid") from exc
        try:
            agent = agent_cls(
                config.avp.base_url,
                private_key,
                name=config.avp.agent_name,
                timeout=timeout,
            )
        except Exception as exc:
            raise RuntimeGateUnavailableError("proxy identity could not be loaded") from exc

        agent_did = getattr(agent, "did", None)
        if isinstance(identity.get("did"), str) and agent_did != identity["did"]:
            raise RuntimeGateUnavailableError("proxy identity DID mismatch")
        try:
            verified_grant = verify_delegation(dict(control_grant))
        except DelegationInvalid as exc:
            raise RuntimeGateUnavailableError("control grant invalid") from exc
        if agent_did and (
            verified_grant.get("issuer") != agent_did
            or verified_grant.get("subject") != agent_did
        ):
            raise RuntimeGateUnavailableError("control grant does not match proxy identity")

        return cls(
            agent=agent,
            config=config,
            control_grant=control_grant,
            environment=environment,
        )

    def evaluate(self, classification: ClassifiedToolCall) -> RuntimeGateDecision:
        """Submit one classified tool call and return a verified backend decision."""

        request = self._build_request(classification)
        try:
            response = self.agent.runtime_evaluate(
                action=request.action,
                resource=request.resource,
                environment=request.environment,
                delegation_receipt=self.control_grant,
                payload_hash=request.payload_hash,
                risk_class=request.risk_class,
                policy_context_hash=request.policy_context_hash,
            )
        except Exception as exc:
            raise RuntimeGateUnavailableError("runtime gate request failed") from exc
        if not isinstance(response, Mapping):
            raise RuntimeGateUnavailableError("runtime gate response invalid")

        receipt_jcs = self._decision_receipt_jcs(response)
        verified = self._verify_decision_receipt(receipt_jcs)
        body = verified["body"]
        self._validate_decision_body(body, response=response, request=request)
        return RuntimeGateDecision(
            decision=body["decision"],
            audit_id=_optional_str(body.get("audit_id")),
            approval_id=_optional_str(body.get("approval_id")),
            receipt_digest=verified["digest"],
            receipt_body=body,
        )

    def _build_request(self, classification: ClassifiedToolCall) -> _RuntimeGateRequest:
        metadata = classification.backend_metadata()
        return _RuntimeGateRequest(
            action=_runtime_field(metadata.get("action")),
            resource=_runtime_field(metadata.get("resource")),
            environment=self.environment,
            payload_hash=_required_str(metadata.get("payload_hash"), "payload_hash"),
            risk_class=_required_str(metadata.get("risk_class"), "risk_class"),
            policy_context_hash=_required_str(
                metadata.get("policy_context_hash"),
                "policy_context_hash",
            ),
        )

    def _decision_receipt_jcs(self, response: Mapping[str, Any]) -> str:
        for key in ("decision_receipt_jcs", "receipt_jcs"):
            value = response.get(key)
            if isinstance(value, str) and value:
                return value
        audit_id = response.get("audit_id")
        if not isinstance(audit_id, str) or not audit_id:
            raise RuntimeGateUntrustedError("runtime decision receipt missing")
        try:
            receipt_jcs = self.agent.get_decision_receipt(audit_id)
        except Exception as exc:
            raise RuntimeGateUnavailableError("runtime decision receipt fetch failed") from exc
        if not isinstance(receipt_jcs, str) or not receipt_jcs:
            raise RuntimeGateUntrustedError("runtime decision receipt missing")
        return receipt_jcs

    def _verify_decision_receipt(self, receipt_jcs: str) -> dict[str, Any]:
        if not self.trusted_signer_dids:
            raise RuntimeGateUntrustedError("trusted signer DID set is empty")
        last_error: ProofVerificationError | None = None
        for signer_did in self.trusted_signer_dids:
            try:
                return verify_signed_jcs(receipt_jcs, expected_signer_did=signer_did)
            except ProofVerificationError as exc:
                last_error = exc
        raise RuntimeGateUntrustedError("runtime decision receipt signer is not trusted") from last_error

    def _validate_decision_body(
        self,
        body: Mapping[str, Any],
        *,
        response: Mapping[str, Any],
        request: _RuntimeGateRequest,
    ) -> None:
        schema_version = body.get("schema_version")
        if schema_version not in _DECISION_RECEIPT_SCHEMAS:
            raise RuntimeGateUntrustedError("runtime decision receipt schema unsupported")
        decision = body.get("decision")
        if decision not in _RUNTIME_DECISIONS:
            raise RuntimeGateUntrustedError("runtime decision unsupported")
        response_decision = response.get("decision")
        if isinstance(response_decision, str) and response_decision != decision:
            raise RuntimeGateUntrustedError("runtime decision response mismatch")
        response_audit_id = response.get("audit_id")
        if (
            isinstance(response_audit_id, str)
            and isinstance(body.get("audit_id"), str)
            and response_audit_id != body["audit_id"]
        ):
            raise RuntimeGateUntrustedError("runtime decision audit mismatch")

        agent_did = getattr(self.agent, "did", None)
        if isinstance(body.get("agent_did"), str) and agent_did and body["agent_did"] != agent_did:
            raise RuntimeGateUntrustedError("runtime decision agent mismatch")
        _assert_receipt_field(body, "action", request.action)
        _assert_receipt_field(body, "resource", request.resource)
        _assert_receipt_field(body, "environment", request.environment)
        _assert_receipt_field(body, "payload_hash", request.payload_hash)
        _assert_receipt_field(body, "client_risk_class", request.risk_class)
        _assert_receipt_field(
            body,
            "client_policy_context_hash",
            request.policy_context_hash,
        )


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeGateUnavailableError(f"{label} unavailable") from exc
    if not isinstance(data, dict):
        raise RuntimeGateUnavailableError(f"{label} invalid")
    return data


def _runtime_field(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    return "redacted"


def _required_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeGateUnavailableError(f"{label} unavailable")
    return value


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _assert_receipt_field(body: Mapping[str, Any], field: str, expected: str) -> None:
    actual = body.get(field)
    if actual is not None and actual != expected:
        raise RuntimeGateUntrustedError(f"runtime decision {field} mismatch")


__all__ = [
    "DECISION_ALLOW",
    "DECISION_BLOCK",
    "DECISION_WAITING",
    "DEFAULT_RUNTIME_GATE_TIMEOUT_SECONDS",
    "DEFAULT_RUNTIME_ENVIRONMENT",
    "RuntimeGateClient",
    "RuntimeGateDecision",
    "RuntimeGateError",
    "RuntimeGateUnavailableError",
    "RuntimeGateUntrustedError",
]
