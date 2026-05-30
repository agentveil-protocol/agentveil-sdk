"""Approval orchestration for MCP Proxy risky tool calls."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
import sys
import threading
import time
from typing import Any, Callable, TextIO
import uuid
import webbrowser

from agentveil_mcp_proxy.approval.headless import HeadlessPolicy
from agentveil_mcp_proxy.approval.notification import ApprovalNotifier
from agentveil_mcp_proxy.approval.server import ApprovalPrompt, ApprovalServer
from agentveil_mcp_proxy.classification import ClassifiedToolCall, sha256_jcs
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceError,
    ApprovalEvidenceStore,
    ApprovalEvidenceTransitionError,
    ApprovalStatus,
    PendingApproval,
)
from agentveil_mcp_proxy.policy import PolicyRule, ProxyConfig, RiskClass, TimeoutAction
from agentveil_mcp_proxy.runtime_gate import DEFAULT_RUNTIME_ENVIRONMENT, RuntimeGateDecision


APPROVAL_SCOPE_EXACT = "exact"
APPROVAL_SCOPE_SIMILAR_5M = "similar_5m"


class ApprovalFlowError(RuntimeError):
    """Raised when approval flow setup fails before UI render."""


@dataclass(frozen=True)
class ApprovalOutcome:
    """Outcome returned to the passthrough layer."""

    request_id: str
    status: str
    reason: str
    approval_scope: str = APPROVAL_SCOPE_EXACT
    approval_url: str | None = None

    @property
    def approved(self) -> bool:
        return self.status == ApprovalStatus.APPROVED.value


class ApprovalManager:
    """Persist, notify, and resolve one approval-required tool call."""

    def __init__(
        self,
        *,
        evidence_store: ApprovalEvidenceStore,
        approval_server: ApprovalServer,
        config: ProxyConfig,
        client_id: str,
        session_id: str | None = None,
        environment: str = DEFAULT_RUNTIME_ENVIRONMENT,
        headless: bool = False,
        auto_deny: bool = False,
        headless_policy: HeadlessPolicy | None = None,
        cli_out: TextIO | None = None,
        browser_open: Callable[[str], bool] | None = None,
        notifier: ApprovalNotifier | None = None,
        wait_for_decision: bool = True,
    ):
        self.evidence_store = evidence_store
        self.approval_server = approval_server
        self.config = config
        self.client_id = client_id
        self.session_id = session_id or secrets.token_urlsafe(16)
        self.environment = environment
        self.headless = headless
        self.auto_deny = auto_deny
        self.headless_policy = headless_policy
        self.cli_out = cli_out or sys.stderr
        self.browser_open = browser_open or webbrowser.open
        self.notifier = notifier or ApprovalNotifier()
        self.wait_for_decision = wait_for_decision

    def request_approval(
        self,
        classification: ClassifiedToolCall,
        *,
        runtime_decision: RuntimeGateDecision | None = None,
        reason: str,
    ) -> ApprovalOutcome:
        """Persist pending approval, notify the user, and await a bounded decision."""

        now = int(time.time())
        timeout = self.config.approval.approval_timeout_seconds
        prompt_expires_at = now + timeout
        record_expires_at = (
            None
            if self.config.approval.on_timeout is TimeoutAction.HANG
            else prompt_expires_at
        )
        request_id = str(uuid.uuid4())
        scope_allowed = self._scope_expansion_allowed(classification)
        active_exact_grant = self.evidence_store.find_active_exact_grant(
            downstream_server=classification.server,
            tool_name=classification.tool,
            policy_rule_id=classification.policy_evaluation.policy_rule_id,
            risk_class=classification.risk_class.value,
            resource_hash=classification.resource_hash,
            payload_hash=classification.payload_hash,
            now_timestamp=now,
        )
        active_similar_grant = None
        if active_exact_grant is None and scope_allowed:
            active_similar_grant = self.evidence_store.find_active_similar_grant(
                downstream_server=classification.server,
                tool_name=classification.tool,
                policy_rule_id=classification.policy_evaluation.policy_rule_id,
                risk_class=classification.risk_class.value,
                resource_hash=classification.resource_hash,
                now_timestamp=now,
            )
        active_grant = active_exact_grant or active_similar_grant
        prompt = self._prompt_for(
            classification,
            request_id=request_id,
            created_at=now,
            expires_at=prompt_expires_at,
            scope_expansion_allowed=scope_allowed,
        )
        record = self._pending_record(
            classification,
            request_id=request_id,
            created_at=now,
            expires_at=record_expires_at,
            runtime_decision=None if active_grant is not None else runtime_decision,
            approval_token_hash=self.approval_server.token_hash,
            granted_by_request_id=(
                None if active_grant is None else active_grant.request_id
            ),
        )
        try:
            self.evidence_store.write_pending(record)
        except ApprovalEvidenceError as exc:
            raise ApprovalFlowError("approval evidence persistence failed") from exc

        if active_grant is not None:
            return self._approve(request_id, APPROVAL_SCOPE_EXACT, now, "scope_cache_hit")

        if self.auto_deny:
            return self._deny(request_id, "headless_auto_deny")

        if self.headless:
            match = None if self.headless_policy is None else self.headless_policy.match(
                classification,
                environment=self.environment,
                now_timestamp=now,
            )
            if match is None:
                return self._deny(request_id, "headless_policy_no_match")
            return self._approve(request_id, APPROVAL_SCOPE_EXACT, now, "headless_policy_match")

        url = self.approval_server.register(prompt)
        self._notify(prompt, url)
        if not self.wait_for_decision:
            self._watch_decision_in_background(request_id, timeout)
            return ApprovalOutcome(
                request_id,
                ApprovalStatus.PENDING.value,
                reason,
                approval_url=url,
            )
        return self._await_decision(request_id, timeout)

    def _watch_decision_in_background(self, request_id: str, timeout: int) -> None:
        """Persist the eventual local approval decision without blocking MCP stdio."""

        def worker() -> None:
            try:
                self._await_decision(request_id, timeout)
            except Exception:
                # The MCP response has already returned. Evidence best-effort
                # failure here must not crash the proxy process.
                return

        thread = threading.Thread(
            target=worker,
            name=f"agentveil-mcp-proxy-approval-watch-{request_id[:8]}",
            daemon=True,
        )
        thread.start()

    def _await_decision(self, request_id: str, timeout: int) -> ApprovalOutcome:
        """Wait for a local approval decision and persist the resulting state."""

        decision = None
        while decision is None:
            decision = self.approval_server.wait_for_decision(
                request_id,
                timeout=min(float(timeout), 60.0),
            )
            if decision is not None:
                break
            if self.config.approval.on_timeout is TimeoutAction.HANG:
                continue
            try:
                self.evidence_store.transition(
                    request_id,
                    ApprovalStatus.EXPIRED.value,
                    error_class="approval_timeout",
                )
            except ApprovalEvidenceTransitionError:
                pass
            self.approval_server.unregister(request_id)
            return ApprovalOutcome(request_id, ApprovalStatus.EXPIRED.value, "approval_timeout")
        if decision.decision == "approve":
            return self._approve(
                request_id,
                decision.approval_scope,
                int(time.time()),
                "user_approved",
            )
        return self._deny(request_id, "user_denied")

    def record_runtime_allow(
        self,
        classification: ClassifiedToolCall,
        *,
        runtime_decision: RuntimeGateDecision,
    ) -> ApprovalOutcome:
        """Persist a verified Runtime Gate ALLOW decision before forwarding."""

        request_id = self._write_runtime_decision_record(
            classification,
            runtime_decision=runtime_decision,
        )
        return ApprovalOutcome(
            request_id,
            ApprovalStatus.APPROVED.value,
            "runtime_gate_allow",
        )

    def record_runtime_block(
        self,
        classification: ClassifiedToolCall,
        *,
        runtime_decision: RuntimeGateDecision,
    ) -> None:
        """Persist a verified Runtime Gate BLOCK decision as terminal evidence."""

        request_id = self._write_runtime_decision_record(
            classification,
            runtime_decision=runtime_decision,
        )
        try:
            self.evidence_store.transition(
                request_id,
                ApprovalStatus.BLOCKED.value,
                error_class="runtime_gate_block",
            )
        except ApprovalEvidenceError as exc:
            raise ApprovalFlowError("runtime decision evidence persistence failed") from exc

    def record_execution_result(self, outcome: ApprovalOutcome, response: dict[str, Any]) -> None:
        """Append execution result evidence for an approved downstream call."""

        if not outcome.approved:
            return
        try:
            if "error" in response:
                self.evidence_store.transition(
                    outcome.request_id,
                    ApprovalStatus.BLOCKED.value,
                    result_status="blocked",
                    result_hash=sha256_jcs(response.get("error", {})),
                    error_class="downstream_error",
                )
            else:
                self.evidence_store.transition(
                    outcome.request_id,
                    ApprovalStatus.EXECUTED.value,
                    result_status="executed",
                    result_hash=sha256_jcs(response.get("result", {})),
                )
        except ApprovalEvidenceError:
            return

    def record_execution_error(self, outcome: ApprovalOutcome, error_class: str) -> None:
        """Append sanitized error evidence for an approved call that did not complete."""

        if not outcome.approved:
            return
        try:
            self.evidence_store.transition(
                outcome.request_id,
                ApprovalStatus.ERROR.value,
                result_status="error",
                error_class=error_class,
            )
        except ApprovalEvidenceError:
            return

    def _approve(
        self,
        request_id: str,
        approval_scope: str,
        decided_at: int,
        reason: str,
    ) -> ApprovalOutcome:
        granted_expires = decided_at + 300 if approval_scope == APPROVAL_SCOPE_SIMILAR_5M else None
        self.evidence_store.transition(
            request_id,
            ApprovalStatus.APPROVED.value,
            approval_token_hash=self.approval_server.token_hash,
            approval_decided_by="local-user",
            approval_scope=approval_scope,
            granted_scope_expires_at=granted_expires,
            user_decision_timestamp=decided_at,
        )
        self.approval_server.unregister(request_id)
        return ApprovalOutcome(request_id, ApprovalStatus.APPROVED.value, reason, approval_scope)

    def _deny(self, request_id: str, reason: str) -> ApprovalOutcome:
        now = int(time.time())
        self.evidence_store.transition(
            request_id,
            ApprovalStatus.DENIED.value,
            approval_token_hash=self.approval_server.token_hash,
            approval_decided_by="local-user",
            approval_scope=APPROVAL_SCOPE_EXACT,
            user_decision_timestamp=now,
            error_class=reason,
        )
        self.approval_server.unregister(request_id)
        return ApprovalOutcome(request_id, ApprovalStatus.DENIED.value, reason)

    def _notify(self, prompt: ApprovalPrompt, url: str) -> None:
        summary = (
            f"approval pending: {prompt.client_id} session {prompt.session_id[:8]} "
            f"{prompt.downstream_server}.{prompt.tool_name} {prompt.risk_class}"
        )
        if getattr(self.cli_out, "isatty", lambda: False)():
            print(f"{summary}: {url}", file=self.cli_out)
        else:
            print(
                f"{summary}: approval server bound to {self.approval_server.port}; check via 'doctor'",
                file=self.cli_out,
            )
        try:
            self.browser_open(url)
        except Exception:
            pass
        self.notifier.notify(prompt)

    def _pending_record(
        self,
        classification: ClassifiedToolCall,
        *,
        request_id: str,
        created_at: int,
        expires_at: int | None,
        runtime_decision: RuntimeGateDecision | None,
        approval_token_hash: str | None = None,
        granted_by_request_id: str | None = None,
    ) -> PendingApproval:
        return PendingApproval(
            request_id=request_id,
            session_id=self.session_id,
            client_id=self.client_id,
            downstream_server=classification.server,
            tool_name=classification.tool,
            action_class=classification.risk_class.value,
            risk_class=classification.risk_class.value,
            resource_hash=classification.resource_hash,
            payload_hash=classification.payload_hash,
            policy_id=classification.policy_evaluation.policy_id,
            policy_rule_id=classification.policy_evaluation.policy_rule_id,
            policy_context_hash=classification.policy_evaluation.policy_context_hash,
            status=ApprovalStatus.PENDING.value,
            created_at=created_at,
            expires_at=expires_at,
            decision_audit_id=None if runtime_decision is None else runtime_decision.audit_id,
            decision_receipt_sha256=None if runtime_decision is None else runtime_decision.receipt_digest,
            approval_token_hash=approval_token_hash,
            matched_policy_rule=classification.policy_evaluation.policy_rule_id,
            granted_by_request_id=granted_by_request_id,
        )

    def _write_runtime_decision_record(
        self,
        classification: ClassifiedToolCall,
        *,
        runtime_decision: RuntimeGateDecision,
    ) -> str:
        now = int(time.time())
        request_id = str(uuid.uuid4())
        record = self._pending_record(
            classification,
            request_id=request_id,
            created_at=now,
            expires_at=None,
            runtime_decision=runtime_decision,
        )
        try:
            self.evidence_store.write_pending(record)
        except ApprovalEvidenceError as exc:
            raise ApprovalFlowError("runtime decision evidence persistence failed") from exc
        return request_id

    def _prompt_for(
        self,
        classification: ClassifiedToolCall,
        *,
        request_id: str,
        created_at: int,
        expires_at: int,
        scope_expansion_allowed: bool,
    ) -> ApprovalPrompt:
        action_details = None
        resource_details = None
        privacy = self.config.privacy
        if privacy.show_details_in_approval_ui and privacy.action == "plain":
            action_details = classification.action_plain
        if privacy.show_details_in_approval_ui and privacy.resource == "plain":
            resource_details = classification.resource_plain
        return ApprovalPrompt(
            request_id=request_id,
            client_id=self.client_id,
            session_id=self.session_id,
            downstream_server=classification.server,
            tool_name=classification.tool,
            action_display=classification.action,
            action_details=action_details,
            resource_display=classification.resource,
            resource_details=resource_details,
            risk_class=classification.risk_class.value,
            payload_hash=classification.payload_hash,
            policy_rule_id=classification.policy_evaluation.policy_rule_id,
            created_at=created_at,
            expires_at=expires_at,
            csrf_token=secrets.token_urlsafe(24),
            scope_expansion_allowed=scope_expansion_allowed,
        )

    def _scope_expansion_allowed(self, classification: ClassifiedToolCall) -> bool:
        if classification.risk_class is not RiskClass.WRITE:
            return False
        if classification.resource_hash is None:
            # Without a resource binding a similar_5m grant cannot constrain the
            # target (payload is intentionally unbound), so it must be neither
            # offered nor reused -- require a fresh approval instead.
            return False
        rule = self._matched_policy_rule(classification.policy_evaluation.policy_rule_id)
        return rule is not None and rule.approval_scope_expansion == APPROVAL_SCOPE_SIMILAR_5M

    def _matched_policy_rule(self, rule_id: str) -> PolicyRule | None:
        for rule in self.config.policy.rules:
            if rule.id == rule_id:
                return rule
        return None


__all__ = [
    "APPROVAL_SCOPE_EXACT",
    "APPROVAL_SCOPE_SIMILAR_5M",
    "ApprovalFlowError",
    "ApprovalManager",
    "ApprovalOutcome",
]
