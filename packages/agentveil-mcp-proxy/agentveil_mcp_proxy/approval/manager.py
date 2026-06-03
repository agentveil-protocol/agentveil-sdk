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
from agentveil_mcp_proxy.approval.server import (
    ApprovalPrompt,
    ApprovalServer,
    ApprovalServerDecision,
    TERMINAL_ALREADY_DECIDED_APPROVE,
    TERMINAL_ALREADY_DECIDED_DENY,
    TERMINAL_APPROVAL_EXPIRED,
)
from agentveil_mcp_proxy.classification import ClassifiedToolCall, sha256_jcs
from agentveil_mcp_proxy.evidence import (
    ApprovalEvidenceError,
    ApprovalEvidenceStore,
    ApprovalEvidenceTransitionError,
    ApprovalStatus,
    PendingApproval,
)
from agentveil_mcp_proxy.evidence.approval_grant import (
    APPROVAL_GRANT_SCHEMA,
    ApprovalGrantError,
    build_approval_grant,
)
from agentveil_mcp_proxy.policy import (
    ApprovalUiOpenMode,
    PolicyRule,
    ProxyConfig,
    RiskClass,
    TimeoutAction,
)
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
        approval_grant_private_key_seed: bytes | None = None,
        approval_grant_agent_did: str | None = None,
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
        self.approval_grant_private_key_seed = approval_grant_private_key_seed
        self.approval_grant_agent_did = approval_grant_agent_did
        self.approval_grant_mint_failures = 0
        self._finalize_lock = threading.Lock()
        self._approval_ui_browser_opened = False
        self.approval_server.set_decision_handler(self._persist_server_decision)

    def request_approval(
        self,
        classification: ClassifiedToolCall,
        *,
        runtime_decision: RuntimeGateDecision | None = None,
        reason: str,
    ) -> ApprovalOutcome:
        """Persist pending approval, notify the user, and await a bounded decision."""

        now = int(time.time())
        self._materialize_server_decisions(classification, now)
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
            policy_context_hash=classification.policy_evaluation.policy_context_hash,
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
                policy_context_hash=classification.policy_evaluation.policy_context_hash,
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
            reason=reason,
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
            return self._approve(
                request_id,
                APPROVAL_SCOPE_EXACT,
                now,
                "scope_cache_hit",
                decided_by="scope-cache-hit",
            )

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
            return self._approve(
                request_id,
                APPROVAL_SCOPE_EXACT,
                now,
                "headless_policy_match",
                decided_by="headless-policy",
            )

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
        """Wait for a local approval decision and persist the resulting state.

        The blocking wait is sliced into bounded (<=60s) polls for
        responsiveness, but the overall wait honors the full configured
        ``approval_timeout_seconds`` deadline. A non-HANG timeout only expires
        the pending record once that real deadline elapses -- a slow (>60s)
        human approval must not be expired after the first poll slice, otherwise
        the later approval may fail to make the record reusable and the client
        retry opens a fresh pending approval (the approval retry loop).
        """

        deadline = time.monotonic() + float(timeout)
        while True:
            if self.config.approval.on_timeout is TimeoutAction.HANG:
                slice_timeout = 60.0
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    try:
                        self.evidence_store.transition(
                            request_id,
                            ApprovalStatus.EXPIRED.value,
                            error_class="approval_timeout",
                        )
                    except ApprovalEvidenceTransitionError:
                        pass
                    self.approval_server.unregister(
                        request_id,
                        terminal_state=TERMINAL_APPROVAL_EXPIRED,
                    )
                    return ApprovalOutcome(
                        request_id, ApprovalStatus.EXPIRED.value, "approval_timeout"
                    )
                slice_timeout = min(remaining, 60.0)
            decision = self.approval_server.wait_for_decision(
                request_id,
                timeout=slice_timeout,
            )
            terminal = self._outcome_if_terminal_evidence(request_id)
            if terminal is not None:
                return terminal
            if decision is not None:
                if decision.decision == "approve":
                    return self._approve(
                        request_id,
                        decision.approval_scope,
                        int(time.time()),
                        "user_approved",
                    )
                return self._deny(request_id, "user_denied")

    def _outcome_if_terminal_evidence(self, request_id: str) -> ApprovalOutcome | None:
        """Return an outcome when evidence is already terminal.

        The sync POST handler may persist APPROVED/DENIED and unregister the
        prompt before this waiter reads ``_decisions``, so ``wait_for_decision``
        can return ``None`` even though the decision is final in the store.
        """

        record = self.evidence_store.get_pending(request_id)
        if record is None:
            return None
        if record.status == ApprovalStatus.APPROVED.value:
            scope = record.approval_scope or APPROVAL_SCOPE_EXACT
            return ApprovalOutcome(
                request_id,
                ApprovalStatus.APPROVED.value,
                "user_approved",
                scope,
            )
        if record.status == ApprovalStatus.DENIED.value:
            return ApprovalOutcome(request_id, ApprovalStatus.DENIED.value, "user_denied")
        return None

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
                result_hash = sha256_jcs(response.get("result", {}))
                updated = self.evidence_store.transition(
                    outcome.request_id,
                    ApprovalStatus.EXECUTED.value,
                    result_status="executed",
                    result_hash=result_hash,
                )
                parent_request_id = updated.granted_by_request_id
                if parent_request_id is not None:
                    self.evidence_store.annotate_linked_execution(
                        parent_request_id,
                        result_status=ApprovalStatus.EXECUTED.value,
                        result_hash=result_hash,
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

    def _persist_server_decision(self, decision: ApprovalServerDecision) -> None:
        """Persist evidence as soon as the approval UI POST is accepted."""

        record = self.evidence_store.get_pending(decision.request_id)
        if record is None or record.status != ApprovalStatus.PENDING.value:
            return
        now = int(time.time())
        try:
            if decision.decision == "approve":
                self._approve(
                    decision.request_id,
                    decision.approval_scope,
                    now,
                    "user_approved",
                )
            else:
                self._deny(decision.request_id, "user_denied")
        except Exception:
            # Best-effort: the background watcher can still finalize later.
            return

    def _materialize_server_decisions(
        self,
        classification: ClassifiedToolCall,
        now: int,
    ) -> None:
        """Flush in-memory approve/deny decisions before grant lookup.

        Covers immediate client retries that land before the POST handler
        callback or background watcher has finished writing evidence.
        """

        for request_id in self.approval_server.list_decided_request_ids():
            record = self.evidence_store.get_pending(request_id)
            if record is None or record.status != ApprovalStatus.PENDING.value:
                continue
            if not self._record_matches_classification(record, classification):
                continue
            decision = self.approval_server.get_decision(request_id)
            if decision is None:
                continue
            try:
                if decision.decision == "approve":
                    self._approve(
                        request_id,
                        decision.approval_scope,
                        now,
                        "user_approved",
                    )
                else:
                    self._deny(request_id, "user_denied")
            except Exception:
                continue

    @staticmethod
    def _record_matches_classification(
        record: PendingApproval,
        classification: ClassifiedToolCall,
    ) -> bool:
        evaluation = classification.policy_evaluation
        return (
            record.downstream_server == classification.server
            and record.tool_name == classification.tool
            and record.risk_class == classification.risk_class.value
            and record.policy_rule_id == evaluation.policy_rule_id
            and record.policy_context_hash == evaluation.policy_context_hash
            and record.resource_hash == classification.resource_hash
            and record.payload_hash == classification.payload_hash
        )

    def _approve(
        self,
        request_id: str,
        approval_scope: str,
        decided_at: int,
        reason: str,
        *,
        decided_by: str = "local-user",
    ) -> ApprovalOutcome:
        with self._finalize_lock:
            granted_expires = decided_at + 300 if approval_scope == APPROVAL_SCOPE_SIMILAR_5M else None
            current = self.evidence_store.get_pending(request_id)
            if current is None:
                raise ApprovalFlowError("approval evidence persistence failed")
            if current.status == ApprovalStatus.APPROVED.value:
                scope = current.approval_scope or approval_scope
                self.approval_server.unregister(
                    request_id,
                    terminal_state=TERMINAL_ALREADY_DECIDED_APPROVE,
                )
                return ApprovalOutcome(
                    request_id,
                    ApprovalStatus.APPROVED.value,
                    reason,
                    scope,
                )
            approval_grant_jcs = self._approval_grant_jcs(
                current,
                approval_scope=approval_scope,
                decided_at=decided_at,
                decided_by=decided_by,
                granted_expires_at=granted_expires,
            )
            self.evidence_store.transition(
                request_id,
                ApprovalStatus.APPROVED.value,
                approval_token_hash=self.approval_server.token_hash,
                approval_decided_by=decided_by,
                approval_scope=approval_scope,
                granted_scope_expires_at=granted_expires,
                user_decision_timestamp=decided_at,
                approval_grant_jcs=approval_grant_jcs,
            )
            self.approval_server.unregister(
                request_id,
                terminal_state=TERMINAL_ALREADY_DECIDED_APPROVE,
            )
            return ApprovalOutcome(
                request_id, ApprovalStatus.APPROVED.value, reason, approval_scope
            )

    def _approval_grant_jcs(
        self,
        record: PendingApproval,
        *,
        approval_scope: str,
        decided_at: int,
        decided_by: str,
        granted_expires_at: int | None,
    ) -> str | None:
        if self.approval_grant_private_key_seed is None or not self.approval_grant_agent_did:
            return None
        expires_at = (
            granted_expires_at if approval_scope == APPROVAL_SCOPE_SIMILAR_5M else record.expires_at
        )
        if expires_at is None:
            return None
        body = {
            "schema_version": APPROVAL_GRANT_SCHEMA,
            "agent_did": self.approval_grant_agent_did,
            "request_id": record.request_id,
            "downstream_server": record.downstream_server,
            "tool_name": record.tool_name,
            "action_class": record.action_class,
            "risk_class": record.risk_class,
            "resource_hash": record.resource_hash,
            "payload_hash": None
            if approval_scope == APPROVAL_SCOPE_SIMILAR_5M
            else record.payload_hash,
            "policy_id": record.policy_id,
            "policy_rule_id": record.policy_rule_id,
            "policy_context_hash": record.policy_context_hash,
            "decision": "APPROVED",
            "approval_scope": approval_scope,
            "decided_by": decided_by,
            "issued_at": decided_at,
            "expires_at": expires_at,
            "decision_audit_id": record.decision_audit_id,
            "decision_receipt_sha256": record.decision_receipt_sha256,
            "granted_by_request_id": record.granted_by_request_id,
        }
        try:
            return build_approval_grant(body, self.approval_grant_private_key_seed)
        except ApprovalGrantError as exc:
            # Boundary: leave approval_grant_jcs unset on mint errors, while the
            # approval record still transitions. Signer + expiry were present, so
            # this path is a systematic mint problem -- emit a sanitized signal
            # with request_id + error class only.
            self.approval_grant_mint_failures += 1
            print(
                f"approval grant mint failed for {record.request_id}: {type(exc).__name__}",
                file=self.cli_out,
            )
            return None

    def _deny(self, request_id: str, reason: str) -> ApprovalOutcome:
        with self._finalize_lock:
            current = self.evidence_store.get_pending(request_id)
            if current is not None and current.status == ApprovalStatus.DENIED.value:
                self.approval_server.unregister(
                    request_id,
                    terminal_state=TERMINAL_ALREADY_DECIDED_DENY,
                )
                return ApprovalOutcome(request_id, ApprovalStatus.DENIED.value, reason)
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
            self.approval_server.unregister(
                request_id,
                terminal_state=TERMINAL_ALREADY_DECIDED_DENY,
            )
            return ApprovalOutcome(request_id, ApprovalStatus.DENIED.value, reason)

    def _effective_ui_open_mode(self) -> ApprovalUiOpenMode:
        """Return the approval UI mode after applying headless overrides."""

        if self.headless:
            return ApprovalUiOpenMode.NONE
        return self.config.approval.ui_open_mode

    def _print_approval_fallback(self, prompt: ApprovalPrompt, url: str, summary: str) -> None:
        """Print an approval URL line without raw payload details."""

        record_hint = f" record_id={prompt.request_id}"
        if getattr(self.cli_out, "isatty", lambda: False)():
            print(f"{summary}{record_hint}: {url}", file=self.cli_out)
            return
        print(
            f"{summary}{record_hint}: approval center "
            f"http://{self.approval_server.host}:{self.approval_server.port}/approval/ "
            f"(session token omitted on non-TTY output)",
            file=self.cli_out,
        )

    def _maybe_open_approval_browser(self) -> None:
        """Open the approval center in the browser at most once per manager lifetime."""

        if self._effective_ui_open_mode() is not ApprovalUiOpenMode.BROWSER:
            return
        if self._approval_ui_browser_opened:
            return
        try:
            self.browser_open(self.approval_server.approval_center_url())
        except Exception:
            pass
        self._approval_ui_browser_opened = True

    def _notify(self, prompt: ApprovalPrompt, url: str) -> None:
        summary = (
            f"approval pending: {prompt.client_id} session {prompt.session_id[:8]} "
            f"{prompt.downstream_server}.{prompt.tool_name} {prompt.risk_class}"
        )
        self._print_approval_fallback(prompt, url, summary)
        self._maybe_open_approval_browser()
        if self._effective_ui_open_mode() is not ApprovalUiOpenMode.NONE:
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
        reason: str,
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
            reason=reason,
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
