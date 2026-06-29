"""Loopback approval server for the MCP Proxy approval surface."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
import hashlib
import json
import hmac
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs

from agentveil_mcp_proxy.evidence.events_show import (
    LOCAL_PROOF_BLOCK_TITLE,
    LOCAL_PROOF_INSPECTION_COMMAND,
    LOCAL_PROOF_PENDING_QUIET_LINE,
    LOCAL_PROOF_POST_APPROVE_BODY,
    LOCAL_PROOF_POST_DENY_BODY,
)
from agentveil_mcp_proxy.evidence.observability import (
    approval_proof_detail_rows,
    approval_raw_evidence_rows,
    bounded_action_display,
    bounded_reason_for_record,
    bounded_resource_display,
    human_approval_reason_label,
    human_approval_summary,
    pending_approval_dict,
    risk_class_plain_label,
    terminal_state_for_record_status,
)


MAX_POST_BODY_BYTES = 8192
REQUEST_SOCKET_TIMEOUT_SECONDS = 5.0
DEFAULT_TERMINAL_REQUEST_RETENTION_SECONDS = 600.0
MIN_TERMINAL_REQUEST_RETENTION_SECONDS = 1.0
SECURITY_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
}
COOKIE_NAME = "avp_approval_session"
INTERNAL_REGISTER_TOKEN_HEADER = "X-AVP-Approval-Register-Token"
APPROVAL_LOCAL_URL_WARNING = (
    "This local approval URL is a bearer-style session URL. Do not share it."
)
APPROVAL_DECISION_RECORDED_BODY = (
    "Decision recorded. Retry the same MCP tool call without changing tool, target, or payload."
)
APPROVAL_DECISION_DENIED_BODY = (
    "Decision recorded. This action was denied and will not run."
)


LOCAL_PROOF_COPY_COMMAND_LABEL = "Copy command"
_LOCAL_PROOF_COMMAND_ELEMENT_ID = "approval-local-proof-command"


def generate_approval_script_nonce() -> str:
    """Return a per-response nonce for Approval Center inline scripts."""

    return secrets.token_urlsafe(16)


def approval_content_security_policy(*, script_nonce: str | None = None) -> str:
    """Build Approval Center CSP, optionally allowing one inline script nonce."""

    script_src = "script-src 'self'"
    if script_nonce:
        script_src = f"script-src 'self' 'nonce-{script_nonce}'"
    return (
        f"default-src 'self'; {script_src}; "
        "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )


def approval_security_headers(*, script_nonce: str | None = None) -> dict[str, str]:
    """Return security headers for one Approval Center response."""

    headers = dict(SECURITY_HEADERS)
    headers["Content-Security-Policy"] = approval_content_security_policy(
        script_nonce=script_nonce,
    )
    return headers


def _local_proof_copy_script(script_nonce: str) -> str:
    return (
        f'<script nonce="{escape(script_nonce)}">\n'
        "(function () {\n"
        '  document.querySelectorAll(".approval-copy-command").forEach(function (button) {\n'
        '    button.addEventListener("click", function () {\n'
        '      var target = document.getElementById(button.getAttribute("data-copy-target"));\n'
        "      if (!target) { return; }\n"
        '      var text = target.textContent || "";\n'
        "      if (navigator.clipboard && navigator.clipboard.writeText) {\n"
        "        navigator.clipboard.writeText(text).then(function () {\n"
        '          button.textContent = "Copied";\n'
        '          setTimeout(function () { button.textContent = "Copy command"; }, 1500);\n'
        "        }).catch(function () {\n"
        "          var range = document.createRange();\n"
        "          range.selectNodeContents(target);\n"
        "          window.getSelection().removeAllRanges();\n"
        "          window.getSelection().addRange(range);\n"
        "        });\n"
        "      } else {\n"
        "        var range = document.createRange();\n"
        "        range.selectNodeContents(target);\n"
        "        window.getSelection().removeAllRanges();\n"
        "        window.getSelection().addRange(range);\n"
        "      }\n"
        "    });\n"
        "  });\n"
        "})();\n"
        "</script>"
    )


def render_local_proof_block(body_text: str, *, script_nonce: str) -> str:
    """Return a compact Approval Center block for local proof inspection."""

    return (
        '<section class="approval-local-proof">'
        f'<h2 class="approval-local-proof-title">{escape(LOCAL_PROOF_BLOCK_TITLE)}</h2>'
        f'<p class="approval-local-proof-body">{escape(body_text)}</p>'
        '<div class="approval-local-proof-command-row">'
        f'<code class="approval-local-proof-command" id="{_LOCAL_PROOF_COMMAND_ELEMENT_ID}">'
        f"{escape(LOCAL_PROOF_INSPECTION_COMMAND)}</code>"
        f'<button type="button" class="approval-copy-command" '
        f'data-copy-target="{_LOCAL_PROOF_COMMAND_ELEMENT_ID}">'
        f"{escape(LOCAL_PROOF_COPY_COMMAND_LABEL)}</button>"
        "</div>"
        f"{_local_proof_copy_script(script_nonce)}"
        "</section>"
    )

TERMINAL_ALREADY_DECIDED_APPROVE = "already_decided_approve"
TERMINAL_ALREADY_DECIDED_DENY = "already_decided_deny"
TERMINAL_APPROVAL_EXPIRED = "approval_expired"
TERMINAL_ALREADY_DECIDED = "already_decided"


class _DaemonThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


class ApprovalServerError(RuntimeError):
    """Raised when the local approval server cannot operate safely."""


class ApprovalServerGone(ApprovalServerError):
    """Raised when a submitted approval URL is no longer actionable."""


@dataclass(frozen=True)
class ApprovalPrompt:
    """Privacy-filtered approval prompt data served by the local UI."""

    request_id: str
    client_id: str
    session_id: str
    downstream_server: str
    tool_name: str
    action_display: str
    action_details: str | None
    resource_display: str | None
    resource_details: str | None
    risk_class: str
    payload_hash: str
    policy_rule_id: str
    reason: str
    created_at: int
    expires_at: int
    csrf_token: str
    action_gate_metadata: dict[str, Any] | None = None
    scope_expansion_allowed: bool = False


@dataclass(frozen=True)
class ApprovalServerDecision:
    """Decision submitted through the local approval server."""

    request_id: str
    decision: str
    approval_scope: str


@dataclass(frozen=True)
class TerminalApprovalSnapshot:
    """Sanitized approval context retained for stale loopback URLs."""

    request_id: str
    state: str
    client_id: str
    session_id_prefix: str
    downstream_server: str
    tool_name: str
    risk_class: str
    reason: str
    action_display: str
    resource_display: str
    policy_rule_id: str
    created_at: int
    expires_at: int

    @classmethod
    def from_prompt(cls, prompt: ApprovalPrompt, *, state: str) -> TerminalApprovalSnapshot:
        return cls(
            request_id=prompt.request_id,
            state=state,
            client_id=prompt.client_id,
            session_id_prefix=prompt.session_id[:8],
            downstream_server=prompt.downstream_server,
            tool_name=prompt.tool_name,
            risk_class=prompt.risk_class,
            reason=prompt.reason,
            action_display=prompt.action_display,
            resource_display=prompt.resource_display or "none",
            policy_rule_id=prompt.policy_rule_id,
            created_at=prompt.created_at,
            expires_at=prompt.expires_at,
        )

    @classmethod
    def from_pending_record(
        cls,
        record: Any,
        *,
        state: str | None = None,
    ) -> TerminalApprovalSnapshot | None:
        """Build a terminal snapshot from one durable evidence record."""

        resolved_state = state or terminal_state_for_record_status(record.status)
        if resolved_state is None:
            return None
        client_id = record.client_id if isinstance(record.client_id, str) and record.client_id else "-"
        session_prefix = record.session_id[:8] if isinstance(record.session_id, str) else "-"
        policy_rule_id = record.policy_rule_id if isinstance(record.policy_rule_id, str) else "-"
        expires_at = record.expires_at if record.expires_at is not None else record.created_at
        return cls(
            request_id=record.request_id,
            state=resolved_state,
            client_id=client_id,
            session_id_prefix=session_prefix,
            downstream_server=record.downstream_server,
            tool_name=record.tool_name,
            risk_class=record.risk_class,
            reason=bounded_reason_for_record(record),
            action_display=bounded_action_display(record),
            resource_display=bounded_resource_display(record),
            policy_rule_id=policy_rule_id,
            created_at=record.created_at,
            expires_at=expires_at,
        )


def approval_prompt_to_dict(prompt: ApprovalPrompt) -> dict[str, Any]:
    """Serialize one approval prompt for the persistent center register API."""

    return {
        "request_id": prompt.request_id,
        "client_id": prompt.client_id,
        "session_id": prompt.session_id,
        "downstream_server": prompt.downstream_server,
        "tool_name": prompt.tool_name,
        "action_display": prompt.action_display,
        "action_details": prompt.action_details,
        "resource_display": prompt.resource_display,
        "resource_details": prompt.resource_details,
        "risk_class": prompt.risk_class,
        "payload_hash": prompt.payload_hash,
        "policy_rule_id": prompt.policy_rule_id,
        "reason": prompt.reason,
        "created_at": prompt.created_at,
        "expires_at": prompt.expires_at,
        "csrf_token": prompt.csrf_token,
        "action_gate_metadata": prompt.action_gate_metadata,
        "scope_expansion_allowed": prompt.scope_expansion_allowed,
    }


def approval_prompt_from_dict(data: Mapping[str, Any]) -> ApprovalPrompt:
    """Deserialize one approval prompt from the persistent center register API."""

    return ApprovalPrompt(
        request_id=str(data["request_id"]),
        client_id=str(data["client_id"]),
        session_id=str(data["session_id"]),
        downstream_server=str(data["downstream_server"]),
        tool_name=str(data["tool_name"]),
        action_display=str(data["action_display"]),
        action_details=data.get("action_details"),
        resource_display=data.get("resource_display"),
        resource_details=data.get("resource_details"),
        risk_class=str(data["risk_class"]),
        payload_hash=str(data["payload_hash"]),
        policy_rule_id=str(data["policy_rule_id"]),
        reason=str(data["reason"]),
        created_at=int(data["created_at"]),
        expires_at=int(data["expires_at"]),
        csrf_token=str(data["csrf_token"]),
        action_gate_metadata=data.get("action_gate_metadata"),
        scope_expansion_allowed=bool(data.get("scope_expansion_allowed", False)),
    )


class ApprovalServer:
    """Authenticated loopback HTTP server for local approval decisions."""

    owns_server_process = True

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        session_token: str | None = None,
        internal_register_token: str | None = None,
        evidence_store: Any = None,
    ):
        if host != "127.0.0.1":
            raise ApprovalServerError("approval server must bind to 127.0.0.1")
        self.host = host
        self.port = port
        self.session_token = session_token or secrets.token_urlsafe(32)
        self.internal_register_token = internal_register_token
        self.evidence_store = evidence_store
        self._hmac_key = secrets.token_bytes(32)
        self._cookie_nonce = secrets.token_urlsafe(16)
        self._lock = threading.RLock()
        self._prompts: dict[str, ApprovalPrompt] = {}
        self._decisions: dict[str, ApprovalServerDecision] = {}
        self._decision_events: dict[str, threading.Event] = {}
        self._terminal_requests: dict[str, float] = {}
        self._terminal_snapshots: dict[str, TerminalApprovalSnapshot] = {}
        self._decision_handler: Callable[[ApprovalServerDecision], None] | None = None
        self._httpd: _DaemonThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def set_decision_handler(
        self,
        handler: Callable[[ApprovalServerDecision], None] | None,
    ) -> None:
        """Register a callback invoked after each approve/deny POST is accepted.

        The handler runs outside the server lock so it can persist evidence
        before the HTTP response returns. That closes the live-console race
        where the client retries immediately after POST while the background
        watcher has not yet written APPROVED to the evidence store.
        """

        self._decision_handler = handler

    @property
    def token_hash(self) -> str:
        """Return a stable hash of the current per-process session token."""

        return "sha256:" + hashlib.sha256(self.session_token.encode("utf-8")).hexdigest()

    @property
    def base_url(self) -> str:
        """Return the loopback base URL."""

        if self._httpd is None:
            raise ApprovalServerError("approval server is not started")
        return f"http://{self.host}:{self.port}"

    @property
    def is_running(self) -> bool:
        """Return whether the HTTP server has been started."""

        return self._httpd is not None

    def start(self) -> None:
        """Start the loopback approval server in a background thread."""

        if self._httpd is not None:
            return

        owner = self

        class Handler(_ApprovalRequestHandler):
            server_owner = owner

        self._httpd = _DaemonThreadingHTTPServer((self.host, self.port), Handler)
        self.host, self.port = self._httpd.server_address[:2]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="agentveil-mcp-proxy-approval-server",
            daemon=True,
        )
        self._thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        """Stop the approval server."""

        httpd = self._httpd
        if httpd is None:
            return
        httpd.shutdown()
        httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._httpd = None
        self._thread = None

    def approval_center_url(self) -> str:
        """Return the loopback approval list URL for the current server session."""

        return f"{self.base_url}/approval/{self.session_token}"

    def approval_url(self, request_id: str) -> str:
        """Return the authenticated approval URL for a pending request."""

        return f"{self.base_url}/approval/{self.session_token}/pending/{request_id}"

    def register(self, prompt: ApprovalPrompt) -> str:
        """Register a prompt after durable evidence persistence succeeds."""

        with self._lock:
            self._prune_terminal_requests_locked()
            self._prompts[prompt.request_id] = prompt
            self._decision_events[prompt.request_id] = threading.Event()
            self._terminal_requests.pop(prompt.request_id, None)
            self._terminal_snapshots.pop(prompt.request_id, None)
        return self.approval_url(prompt.request_id)

    def unregister(self, request_id: str, *, terminal_state: str = TERMINAL_ALREADY_DECIDED) -> None:
        """Mark an approval URL as no longer actionable."""

        with self._lock:
            self._prune_terminal_requests_locked()
            prompt = self._prompts.pop(request_id, None)
            decision = self._decisions.pop(request_id, None)
            self._decision_events.pop(request_id, None)
            state = terminal_state
            if prompt is not None and state == TERMINAL_ALREADY_DECIDED and decision is not None:
                if decision.decision == "approve":
                    state = TERMINAL_ALREADY_DECIDED_APPROVE
                elif decision.decision == "deny":
                    state = TERMINAL_ALREADY_DECIDED_DENY
            if prompt is not None:
                self._terminal_snapshots[request_id] = TerminalApprovalSnapshot.from_prompt(
                    prompt,
                    state=state,
                )
            self._terminal_requests[request_id] = self._terminal_retain_until(prompt)

    def list_decided_request_ids(self) -> tuple[str, ...]:
        """Return request IDs with a local approve/deny decision not yet unregistered."""

        with self._lock:
            return tuple(self._decisions.keys())

    def get_decision(self, request_id: str) -> ApprovalServerDecision | None:
        """Return a recorded local decision, if present."""

        with self._lock:
            return self._decisions.get(request_id)

    def wait_for_decision(self, request_id: str, *, timeout: float) -> ApprovalServerDecision | None:
        """Wait for an approve/deny POST for one request."""

        with self._lock:
            event = self._decision_events.get(request_id)
        if event is None:
            return None
        if not event.wait(timeout=timeout):
            return None
        with self._lock:
            return self._decisions.get(request_id)

    def pending_row_dict(self, prompt: ApprovalPrompt) -> dict[str, Any]:
        """Sanitized pending row shared by the dashboard HTML and JSON API."""

        return pending_approval_dict(
            request_id=prompt.request_id,
            client_id=prompt.client_id,
            session_id=prompt.session_id,
            downstream_server=prompt.downstream_server,
            tool_name=prompt.tool_name,
            action_display=prompt.action_display,
            resource_display=prompt.resource_display,
            risk_class=prompt.risk_class,
            reason=prompt.reason,
            payload_hash=prompt.payload_hash,
            policy_rule_id=prompt.policy_rule_id,
            created_at=prompt.created_at,
            expires_at=prompt.expires_at,
            action_gate_metadata=prompt.action_gate_metadata,
        )

    def pending_approvals_api_payload(self) -> dict[str, Any]:
        """Return sanitized pending approvals for the loopback JSON API."""

        return {
            "ok": True,
            "approvals": [
                self.pending_row_dict(prompt)
                for prompt in self.pending_prompts()
            ],
        }

    def pending_prompts(self) -> list[ApprovalPrompt]:
        """Return currently pending prompts for the token-authenticated list page."""

        with self._lock:
            self._prune_terminal_requests_locked()
            self._prune_expired_pending_locked()
            decided = set(self._decisions)
            terminal = set(self._terminal_requests)
            return [
                prompt
                for request_id, prompt in sorted(self._prompts.items())
                if request_id not in decided and request_id not in terminal
            ]

    def prompt_for(self, request_id: str) -> ApprovalPrompt | None:
        """Return one pending prompt."""

        with self._lock:
            self._prune_terminal_requests_locked()
            if request_id in self._decisions or request_id in self._terminal_requests:
                return None
            return self._prompts.get(request_id)

    def is_terminal(self, request_id: str) -> bool:
        """Return whether a prompt was already decided or expired."""

        with self._lock:
            self._prune_terminal_requests_locked()
            return request_id in self._terminal_requests or request_id in self._decisions

    def terminal_snapshot_for(self, request_id: str) -> TerminalApprovalSnapshot | None:
        """Return sanitized stale-state context while the terminal retention window is active."""

        with self._lock:
            self._prune_terminal_requests_locked()
            return self._terminal_snapshots.get(request_id)

    def stale_terminal_snapshot_for(self, request_id: str) -> TerminalApprovalSnapshot | None:
        """Return retained or inferred terminal context for a non-actionable request."""

        with self._lock:
            self._prune_terminal_requests_locked()
            snapshot = self._terminal_snapshots.get(request_id)
            if snapshot is not None:
                return snapshot
            decision = self._decisions.get(request_id)
            prompt = self._prompts.get(request_id)
            if decision is not None and prompt is not None:
                state = TERMINAL_ALREADY_DECIDED
                if decision.decision == "approve":
                    state = TERMINAL_ALREADY_DECIDED_APPROVE
                elif decision.decision == "deny":
                    state = TERMINAL_ALREADY_DECIDED_DENY
                return TerminalApprovalSnapshot.from_prompt(prompt, state=state)
        return self._terminal_snapshot_from_evidence(request_id)

    def _terminal_snapshot_from_evidence(self, request_id: str) -> TerminalApprovalSnapshot | None:
        """Load terminal context from durable evidence when in-memory state is gone."""

        store = self.evidence_store
        if store is None:
            return None
        record = store.get_pending(request_id)
        if record is None:
            return None
        return TerminalApprovalSnapshot.from_pending_record(record)

    def submit_decision(self, request_id: str, decision: str, approval_scope: str) -> None:
        """Record a local approve/deny POST."""

        if decision not in {"approve", "deny"}:
            raise ApprovalServerError("approval decision must be approve or deny")
        if approval_scope not in {"exact", "similar_5m"}:
            raise ApprovalServerError("approval scope is unsupported")
        with self._lock:
            self._prune_terminal_requests_locked()
            if request_id in self._terminal_requests or request_id in self._decisions:
                raise ApprovalServerGone("approval already decided")
            prompt = self._prompts.get(request_id)
            if prompt is None:
                raise ApprovalServerError("pending approval not found")
            if approval_scope == "similar_5m" and not prompt.scope_expansion_allowed:
                raise ApprovalServerError("approval scope is not available for this request")
            self._decisions[request_id] = ApprovalServerDecision(
                request_id=request_id,
                decision=decision,
                approval_scope=approval_scope,
            )
            self._decision_events.setdefault(request_id, threading.Event()).set()
            snapshot = self._decisions[request_id]
            handler = self._decision_handler
        if handler is not None:
            handler(snapshot)

    def _cookie_value(self) -> str:
        message = f"{self.session_token}:{self._cookie_nonce}".encode("utf-8")
        return hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()

    def _valid_cookie(self, raw_cookie: str | None) -> bool:
        if not raw_cookie:
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return False
        morsel = cookie.get(COOKIE_NAME)
        if morsel is None:
            return False
        return hmac.compare_digest(morsel.value, self._cookie_value())

    def _valid_internal_register_token(self, raw_token: str | None) -> bool:
        expected = self.internal_register_token
        if not isinstance(expected, str) or not expected:
            return False
        if not isinstance(raw_token, str) or not raw_token:
            return False
        return hmac.compare_digest(raw_token, expected)

    def _terminal_retain_until(self, prompt: ApprovalPrompt | None) -> float:
        now = time.time()
        retention = DEFAULT_TERMINAL_REQUEST_RETENTION_SECONDS
        if prompt is not None:
            retention = max(
                float(prompt.expires_at - prompt.created_at) * 2.0,
                MIN_TERMINAL_REQUEST_RETENTION_SECONDS,
            )
        return now + retention

    def _prune_terminal_requests_locked(self) -> None:
        now = time.time()
        expired = [
            request_id
            for request_id, retain_until in self._terminal_requests.items()
            if retain_until <= now
        ]
        for request_id in expired:
            self._terminal_requests.pop(request_id, None)
            self._terminal_snapshots.pop(request_id, None)

    def _prune_expired_pending_locked(self) -> None:
        """Hide expired pending prompts from the default list without deleting evidence."""

        now = int(time.time())
        expired_ids = [
            request_id
            for request_id, prompt in self._prompts.items()
            if request_id not in self._decisions
            and request_id not in self._terminal_requests
            and now > prompt.expires_at
        ]
        for request_id in expired_ids:
            prompt = self._prompts.pop(request_id, None)
            self._decision_events.pop(request_id, None)
            if prompt is None:
                continue
            self._terminal_snapshots[request_id] = TerminalApprovalSnapshot.from_prompt(
                prompt,
                state=TERMINAL_APPROVAL_EXPIRED,
            )
            self._terminal_requests[request_id] = self._terminal_retain_until(prompt)


class _ApprovalRequestHandler(BaseHTTPRequestHandler):
    server_owner: ApprovalServer

    def setup(self) -> None:
        super().setup()
        self.request.settimeout(REQUEST_SOCKET_TIMEOUT_SECONDS)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:
        token, route, request_id = self._parse_path()
        if not self._token_ok(token):
            if route == "api_list":
                self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            else:
                self._send_html(HTTPStatus.FORBIDDEN, self._render_forbidden_session())
            return
        if route == "api_list":
            self._send_json(HTTPStatus.OK, self.server_owner.pending_approvals_api_payload())
            return
        if route == "list":
            prompts = self.server_owner.pending_prompts()
            if len(prompts) == 1:
                token = self.server_owner.session_token
                location = f"/approval/{token}/pending/{prompts[0].request_id}"
                self._send_redirect(
                    location,
                    extra_headers={"Set-Cookie": self._session_cookie_header()},
                )
                return
            extra_headers = None
            if prompts:
                extra_headers = {"Set-Cookie": self._session_cookie_header()}
            self._send_html(HTTPStatus.OK, self._render_list(), extra_headers=extra_headers)
            return
        if route != "pending" or request_id is None:
            self._send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        self._respond_pending_get(request_id)

    def do_POST(self) -> None:
        token, route, request_id = self._parse_path()
        if route == "internal_register":
            self._handle_internal_register()
            return
        if route == "legacy_internal_register":
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        if route != "pending" or request_id is None or not self._token_ok(token):
            if route == "api_list":
                self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            else:
                self._send_html(HTTPStatus.FORBIDDEN, self._render_forbidden_session())
            return
        prompt = self.server_owner.prompt_for(request_id)
        if prompt is None:
            self._respond_stale_pending(request_id)
            return
        if int(time.time()) > prompt.expires_at:
            snapshot = TerminalApprovalSnapshot.from_prompt(
                prompt,
                state=TERMINAL_APPROVAL_EXPIRED,
            )
            self._send_html(HTTPStatus.GONE, self._render_terminal(snapshot))
            return
        if not self.server_owner._valid_cookie(self.headers.get("Cookie")):
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except ValueError:
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid content length")
            return
        if length < 0 or length > MAX_POST_BODY_BYTES:
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid content length")
            return
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body, keep_blank_values=True)
        csrf = (form.get("csrf_token") or [""])[0]
        if not hmac.compare_digest(csrf, prompt.csrf_token):
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        decision = (form.get("decision") or [""])[0]
        scope = (form.get("approval_scope") or ["exact"])[0]
        try:
            self.server_owner.submit_decision(request_id, decision, scope)
        except ApprovalServerGone:
            self._respond_stale_pending(request_id)
            return
        except ApprovalServerError:
            self._send_html(HTTPStatus.FORBIDDEN, self._render_forbidden_session())
            return
        recorded_body = (
            APPROVAL_DECISION_RECORDED_BODY
            if decision == "approve"
            else APPROVAL_DECISION_DENIED_BODY
        )
        proof_body = (
            LOCAL_PROOF_POST_APPROVE_BODY
            if decision == "approve"
            else LOCAL_PROOF_POST_DENY_BODY
        )
        script_nonce = generate_approval_script_nonce()
        self._send_html(
            HTTPStatus.OK,
            self._page(
                "Approval recorded",
                (
                    f"<p>{escape(recorded_body)}</p>"
                    f"{render_local_proof_block(proof_body, script_nonce=script_nonce)}"
                ),
                page_kind="detail",
                include_card_styles=False,
                include_local_proof_styles=True,
            ),
            script_nonce=script_nonce,
        )

    def _respond_pending_get(self, request_id: str) -> None:
        prompt = self.server_owner.prompt_for(request_id)
        if prompt is not None and int(time.time()) > prompt.expires_at:
            snapshot = TerminalApprovalSnapshot.from_prompt(
                prompt,
                state=TERMINAL_APPROVAL_EXPIRED,
            )
            self._send_html(HTTPStatus.GONE, self._render_terminal(snapshot))
            return
        if prompt is not None:
            self._send_html(
                HTTPStatus.OK,
                self._render_prompt(prompt),
                extra_headers={"Set-Cookie": self._session_cookie_header()},
            )
            return
        self._respond_stale_pending(request_id)

    def _respond_stale_pending(self, request_id: str) -> None:
        snapshot = self.server_owner.stale_terminal_snapshot_for(request_id)
        if snapshot is not None:
            self._send_html(HTTPStatus.GONE, self._render_terminal(snapshot))
            return
        if self.server_owner.is_terminal(request_id):
            self._send_html(
                HTTPStatus.GONE,
                self._render_terminal(
                    TerminalApprovalSnapshot(
                        request_id=request_id,
                        state=TERMINAL_ALREADY_DECIDED,
                        client_id="-",
                        session_id_prefix="-",
                        downstream_server="-",
                        tool_name="-",
                        risk_class="-",
                        reason="-",
                        action_display="-",
                        resource_display="none",
                        policy_rule_id="-",
                        created_at=0,
                        expires_at=0,
                    ),
                ),
            )
            return
        self._send_html(HTTPStatus.NOT_FOUND, self._render_request_not_found(request_id))

    def _parse_path(self) -> tuple[str | None, str | None, str | None]:
        parts = [part for part in self.path.split("?")[0].split("/") if part]
        if len(parts) == 2 and parts[0] == "internal" and parts[1] == "register":
            return None, "internal_register", None
        if len(parts) >= 2 and parts[0] == "approval":
            token = parts[1]
            if len(parts) == 2:
                return token, "list", None
            if len(parts) == 4 and parts[2] == "api" and parts[3] == "approvals":
                return token, "api_list", None
            if len(parts) == 4 and parts[2] == "internal" and parts[3] == "register":
                return token, "legacy_internal_register", None
            if len(parts) == 4 and parts[2] == "pending":
                return token, "pending", parts[3]
        return None, None, None

    def _handle_internal_register(self) -> None:
        if not self.server_owner._valid_internal_register_token(
            self.headers.get(INTERNAL_REGISTER_TOKEN_HEADER),
        ):
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        raw_length = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_length)
        except ValueError:
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid content length")
            return
        if length < 0 or length > MAX_POST_BODY_BYTES:
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid content length")
            return
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid json")
            return
        if not isinstance(payload, dict):
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid json")
            return
        try:
            prompt = approval_prompt_from_dict(payload)
        except (KeyError, TypeError, ValueError):
            self._send_text(HTTPStatus.BAD_REQUEST, "invalid prompt")
            return
        approval_url = self.server_owner.register(prompt)
        self._send_json(
            HTTPStatus.OK,
            {"ok": True, "approval_url": approval_url},
        )

    def _token_ok(self, token: str | None) -> bool:
        return bool(token) and hmac.compare_digest(token or "", self.server_owner.session_token)

    def _session_cookie_header(self) -> str:
        return (
            f"{COOKIE_NAME}={self.server_owner._cookie_value()}; "
            f"Path=/approval/{self.server_owner.session_token}; HttpOnly; SameSite=Strict"
        )

    def _render_forbidden_session(self) -> str:
        return self._page(
            "Forbidden",
            "<p>Invalid approval session URL.</p>",
        )

    def _render_request_not_found(self, request_id: str) -> str:
        body = (
            "<p>This approval request is no longer pending.</p>"
            f"<p class=\"approval-request-id\">request {escape(request_id)}</p>"
            "<p>Open your Approval Center pending list from the original notification link.</p>"
        )
        return self._page("Request no longer pending", body)

    def _terminal_titles(self, state: str) -> tuple[str, str]:
        if state == TERMINAL_APPROVAL_EXPIRED:
            return "Approval expired", "This approval request has expired."
        if state == TERMINAL_ALREADY_DECIDED_APPROVE:
            return "Already decided", "Approved"
        if state == TERMINAL_ALREADY_DECIDED_DENY:
            return "Already decided", "Denied"
        return "Already decided", "This approval request is no longer actionable."

    def _render_terminal(self, snapshot: TerminalApprovalSnapshot) -> str:
        title, subtitle = self._terminal_titles(snapshot.state)
        body = f"""
<p>{escape(subtitle)}</p>
<p class="approval-request-id">request {escape(snapshot.request_id)}</p>
<dl>
<dt>Client</dt><dd>{escape(snapshot.client_id)}</dd>
<dt>Session prefix</dt><dd>{escape(snapshot.session_id_prefix)}</dd>
<dt>Downstream</dt><dd>{escape(snapshot.downstream_server)}</dd>
<dt>Tool</dt><dd>{escape(snapshot.tool_name)}</dd>
<dt>Action</dt><dd>{escape(snapshot.action_display)}</dd>
<dt>Resource</dt><dd>{escape(snapshot.resource_display)}</dd>
<dt>Risk</dt><dd>{escape(snapshot.risk_class)}</dd>
<dt>Reason</dt><dd>{escape(snapshot.reason)}</dd>
<dt>Policy rule</dt><dd>{escape(snapshot.policy_rule_id)}</dd>
<dt>Created</dt><dd>{snapshot.created_at}</dd>
<dt>Expires</dt><dd>{snapshot.expires_at}</dd>
</dl>
<p>Open your Approval Center pending list from the original notification link.</p>
"""
        return self._page(title, body)

    def _render_list(self) -> str:
        prompts = self.server_owner.pending_prompts()
        token = self.server_owner.session_token
        if not prompts:
            body = '<p class="approval-empty">No pending approvals</p>'
        else:
            cards = "".join(
                self._render_dashboard_card(
                    self.server_owner.pending_row_dict(prompt),
                    detail_href=f"/approval/{token}/pending/{prompt.request_id}",
                    csrf_token=prompt.csrf_token,
                )
                for prompt in prompts
            )
            body = f'<section class="approval-cards">{cards}</section>'
        return self._page(
            "Pending approvals",
            body,
            page_kind="dashboard",
            include_card_styles=bool(prompts),
        )

    def _render_dashboard_card(
        self,
        row: dict[str, Any],
        *,
        detail_href: str,
        csrf_token: str,
    ) -> str:
        risk = escape(row["risk_class"])
        risk_label = escape(risk_class_plain_label(str(row["risk_class"])))
        summary = escape(
            human_approval_summary(
                tool_name=str(row["tool_name"]),
                resource_display=str(row.get("resource")),
            )
        )
        reason_label = escape(human_approval_reason_label(str(row.get("reason", ""))))
        decision_form = (
            f'<form method="post" action="{escape(detail_href)}">'
            f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
            '<input type="hidden" name="approval_scope" value="exact">'
            '<button type="submit" name="decision" value="approve">Approve</button>'
            '<button type="submit" name="decision" value="deny">Deny</button>'
            "</form>"
        )
        return (
            '<article class="approval-card">'
            '<header class="approval-card-header">'
            f'<span class="approval-tool">{summary}</span>'
            f'<span class="approval-risk approval-risk-{risk}">{risk_label}</span>'
            "</header>"
            f'<p class="approval-reason">{reason_label}</p>'
            '<dl class="approval-meta">'
            f'<div><dt>Tool</dt><dd class="approval-wrap">{escape(row["tool_name"])}</dd></div>'
            f'<div><dt>Target</dt><dd class="approval-wrap">{escape(row["resource"])}</dd></div>'
            f'<div><dt>Client</dt><dd class="approval-wrap">{escape(row["client_id"])}</dd></div>'
            "</dl>"
            f'<p class="approval-card-actions">'
            f'<a class="approval-button" href="{escape(detail_href)}">Review &amp; decide</a>'
            "</p>"
            f"{decision_form}"
            "</article>"
        )

    def _render_prompt(self, prompt: ApprovalPrompt) -> str:
        token = self.server_owner.session_token
        summary = human_approval_summary(
            tool_name=prompt.tool_name,
            resource_display=prompt.resource_display,
        )
        risk_label = risk_class_plain_label(prompt.risk_class)
        reason_label = human_approval_reason_label(prompt.reason)
        title = f"Review: {prompt.tool_name}"
        back_link = (
            f'<p class="approval-back"><a href="/approval/{escape(token)}">'
            "&larr; Back to pending list</a></p>"
        )
        detail = ""
        if prompt.action_details or prompt.resource_details:
            detail_items = []
            if prompt.action_details:
                detail_items.append(f"<dt>Action detail</dt><dd>{escape(prompt.action_details)}</dd>")
            if prompt.resource_details:
                detail_items.append(f"<dt>Resource detail</dt><dd>{escape(prompt.resource_details)}</dd>")
            detail = (
                "<details><summary>Show local details</summary><dl>"
                + "".join(detail_items)
                + "</dl></details>"
            )
        similar = ""
        if prompt.scope_expansion_allowed:
            similar = (
                "<form method=\"post\">"
                f"<input type=\"hidden\" name=\"csrf_token\" value=\"{escape(prompt.csrf_token)}\">"
                "<input type=\"hidden\" name=\"approval_scope\" value=\"similar_5m\">"
                "<button type=\"submit\" name=\"decision\" value=\"approve\">"
                "Approve similar for 5 minutes</button>"
                "</form>"
            )
        session_prefix = prompt.session_id[:8]
        proof_rows = approval_proof_detail_rows(
            tool_name=prompt.tool_name,
            resource_display=prompt.resource_display,
            risk_class=prompt.risk_class,
            reason=prompt.reason,
            payload_hash=prompt.payload_hash,
            policy_rule_id=prompt.policy_rule_id,
            request_id=prompt.request_id,
            created_at=prompt.created_at,
            expires_at=prompt.expires_at,
            action_gate_metadata=prompt.action_gate_metadata,
        )
        proof_items = "".join(
            f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>"
            for label, value in proof_rows
        )
        raw_rows = approval_raw_evidence_rows(
            client_id=prompt.client_id,
            session_id_prefix=session_prefix,
            action_display=prompt.action_display,
            action_gate_metadata=prompt.action_gate_metadata,
        )
        raw_items = "".join(
            f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>"
            for label, value in raw_rows
        )
        body = f"""
{back_link}
<p class="approval-summary">{escape(summary)}</p>
<p class="approval-reason">{escape(reason_label)}</p>
<dl class="approval-detail">
<dt>Tool</dt><dd>{escape(prompt.tool_name)}</dd>
<dt>Target</dt><dd>{escape(prompt.resource_display or "none")}</dd>
<dt>Risk</dt><dd>{escape(risk_label)}</dd>
</dl>
<form method=\"post\">
<input type=\"hidden\" name=\"csrf_token\" value=\"{escape(prompt.csrf_token)}\">
<input type=\"hidden\" name=\"approval_scope\" value=\"exact\">
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>
<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>
</form>
<p class="approval-decision-note">{escape(LOCAL_PROOF_PENDING_QUIET_LINE)}</p>
{similar}
<details class="approval-proof-details">
<summary>Proof details</summary>
<dl class="approval-detail">
{proof_items}
</dl>
<details class="approval-raw-evidence">
<summary>Raw evidence</summary>
<dl class="approval-detail">
{raw_items}
</dl>
{detail}
</details>
</details>
"""
        return self._page(title, body, page_kind="detail")

    def _security_notice_html(self) -> str:
        return (
            '<p class="approval-security-notice">'
            f"{escape(APPROVAL_LOCAL_URL_WARNING)}"
            "</p>"
        )

    def _approval_page_styles(
        self,
        *,
        include_card_styles: bool = True,
        include_local_proof_styles: bool = False,
    ) -> str:
        card_styles = """
.approval-cards { display: flex; flex-direction: column; gap: 8px; }
.approval-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  background: var(--card-bg);
}
.approval-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 8px;
}
.approval-tool { font-weight: 600; word-break: break-word; color: var(--text); }
.approval-risk {
  flex-shrink: 0;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.02em;
  padding: 2px 6px;
  border-radius: 4px;
  background: var(--badge-bg);
  color: var(--badge-text);
}
.approval-reason {
  margin: 0 0 8px;
  color: var(--muted);
  word-break: break-word;
  overflow-wrap: anywhere;
}
.approval-meta {
  margin: 0 0 8px;
  display: grid;
  gap: 4px 12px;
  grid-template-columns: auto 1fr;
}
.approval-meta div { display: contents; }
.approval-meta dt {
  margin: 0;
  color: var(--label);
  font-size: 11px;
  text-transform: uppercase;
}
.approval-meta dd { margin: 0; color: var(--text-secondary); }
.approval-wrap {
  word-break: break-word;
  overflow-wrap: anywhere;
}
.approval-request-id {
  margin: 0 0 8px;
  font-size: 11px;
  color: var(--label);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  overflow-wrap: anywhere;
}
.approval-card-actions { margin: 0; }
.approval-button {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 6px;
  border: 1px solid var(--button-border);
  background: var(--button-bg);
  color: var(--button-text);
  text-decoration: none;
  font-size: 12px;
  font-weight: 500;
}
.approval-button:hover { background: var(--button-bg-hover); }
""" if include_card_styles else ""
        return f"""
<style>
:root {{
  --bg: #12141a;
  --text: #e8eaed;
  --text-secondary: #d1d5db;
  --muted: #b8bcc4;
  --label: #6b7280;
  --border: #2d333b;
  --card-bg: #1a1d24;
  --badge-bg: #2d333b;
  --badge-text: #c9d1d9;
  --button-bg: #252930;
  --button-bg-hover: #2f3540;
  --button-border: #3d4450;
  --button-text: #e8eaed;
  --link: #8ab4f8;
  --notice-bg: #1a1d24;
  --notice-border: #2d333b;
  --notice-text: #9aa0a6;
}}
@media (prefers-color-scheme: light) {{
  :root {{
    --bg: #f6f7f9;
    --text: #1f2328;
    --text-secondary: #3d444d;
    --muted: #57606a;
    --label: #656d76;
    --border: #d0d7de;
    --card-bg: #ffffff;
    --badge-bg: #eaeef2;
    --badge-text: #24292f;
    --button-bg: #f6f8fa;
    --button-bg-hover: #eaeef2;
    --button-border: #d0d7de;
    --button-text: #24292f;
    --link: #0969da;
    --notice-bg: #f6f8fa;
    --notice-border: #d0d7de;
    --notice-text: #57606a;
  }}
}}
body {{
  margin: 0;
  padding: 16px;
  font: 13px/1.45 system-ui, -apple-system, Segoe UI, sans-serif;
  color: var(--text);
  background: var(--bg);
}}
h1 {{ font-size: 16px; font-weight: 600; margin: 0 0 12px; color: var(--text); }}
.approval-security-notice {{
  margin: 0 0 12px;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--notice-border);
  background: var(--notice-bg);
  color: var(--notice-text);
  font-size: 12px;
  line-height: 1.4;
}}
.approval-empty {{ margin: 0; color: var(--muted); }}
.approval-decision-note {{
  margin: 0 0 12px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.4;
}}
{self._local_proof_block_styles() if include_local_proof_styles else ""}{card_styles}.approval-back {{ margin: 0 0 12px; font-size: 12px; }}
.approval-back a {{ color: var(--link); text-decoration: none; }}
dl {{ margin: 0 0 12px; }}
dt {{ color: var(--label); font-size: 11px; text-transform: uppercase; }}
dd {{ margin: 0 0 8px; color: var(--text-secondary); word-break: break-word; overflow-wrap: anywhere; }}
button {{
  margin-right: 8px;
  padding: 6px 10px;
  border-radius: 6px;
  border: 1px solid var(--button-border);
  background: var(--button-bg);
  color: var(--button-text);
  font-size: 12px;
  cursor: pointer;
}}
details {{ margin: 8px 0 12px; }}
</style>
"""

    @staticmethod
    def _local_proof_block_styles() -> str:
        return """
.approval-local-proof {
  margin: 12px 0;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--card-bg);
}
.approval-local-proof-title {
  margin: 0 0 6px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  color: var(--text);
}
.approval-local-proof-body {
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.4;
}
.approval-local-proof-command {
  display: block;
  flex: 1 1 auto;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-word;
  /* claim-check: allow CSS user-select value, not a product coverage claim. */
  user-select: all;
}
.approval-local-proof-command-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: stretch;
}
.approval-copy-command {
  flex: 0 0 auto;
  align-self: stretch;
}
"""

    def _page(
        self,
        title: str,
        body: str,
        *,
        page_kind: str = "plain",
        include_card_styles: bool = True,
        include_local_proof_styles: bool = False,
    ) -> str:
        styles = (
            self._approval_page_styles(
                include_card_styles=include_card_styles,
                include_local_proof_styles=include_local_proof_styles,
            )
            if page_kind in {"dashboard", "detail"}
            else ""
        )
        notice = (
            self._security_notice_html()
            if page_kind in {"dashboard", "detail"}
            else ""
        )
        return (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            f"<title>{escape(title)}</title>{styles}</head>"
            f"<body>{notice}<h1>{escape(title)}</h1>{body}</body></html>"
        )

    def _send_redirect(
        self,
        location: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(int(HTTPStatus.FOUND))
        for key, value in approval_security_headers().items():
            self.send_header(key, value)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.close_connection = True

    def _send_html(
        self,
        status: HTTPStatus,
        body: str,
        *,
        extra_headers: dict[str, str] | None = None,
        script_nonce: str | None = None,
    ) -> None:
        self._send_bytes(
            status,
            body.encode("utf-8"),
            "text/html; charset=utf-8",
            extra_headers,
            script_nonce=script_nonce,
        )

    def _send_text(self, status: HTTPStatus, body: str) -> None:
        self._send_bytes(status, body.encode("utf-8"), "text/plain; charset=utf-8", None)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        self._send_bytes(
            status,
            json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            "application/json; charset=utf-8",
            None,
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None,
        *,
        script_nonce: str | None = None,
    ) -> None:
        self.send_response(int(status))
        for key, value in approval_security_headers(script_nonce=script_nonce).items():
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True


__all__ = [
    "APPROVAL_DECISION_DENIED_BODY",
    "APPROVAL_DECISION_RECORDED_BODY",
    "APPROVAL_LOCAL_URL_WARNING",
    "INTERNAL_REGISTER_TOKEN_HEADER",
    "ApprovalPrompt",
    "ApprovalServer",
    "ApprovalServerDecision",
    "ApprovalServerError",
    "ApprovalServerGone",
    "SECURITY_HEADERS",
    "approval_content_security_policy",
    "approval_security_headers",
    "generate_approval_script_nonce",
    "render_local_proof_block",
    "TERMINAL_ALREADY_DECIDED",
    "TERMINAL_ALREADY_DECIDED_APPROVE",
    "TERMINAL_ALREADY_DECIDED_DENY",
    "TERMINAL_APPROVAL_EXPIRED",
    "TerminalApprovalSnapshot",
]
