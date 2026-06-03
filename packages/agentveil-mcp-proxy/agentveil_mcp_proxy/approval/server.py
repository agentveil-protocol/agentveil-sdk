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
from typing import Any, Callable
from urllib.parse import parse_qs

from agentveil_mcp_proxy.evidence.observability import pending_approval_dict


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
APPROVAL_LOCAL_URL_WARNING = (
    "This local approval URL is a bearer-style session URL. Do not share it."
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


class ApprovalServer:
    """Authenticated loopback HTTP server for local approval decisions."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0):
        if host != "127.0.0.1":
            raise ApprovalServerError("approval server must bind to 127.0.0.1")
        self.host = host
        self.port = port
        self.session_token = secrets.token_urlsafe(32)
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
            if decision is None or prompt is None:
                return None
            state = TERMINAL_ALREADY_DECIDED
            if decision.decision == "approve":
                state = TERMINAL_ALREADY_DECIDED_APPROVE
            elif decision.decision == "deny":
                state = TERMINAL_ALREADY_DECIDED_DENY
            return TerminalApprovalSnapshot.from_prompt(prompt, state=state)

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
            self._send_html(HTTPStatus.OK, self._render_list())
            return
        if route != "pending" or request_id is None:
            self._send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        self._respond_pending_get(request_id)

    def do_POST(self) -> None:
        token, route, request_id = self._parse_path()
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
        self._send_html(HTTPStatus.OK, self._page("Approval recorded", "<p>Decision recorded.</p>"))

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
        if len(parts) >= 2 and parts[0] == "approval":
            token = parts[1]
            if len(parts) == 2:
                return token, "list", None
            if len(parts) == 4 and parts[2] == "api" and parts[3] == "approvals":
                return token, "api_list", None
            if len(parts) == 4 and parts[2] == "pending":
                return token, "pending", parts[3]
        return None, None, None

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

    def _render_dashboard_card(self, row: dict[str, Any], *, detail_href: str) -> str:
        risk = escape(row["risk_class"])
        return (
            '<article class="approval-card">'
            '<header class="approval-card-header">'
            f'<span class="approval-tool">'
            f'{escape(row["downstream_server"])}.{escape(row["tool_name"])}</span>'
            f'<span class="approval-risk approval-risk-{risk}">{risk}</span>'
            "</header>"
            f'<p class="approval-reason">{escape(row["reason"])}</p>'
            '<dl class="approval-meta">'
            f'<div><dt>Action</dt><dd class="approval-wrap">{escape(row["action"])}</dd></div>'
            f'<div><dt>Resource</dt><dd class="approval-wrap">{escape(row["resource"])}</dd></div>'
            f'<div><dt>Client</dt><dd class="approval-wrap">{escape(row["client_id"])}</dd></div>'
            f'<div><dt>Session</dt><dd>{escape(row["session_id_prefix"])}</dd></div>'
            f'<div><dt>Created</dt><dd>{row["created_at"]}</dd></div>'
            f'<div><dt>Expires</dt><dd>{row["expires_at"]}</dd></div>'
            f'<div><dt>Payload hash</dt><dd class="approval-wrap">{escape(row["payload_hash"])}</dd></div>'
            "</dl>"
            f'<p class="approval-request-id">request {escape(row["request_id"])}</p>'
            f'<p class="approval-card-actions">'
            f'<a class="approval-button" href="{escape(detail_href)}">Review &amp; decide</a>'
            "</p>"
            "</article>"
        )

    def _render_prompt(self, prompt: ApprovalPrompt) -> str:
        token = self.server_owner.session_token
        title = f"Approval pending: {prompt.client_id} session {prompt.session_id[:8]}"
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
        body = f"""
{back_link}
<dl class="approval-detail">
<dt>Client</dt><dd>{escape(prompt.client_id)}</dd>
<dt>Session prefix</dt><dd>{escape(session_prefix)}</dd>
<dt>Request</dt><dd>{escape(prompt.request_id)}</dd>
<dt>Downstream</dt><dd>{escape(prompt.downstream_server)}</dd>
<dt>Tool</dt><dd>{escape(prompt.tool_name)}</dd>
<dt>Action</dt><dd>{escape(prompt.action_display)}</dd>
<dt>Resource</dt><dd>{escape(prompt.resource_display or "none")}</dd>
<dt>Risk</dt><dd>{escape(prompt.risk_class)}</dd>
<dt>Payload hash</dt><dd>{escape(prompt.payload_hash)}</dd>
<dt>Policy rule</dt><dd>{escape(prompt.policy_rule_id)}</dd>
<dt>Created</dt><dd>{prompt.created_at}</dd>
<dt>Expires</dt><dd>{prompt.expires_at}</dd>
</dl>
{detail}
<form method=\"post\">
<input type=\"hidden\" name=\"csrf_token\" value=\"{escape(prompt.csrf_token)}\">
<input type=\"hidden\" name=\"approval_scope\" value=\"exact\">
<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>
<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>
</form>
{similar}
"""
        return self._page(title, body, page_kind="detail")

    def _security_notice_html(self) -> str:
        return (
            '<p class="approval-security-notice">'
            f"{escape(APPROVAL_LOCAL_URL_WARNING)}"
            "</p>"
        )

    def _approval_page_styles(self, *, include_card_styles: bool = True) -> str:
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
{card_styles}.approval-back {{ margin: 0 0 12px; font-size: 12px; }}
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

    def _page(
        self,
        title: str,
        body: str,
        *,
        page_kind: str = "plain",
        include_card_styles: bool = True,
    ) -> str:
        styles = (
            self._approval_page_styles(include_card_styles=include_card_styles)
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

    def _send_html(
        self,
        status: HTTPStatus,
        body: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._send_bytes(status, body.encode("utf-8"), "text/html; charset=utf-8", extra_headers)

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
    ) -> None:
        self.send_response(int(status))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


__all__ = [
    "APPROVAL_LOCAL_URL_WARNING",
    "ApprovalPrompt",
    "ApprovalServer",
    "ApprovalServerDecision",
    "ApprovalServerError",
    "ApprovalServerGone",
    "SECURITY_HEADERS",
    "TERMINAL_ALREADY_DECIDED",
    "TERMINAL_ALREADY_DECIDED_APPROVE",
    "TERMINAL_ALREADY_DECIDED_DENY",
    "TERMINAL_APPROVAL_EXPIRED",
    "TerminalApprovalSnapshot",
]
