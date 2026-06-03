"""Loopback approval server for the MCP Proxy approval surface."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
import hashlib
import hmac
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qs


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
        "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
}
COOKIE_NAME = "avp_approval_session"


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
        return self.approval_url(prompt.request_id)

    def unregister(self, request_id: str) -> None:
        """Mark an approval URL as no longer actionable."""

        with self._lock:
            self._prune_terminal_requests_locked()
            prompt = self._prompts.pop(request_id, None)
            self._decisions.pop(request_id, None)
            self._decision_events.pop(request_id, None)
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


class _ApprovalRequestHandler(BaseHTTPRequestHandler):
    server_owner: ApprovalServer

    def setup(self) -> None:
        super().setup()
        self.request.settimeout(REQUEST_SOCKET_TIMEOUT_SECONDS)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:
        token, request_id = self._parse_path()
        if not self._token_ok(token):
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        if request_id is None:
            self._send_html(HTTPStatus.OK, self._render_list())
            return
        prompt = self.server_owner.prompt_for(request_id)
        if prompt is None:
            if self.server_owner.is_terminal(request_id):
                self._send_text(HTTPStatus.GONE, "approval already decided")
            else:
                self._send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        self._send_html(
            HTTPStatus.OK,
            self._render_prompt(prompt),
            extra_headers={"Set-Cookie": self._session_cookie_header()},
        )

    def do_POST(self) -> None:
        token, request_id = self._parse_path()
        if request_id is None or not self._token_ok(token):
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        prompt = self.server_owner.prompt_for(request_id)
        if prompt is None:
            if self.server_owner.is_terminal(request_id):
                self._send_text(HTTPStatus.GONE, "approval already decided")
            else:
                self._send_text(HTTPStatus.NOT_FOUND, "not found")
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
            self._send_text(HTTPStatus.GONE, "approval already decided")
            return
        except ApprovalServerError:
            self._send_text(HTTPStatus.FORBIDDEN, "forbidden")
            return
        self._send_html(HTTPStatus.OK, self._page("Approval recorded", "<p>Decision recorded.</p>"))

    def _parse_path(self) -> tuple[str | None, str | None]:
        parts = [part for part in self.path.split("?")[0].split("/") if part]
        if len(parts) >= 2 and parts[0] == "approval":
            token = parts[1]
            if len(parts) == 2:
                return token, None
            if len(parts) == 4 and parts[2] == "pending":
                return token, parts[3]
        return None, None

    def _token_ok(self, token: str | None) -> bool:
        return bool(token) and hmac.compare_digest(token or "", self.server_owner.session_token)

    def _session_cookie_header(self) -> str:
        return (
            f"{COOKIE_NAME}={self.server_owner._cookie_value()}; "
            f"Path=/approval/{self.server_owner.session_token}; HttpOnly; SameSite=Strict"
        )

    def _render_list(self) -> str:
        items = []
        for prompt in self.server_owner.pending_prompts():
            href = f"/approval/{self.server_owner.session_token}/pending/{prompt.request_id}"
            items.append(
                "<li>"
                f"<a href=\"{escape(href)}\">{escape(prompt.downstream_server)}."
                f"{escape(prompt.tool_name)}</a> "
                f"{escape(prompt.risk_class)} {escape(prompt.payload_hash[:19])} "
                f"{escape(prompt.client_id)} session {escape(prompt.session_id[:8])}"
                "</li>"
            )
        body = "<p>No pending approvals.</p>" if not items else "<ul>" + "".join(items) + "</ul>"
        return self._page("Pending approvals", body)

    def _render_prompt(self, prompt: ApprovalPrompt) -> str:
        title = f"Approval pending: {prompt.client_id} session {prompt.session_id[:8]}"
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
        body = f"""
<h1>Approval pending</h1>
<dl>
<dt>Client</dt><dd>{escape(prompt.client_id)}</dd>
<dt>Session</dt><dd>{escape(prompt.session_id)}</dd>
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
        return self._page(title, body)

    def _page(self, title: str, body: str) -> str:
        return (
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            f"<title>{escape(title)}</title></head><body>{body}</body></html>"
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
    "ApprovalPrompt",
    "ApprovalServer",
    "ApprovalServerDecision",
    "ApprovalServerError",
    "ApprovalServerGone",
    "SECURITY_HEADERS",
]
