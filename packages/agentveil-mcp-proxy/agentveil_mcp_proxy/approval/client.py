"""Client adapter for the stable local Approval Center."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    load_manifest,
    manifest_is_reachable,
)
from agentveil_mcp_proxy.approval.server import (
    ApprovalPrompt,
    ApprovalServer,
    ApprovalServerDecision,
    ApprovalServerError,
    INTERNAL_REGISTER_TOKEN_HEADER,
    approval_prompt_to_dict,
)
from agentveil_mcp_proxy.evidence import ApprovalStatus


REGISTER_TIMEOUT_SECONDS = 5.0
POLL_INTERVAL_SECONDS = 0.1


class RemoteApprovalServer:
    """Approval server adapter that forwards prompts to a stable local center."""

    owns_server_process = False

    def __init__(
        self,
        manifest: ApprovalCenterManifest,
        *,
        evidence_store: Any,
    ):
        self._manifest = manifest
        self.evidence_store = evidence_store
        self.host = manifest.host
        self.port = manifest.port
        self.session_token = manifest.session_token
        self._decision_handler: Callable[[ApprovalServerDecision], None] | None = None
        self._lock = threading.RLock()
        self._local_decisions: dict[str, ApprovalServerDecision] = {}

    @property
    def token_hash(self) -> str:
        return self._manifest.token_hash

    @property
    def base_url(self) -> str:
        return self._manifest.base_url

    @property
    def is_running(self) -> bool:
        return True

    def set_decision_handler(
        self,
        handler: Callable[[ApprovalServerDecision], None] | None,
    ) -> None:
        self._decision_handler = handler

    def start(self) -> None:
        return

    def stop(self, *, timeout: float = 2.0) -> None:
        return

    def approval_center_url(self) -> str:
        return self._manifest.approval_center_url()

    def approval_url(self, request_id: str) -> str:
        return f"{self.base_url}/approval/{self.session_token}/pending/{request_id}"

    def register(self, prompt: ApprovalPrompt) -> str:
        url = f"{self.base_url}/internal/register"
        try:
            with httpx.Client(trust_env=False, timeout=REGISTER_TIMEOUT_SECONDS) as client:
                response = client.post(
                    url,
                    json=approval_prompt_to_dict(prompt),
                    headers={
                        INTERNAL_REGISTER_TOKEN_HEADER: self._manifest.internal_register_token,
                    },
                )
                body = response.text
        except httpx.HTTPError as exc:
            raise ApprovalServerError("persistent approval center is unavailable") from exc
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ApprovalServerError("persistent approval center returned invalid json") from exc
        if not isinstance(parsed, dict) or not parsed.get("ok"):
            raise ApprovalServerError("persistent approval center rejected prompt registration")
        approval_url = parsed.get("approval_url")
        if not isinstance(approval_url, str) or not approval_url:
            raise ApprovalServerError("persistent approval center returned no approval URL")
        return approval_url

    def unregister(self, request_id: str, *, terminal_state: str = "already_decided") -> None:
        return

    def list_decided_request_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._local_decisions.keys())

    def get_decision(self, request_id: str) -> ApprovalServerDecision | None:
        with self._lock:
            return self._local_decisions.get(request_id)

    def wait_for_decision(self, request_id: str, *, timeout: float) -> ApprovalServerDecision | None:
        deadline = time.monotonic() + float(timeout)
        while time.monotonic() < deadline:
            decision = self._decision_from_evidence(request_id)
            if decision is not None:
                with self._lock:
                    self._local_decisions[request_id] = decision
                return decision
            time.sleep(POLL_INTERVAL_SECONDS)
        return None

    def _decision_from_evidence(self, request_id: str) -> ApprovalServerDecision | None:
        record = self.evidence_store.get_pending(request_id)
        if record is None:
            return None
        if record.status == ApprovalStatus.APPROVED.value:
            scope = record.approval_scope or "exact"
            return ApprovalServerDecision(
                request_id=request_id,
                decision="approve",
                approval_scope=scope,
            )
        if record.status == ApprovalStatus.DENIED.value:
            return ApprovalServerDecision(
                request_id=request_id,
                decision="deny",
                approval_scope="exact",
            )
        return None


def resolve_approval_server(
    proxy_dir: Path,
    *,
    evidence_store: Any,
    fallback_factory: Callable[[], ApprovalServer],
) -> ApprovalServer | RemoteApprovalServer:
    """Reuse the stable Approval Center when its manifest and process are alive."""

    manifest = load_manifest(proxy_dir)
    if manifest is not None and manifest_is_reachable(manifest):
        return RemoteApprovalServer(
            manifest,
            evidence_store=evidence_store,
        )
    return fallback_factory()


__all__ = ["RemoteApprovalServer", "resolve_approval_server"]
