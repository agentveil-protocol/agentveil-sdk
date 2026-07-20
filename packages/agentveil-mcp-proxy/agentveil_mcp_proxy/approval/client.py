"""Client adapter for the stable local Approval Center."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable

from agentveil_mcp_proxy.approval.persistent import (
    ApprovalCenterManifest,
    load_manifest,
    loopback_json_post,
    manifest_is_reachable,
)
from agentveil_mcp_proxy.approval.server import (
    ApprovalPrompt,
    ApprovalServer,
    ApprovalServerDecision,
    ApprovalServerError,
    INTERNAL_REGISTER_TOKEN_HEADER,
    approval_prompt_to_dict,
    ensure_managed_approval_center_running,
    inspect_managed_approval_center,
    spawn_managed_approval_center_process,
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
            parsed = loopback_json_post(
                url,
                payload=approval_prompt_to_dict(prompt),
                headers={
                    INTERNAL_REGISTER_TOKEN_HEADER: self._manifest.internal_register_token,
                },
                timeout=REGISTER_TIMEOUT_SECONDS,
            )
        except (OSError, TimeoutError, ValueError) as exc:
            raise ApprovalServerError("persistent approval center is unavailable") from exc
        if not isinstance(parsed, dict) or not parsed.get("ok"):
            raise ApprovalServerError("persistent approval center rejected prompt registration")
        approval_url = parsed.get("approval_url")
        if not isinstance(approval_url, str) or not approval_url:
            raise ApprovalServerError("persistent approval center returned no approval URL")
        return approval_url

    def unregister(self, request_id: str, *, terminal_state: str = "already_decided") -> None:
        return

    def notify_cancelled(self, request_id: str) -> None:
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
            record = self.evidence_store.get_pending(request_id)
            if record is not None and record.status != ApprovalStatus.PENDING.value:
                # Terminal non-approve/deny (invalidated/cancelled/...) — stop polling.
                return None
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
    """Reuse the stable Approval Center when reachable and runtime-matched."""

    from agentveil_mcp_proxy.approval.persistent import manifest_runtime_matches_current

    manifest = load_manifest(proxy_dir)
    if (
        manifest is not None
        and manifest_is_reachable(manifest)
        and manifest_runtime_matches_current(manifest)
    ):
        return RemoteApprovalServer(
            manifest,
            evidence_store=evidence_store,
        )
    return fallback_factory()


def reconcile_managed_approval_center_for_runtime(
    *,
    home: Path,
    proxy_command: str,
    passphrase_file: Path | None = None,
) -> None:
    """Ensure one runtime-matched managed center exists before server resolution.

    A reachable but runtime-mismatched managed center is replaced through the
    shared lifecycle helpers so ``run_proxy`` does not fall back to an ephemeral
    in-process server while the stale managed process remains alive.
    """

    if inspect_managed_approval_center(home).state == "running":
        return

    def spawn() -> Any:
        return spawn_managed_approval_center_process(
            proxy_command=proxy_command,
            home=home,
            passphrase_file=passphrase_file,
        )

    ensure_managed_approval_center_running(home=home, spawn=spawn)


__all__ = [
    "RemoteApprovalServer",
    "reconcile_managed_approval_center_for_runtime",
    "resolve_approval_server",
]
