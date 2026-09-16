# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Best-effort active-only Console heartbeat for a bound CA runtime."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from agentveil_mcp_proxy.console_credentials import (
    CREDENTIAL_SCOPE,
    StoredCredential,
    load_credential,
)
from agentveil_mcp_proxy.controlled_alternatives_transport import (
    ControlledAlternativeRuntimeContext,
)

HEARTBEAT_INTERVAL_SECONDS = 60.0
HEARTBEAT_STOP_TIMEOUT_SECONDS = 5.25

Heartbeat = Callable[[str, str], tuple[int, Mapping[str, Any]]]
LoadCredential = Callable[..., StoredCredential | None]
Clock = Callable[[], datetime]


def _canonical_observed_at(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    text = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        text += f".{utc.microsecond:06d}".rstrip("0")
    return f"{text}Z"


def _valid_ack(
    status_code: int,
    payload: Mapping[str, Any],
    *,
    requested_at: str,
) -> bool:
    if status_code != 200 or set(payload) != {
        "schema_version",
        "status",
        "observed_at",
        "result",
    }:
        return False
    if payload.get("schema_version") != "1" or payload.get("status") != "active":
        return False
    result = payload.get("result")
    if result not in {"accepted", "duplicate"}:
        return False
    observed_at = payload.get("observed_at")
    if not isinstance(observed_at, str):
        return False
    try:
        requested = datetime.fromisoformat(requested_at.removesuffix("Z") + "+00:00")
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if observed.tzinfo is None:
        return False
    if result == "accepted":
        return observed == requested
    return observed >= requested


class ControlledAlternativesStatusDispatcher:
    """One owned worker with best-effort transport isolated from proxy execution."""

    def __init__(
        self,
        *,
        runtime_context: ControlledAlternativeRuntimeContext | None,
        home: Path | None = None,
        load_credential_fn: LoadCredential = load_credential,
        interval_seconds: float = HEARTBEAT_INTERVAL_SECONDS,
        clock: Clock | None = None,
    ) -> None:
        self._runtime_context = runtime_context
        self._home = home
        self._load_credential_fn = load_credential_fn
        self._interval_seconds = max(float(interval_seconds), 0.01)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._active = False
        self._last_result = "not_started"

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def last_result(self) -> str:
        return self._last_result

    def start(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        context = self._runtime_context
        heartbeat = None if context is None else context.heartbeat
        if not callable(heartbeat):
            self._last_result = "skipped_no_runtime_binding"
            return
        try:
            credential = self._load_credential_fn(home=self._home)
        except Exception:
            self._last_result = "skipped_unsafe_credential"
            return
        if credential is None:
            self._last_result = "skipped_no_credential"
            return
        if credential.scope != CREDENTIAL_SCOPE:
            self._last_result = "skipped_unsafe_credential"
            return
        self._stop.clear()
        self._active = True
        self._worker = threading.Thread(
            target=self._run,
            args=(heartbeat, credential.token),
            name="console-ca-runtime-status",
            daemon=True,
        )
        try:
            self._worker.start()
        except Exception:
            self._active = False
            self._last_result = "unavailable"

    def stop(self, *, timeout: float = HEARTBEAT_STOP_TIMEOUT_SECONDS) -> None:
        self._stop.set()
        worker = self._worker
        if worker is not None and worker.is_alive():
            try:
                worker.join(timeout=max(float(timeout), 0.0))
            except Exception:
                pass
        self._active = False

    def _run(self, heartbeat: Heartbeat, console_credential: str) -> None:
        while not self._stop.is_set():
            try:
                requested_at = _canonical_observed_at(self._clock())
                status, payload = heartbeat(console_credential, requested_at)
                self._last_result = (
                    "accepted"
                    if _valid_ack(status, payload, requested_at=requested_at)
                    else "unavailable"
                )
            except Exception:
                self._last_result = "unavailable"
            if self._stop.wait(self._interval_seconds):
                return


__all__ = [
    "ControlledAlternativesStatusDispatcher",
    "HEARTBEAT_INTERVAL_SECONDS",
    "HEARTBEAT_STOP_TIMEOUT_SECONDS",
]
