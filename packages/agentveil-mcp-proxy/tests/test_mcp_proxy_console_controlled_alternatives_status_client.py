"""Tests for the best-effort active-only Console runtime heartbeat."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from agentveil_mcp_proxy.console_controlled_alternatives_status_client import (
    ControlledAlternativesStatusDispatcher,
    HEARTBEAT_INTERVAL_SECONDS,
)
from agentveil_mcp_proxy.console_credentials import CREDENTIAL_SCOPE, StoredCredential
from agentveil_mcp_proxy.controlled_alternatives_transport import (
    ControlledAlternativeRuntimeContext,
)

TOKEN = "console-device-token-canary-001"


def _credential(home=None):
    return StoredCredential(scope=CREDENTIAL_SCOPE, token=TOKEN)


def _context(heartbeat) -> ControlledAlternativeRuntimeContext:
    return ControlledAlternativeRuntimeContext(
        request=lambda _operation, _payload: (503, {}),
        state_root="/private/canary",
        heartbeat=heartbeat,
    )


def _ack(observed_at: str, *, result: str = "accepted") -> dict[str, object]:
    return {
        "schema_version": "1",
        "status": "active",
        "observed_at": observed_at,
        "result": result,
    }


def test_default_interval_is_sixty_seconds() -> None:
    assert HEARTBEAT_INTERVAL_SECONDS == 60.0


def test_no_runtime_binding_or_credential_makes_zero_heartbeat_calls(tmp_path) -> None:
    calls = []
    no_binding = ControlledAlternativesStatusDispatcher(
        runtime_context=None,
        home=tmp_path,
        load_credential_fn=_credential,
    )
    no_binding.start()
    assert no_binding.is_active is False
    assert no_binding.last_result == "skipped_no_runtime_binding"

    context = _context(lambda *_args: calls.append(True))
    no_credential = ControlledAlternativesStatusDispatcher(
        runtime_context=context,
        home=tmp_path,
        load_credential_fn=lambda home=None: None,
    )
    no_credential.start()
    assert no_credential.is_active is False
    assert no_credential.last_result == "skipped_no_credential"
    assert calls == []


def test_wrong_scope_or_loader_error_makes_zero_heartbeat_calls(tmp_path) -> None:
    calls = []
    context = _context(lambda *_args: calls.append(True))
    wrong_scope = ControlledAlternativesStatusDispatcher(
        runtime_context=context,
        home=tmp_path,
        load_credential_fn=lambda home=None: StoredCredential(
            scope="other_scope",
            token=TOKEN,
        ),
    )
    wrong_scope.start()
    assert wrong_scope.last_result == "skipped_unsafe_credential"

    broken = ControlledAlternativesStatusDispatcher(
        runtime_context=context,
        home=tmp_path,
        load_credential_fn=lambda home=None: (_ for _ in ()).throw(RuntimeError(TOKEN)),
    )
    broken.start()
    assert broken.last_result == "skipped_unsafe_credential"
    assert TOKEN not in repr(broken)
    assert calls == []


def test_immediate_and_periodic_heartbeat_then_owned_stop(tmp_path) -> None:
    calls: list[tuple[str, str]] = []
    reached_two = threading.Event()

    def heartbeat(token: str, observed_at: str):
        calls.append((token, observed_at))
        if len(calls) >= 2:
            reached_two.set()
        return 200, _ack(observed_at)

    dispatcher = ControlledAlternativesStatusDispatcher(
        runtime_context=_context(heartbeat),
        home=tmp_path,
        load_credential_fn=_credential,
        interval_seconds=0.02,
        clock=lambda: datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        + timedelta(seconds=len(calls)),
    )
    dispatcher.start()
    assert reached_two.wait(timeout=1.0)
    dispatcher.stop()
    count_after_stop = len(calls)
    time.sleep(0.05)
    assert dispatcher.is_active is False
    assert dispatcher.last_result == "accepted"
    assert len(calls) == count_after_stop
    assert not any(token != TOKEN for token, _ in calls)
    assert not any(not observed.endswith("Z") for _, observed in calls)
    assert TOKEN not in repr(dispatcher)
    assert "/private/canary" not in repr(dispatcher)


def test_duplicate_newer_ack_is_accepted(tmp_path) -> None:
    called = threading.Event()

    def heartbeat(_token: str, observed_at: str):
        called.set()
        newer = "2026-09-15T12:00:01Z"
        assert observed_at == "2026-09-15T12:00:00Z"
        return 200, _ack(newer, result="duplicate")

    dispatcher = ControlledAlternativesStatusDispatcher(
        runtime_context=_context(heartbeat),
        home=tmp_path,
        load_credential_fn=_credential,
        clock=lambda: datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
    )
    dispatcher.start()
    assert called.wait(timeout=1.0)
    deadline = time.monotonic() + 1.0
    while dispatcher.last_result == "not_started" and time.monotonic() < deadline:
        time.sleep(0.01)
    dispatcher.stop()
    assert dispatcher.last_result == "accepted"


def test_accepted_ack_cannot_replace_requested_timestamp(tmp_path) -> None:
    called = threading.Event()

    def heartbeat(_token: str, _observed_at: str):
        called.set()
        return 200, _ack("2099-01-01T00:00:00Z")

    dispatcher = ControlledAlternativesStatusDispatcher(
        runtime_context=_context(heartbeat),
        home=tmp_path,
        load_credential_fn=_credential,
        clock=lambda: datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
    )
    dispatcher.start()
    assert called.wait(timeout=1.0)
    deadline = time.monotonic() + 1.0
    while dispatcher.last_result == "not_started" and time.monotonic() < deadline:
        time.sleep(0.01)
    dispatcher.stop()
    assert dispatcher.last_result == "unavailable"


def test_malformed_error_and_clock_failure_are_bounded(tmp_path) -> None:
    outcomes = [
        (500, {"secret": TOKEN}),
        (200, {"schema_version": "1"}),
    ]
    calls = 0

    def heartbeat(_token: str, _observed_at: str):
        nonlocal calls
        result = outcomes[min(calls, len(outcomes) - 1)]
        calls += 1
        return result

    dispatcher = ControlledAlternativesStatusDispatcher(
        runtime_context=_context(heartbeat),
        home=tmp_path,
        load_credential_fn=_credential,
        interval_seconds=0.02,
    )
    dispatcher.start()
    deadline = time.monotonic() + 1.0
    while calls < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    dispatcher.stop()
    assert calls >= 2
    assert dispatcher.last_result == "unavailable"
    assert TOKEN not in dispatcher.last_result

    clock_failure = ControlledAlternativesStatusDispatcher(
        runtime_context=_context(lambda *_args: (200, {})),
        home=tmp_path,
        load_credential_fn=_credential,
        interval_seconds=0.02,
        clock=lambda: (_ for _ in ()).throw(RuntimeError("/Users/canary")),
    )
    clock_failure.start()
    time.sleep(0.05)
    clock_failure.stop()
    assert clock_failure.last_result == "unavailable"
    assert "/Users/" not in repr(clock_failure)
