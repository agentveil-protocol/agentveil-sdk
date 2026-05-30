"""Gateway-agnostic circuit breaker for bounded backend calls."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
import threading
import time
from typing import Any, Callable, Deque, Mapping


class CircuitState(str, Enum):
    """Circuit breaker state machine values."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(RuntimeError):
    """Raised when a backend call is skipped because the circuit is open."""


@dataclass(frozen=True)
class CircuitBreakerConfig:
    """Configuration for the backend circuit breaker."""

    failures_before_open: int = 5
    window_seconds: int = 60
    cooldown_seconds: int = 30
    half_open_test_count: int = 1

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None = None) -> "CircuitBreakerConfig":
        """Parse and validate circuit breaker config."""

        if data is None:
            return cls()
        if not isinstance(data, Mapping):
            raise ValueError("circuit_breaker must be an object")
        allowed = {
            "failures_before_open",
            "window_seconds",
            "cooldown_seconds",
            "half_open_test_count",
        }
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ValueError(f"circuit_breaker has unknown field(s): {', '.join(unknown)}")
        defaults = cls()
        return cls(
            failures_before_open=_positive_int(
                data.get("failures_before_open", defaults.failures_before_open),
                "circuit_breaker.failures_before_open",
            ),
            window_seconds=_positive_int(
                data.get("window_seconds", defaults.window_seconds),
                "circuit_breaker.window_seconds",
            ),
            cooldown_seconds=_positive_int(
                data.get("cooldown_seconds", defaults.cooldown_seconds),
                "circuit_breaker.cooldown_seconds",
            ),
            half_open_test_count=_positive_int(
                data.get("half_open_test_count", defaults.half_open_test_count),
                "circuit_breaker.half_open_test_count",
            ),
        )


class CircuitBreaker:
    """Three-state circuit breaker with a sliding failure window."""

    def __init__(
        self,
        config: CircuitBreakerConfig | None = None,
        *,
        time_func: Callable[[], float] = time.monotonic,
    ):
        self.config = config or CircuitBreakerConfig()
        self._time_func = time_func
        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_times: Deque[float] = deque()
        self._opened_at: float | None = None
        self._half_open_successes = 0
        self._state_change_count = 0
        self._events: Deque[dict[str, Any]] = deque(maxlen=1000)

    @property
    def state(self) -> CircuitState:
        """Return the current circuit state."""

        with self._lock:
            return self._state

    @property
    def state_change_count(self) -> int:
        """Return the number of state transitions since construction."""

        with self._lock:
            return self._state_change_count

    def before_call(self) -> None:
        """Allow a backend call or raise when the circuit is open."""

        with self._lock:
            now = self._time_func()
            if self._state is CircuitState.OPEN:
                if self._opened_at is not None and (
                    now - self._opened_at >= self.config.cooldown_seconds
                ):
                    self._transition_locked(CircuitState.HALF_OPEN, now)
                else:
                    raise CircuitBreakerOpenError("runtime gate circuit breaker open")

    def record_success(self) -> None:
        """Record a successful backend call."""

        with self._lock:
            now = self._time_func()
            if self._state is CircuitState.HALF_OPEN:
                self._half_open_successes += 1
                if self._half_open_successes >= self.config.half_open_test_count:
                    self._failure_times.clear()
                    self._transition_locked(CircuitState.CLOSED, now)
                return
            if self._state is CircuitState.CLOSED:
                self._failure_times.clear()

    def record_failure(self) -> None:
        """Record an availability failure."""

        with self._lock:
            now = self._time_func()
            if self._state is CircuitState.HALF_OPEN:
                self._transition_locked(CircuitState.OPEN, now)
                return
            if self._state is CircuitState.OPEN:
                self._opened_at = now
                return
            self._prune_failures_locked(now)
            self._failure_times.append(now)
            if len(self._failure_times) >= self.config.failures_before_open:
                self._transition_locked(CircuitState.OPEN, now)

    def drain_events(self) -> tuple[Mapping[str, Any], ...]:
        """Return and clear sanitized state-change events."""

        with self._lock:
            events = tuple(dict(event) for event in self._events)
            self._events.clear()
        return events

    def _transition_locked(self, state: CircuitState, now: float) -> None:
        if state is self._state:
            return
        self._state = state
        self._state_change_count += 1
        if state is CircuitState.OPEN:
            self._opened_at = now
            self._half_open_successes = 0
        elif state is CircuitState.HALF_OPEN:
            self._half_open_successes = 0
        else:
            self._opened_at = None
            self._half_open_successes = 0
        self._events.append({
            "type": _EVENT_BY_STATE[state],
            "state": state.value,
            "timestamp": now,
            "state_change_count": self._state_change_count,
            "failures_before_open": self.config.failures_before_open,
            "cooldown_seconds": self.config.cooldown_seconds,
        })

    def _prune_failures_locked(self, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while self._failure_times and self._failure_times[0] < cutoff:
            self._failure_times.popleft()


_EVENT_BY_STATE = {
    CircuitState.OPEN: "circuit_breaker_opened",
    CircuitState.HALF_OPEN: "circuit_breaker_half_open",
    CircuitState.CLOSED: "circuit_breaker_closed",
}


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{where} must be a positive integer")
    return value


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerOpenError",
    "CircuitState",
]
