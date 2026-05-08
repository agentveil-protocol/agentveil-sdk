#!/usr/bin/env python3
"""Typed AgentVeil error-handling patterns.

The demo uses mock mode and simulated API failures, so it is safe to run
without a backend. Replace the simulated calls with real SDK calls in
production and keep the same exception structure.
"""

from __future__ import annotations

import httpx

from agentveil import (
    AVPAgent,
    AVPAuthError,
    AVPError,
    AVPRateLimitError,
    AVPServerError,
    AVPValidationError,
)
from agentveil.delegation import DelegationInvalid

EXIT_SUCCESS = 0
EXIT_RETRYABLE = 1
EXIT_NON_RETRYABLE = 2
EXIT_CONFIG = 3


def run_step(label: str, call) -> int:
    try:
        call()
    except AVPRateLimitError as exc:
        print(f"{label}: retryable rate limit; wait={exc.retry_after}s")
        return EXIT_RETRYABLE
    except AVPValidationError as exc:
        print(f"{label}: validation error; message={exc.message}")
        return EXIT_NON_RETRYABLE
    except AVPServerError as exc:
        print(f"{label}: server unavailable; status={exc.status_code}")
        return EXIT_RETRYABLE
    except AVPAuthError as exc:
        print(f"{label}: auth/setup error; message={exc.message}")
        return EXIT_CONFIG
    except AVPError as exc:
        print(f"{label}: sdk error; status={exc.status_code}; message={exc.message}")
        return EXIT_NON_RETRYABLE
    except httpx.RequestError as exc:
        print(f"{label}: network error; detail={exc}")
        return EXIT_RETRYABLE
    except DelegationInvalid as exc:
        print(f"{label}: invalid delegation; reason={exc.reason}")
        return EXIT_NON_RETRYABLE
    else:
        print(f"{label}: success")
        return EXIT_SUCCESS


def simulated_rate_limit() -> None:
    raise AVPRateLimitError("Rate limited: trust gate", retry_after=30)


def simulated_server_error() -> None:
    raise AVPServerError("Server error: signing key unavailable", 503, "")


def simulated_auth_error() -> None:
    raise AVPAuthError("Authentication failed: signature_invalid", 401, "")


def simulated_network_error() -> None:
    raise httpx.ConnectError("connection refused")


def main() -> int:
    agent = AVPAgent.create(mock=True, name="error-demo")

    scenarios = [
        (
            "mock batch validation",
            lambda: agent.attest_batch([]),
        ),
        (
            "offline delegation verification",
            lambda: agent.verify_delegation_receipt({}),
        ),
        (
            "rate limit retry",
            simulated_rate_limit,
        ),
        (
            "server retry",
            simulated_server_error,
        ),
        (
            "auth recovery",
            simulated_auth_error,
        ),
        (
            "network retry",
            simulated_network_error,
        ),
    ]

    results = [run_step(label, call) for label, call in scenarios]
    print("recommended_exit_codes:", results)
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
