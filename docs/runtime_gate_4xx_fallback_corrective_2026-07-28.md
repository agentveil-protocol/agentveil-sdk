# Runtime Gate reached-4xx fallback corrective (2026-07-28)

Slice: `public-runtime-gate-4xx-fallback-corrective`

## User outcome

Evidence: the focused Runtime Gate regression exercises a fallback-ALLOW
configuration and asserts a terminal denial with zero downstream mutations.
A reached Runtime Gate HTTP `4xx` is treated as a bounded terminal rejection,
not an availability outage.

## Root cause

`RuntimeGateClient.evaluate()` caught exceptions raised by
`agent.runtime_evaluate()` and converted it into `RuntimeGateUnavailableError`.
The passthrough layer treats `RuntimeGateUnavailableError` as an availability
failure and calls `_fallback_error_response()`. The AVP SDK represents
`400/401/403/404/409/429` (and other client/policy errors) as `AVPError`
subclasses carrying `status_code`, so a normal reached-backend rejection could
incorrectly enter local fallback and — with a permissive fallback policy —
reach the downstream target through a different path.

## Change

### `runtime_gate.py`

- Added `RuntimeGateRejectedError(RuntimeGateError)` for a reached terminal
  `4xx`. It carries only a bounded `status_code` integer and the fixed message
  `"runtime gate rejected the request"` — no backend body, URL, headers, DID,
  token, resource, tool arguments, or request payload.
- Added `_classify_runtime_request_error()`: an SDK exception whose
  `status_code` is in `[400, 500)` becomes `RuntimeGateRejectedError`; timeout,
  connection, `5xx`, and any error without a usable `4xx` status stay
  `RuntimeGateUnavailableError`.
- `evaluate()` now raises the classified error and re-raises
  `RuntimeGateRejectedError` without calling `circuit_breaker.record_failure()`,
  so a reached `4xx` does not count as Runtime Gate unavailability.

### `passthrough.py`

- Added JSON-RPC error code `JSONRPC_RUNTIME_GATE_REJECTED = -32015` and a
  bounded user message.
- `_runtime_gate_error_response()` handles `RuntimeGateRejectedError` before the
  unavailable/general handlers and returns one bounded terminal JSON-RPC denial
  <!-- claim-check: allow bounded JSON-RPC status vocabulary is asserted by the focused passthrough regression. -->
  (`status="blocked"`, `reason="runtime_gate_rejected"`, `target_reached=False`).
  It does not call `_fallback_error_response()`.

## Unchanged

Signed `2xx` DecisionReceipt verification and `ALLOW` / `BLOCK` /
`WAITING_FOR_HUMAN_APPROVAL` behavior are unchanged. Timeout, connection, and
`5xx` failures retain the existing unavailable/fallback behavior.

## Verification

`PYTHONPATH=.:packages/agentveil-mcp-proxy python3 -m pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_runtime_gate.py -q`
→ 79 passed.

New tests cover: reached `4xx` (400/401/403/404/409/429/418) → terminal
rejection with no raw detail; circuit breaker not worsened; passthrough with
fallback `ALLOW` produces a terminal denial and zero downstream mutations;
timeout/connection/`5xx` stay unavailable/fallback; signed `ALLOW` still
verifies.
