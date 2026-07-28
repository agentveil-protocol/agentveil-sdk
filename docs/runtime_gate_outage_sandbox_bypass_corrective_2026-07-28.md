# Runtime Gate outage sandbox bypass corrective (2026-07-28)

Slice: `public-runtime-gate-outage-sandbox-bypass-corrective`

## Upgrade impact (public)

When AVP Runtime Gate is genuinely unavailable (timeout, connection failure, or
`5xx`), read-only sandbox MCP tools such as `read_file` and `list_workspace` no
longer bypass governance automatically. They now follow the operator's explicit
fallback policy for the read risk class:

- `fallback.read=block` → bounded `runtime_gate_unavailable` denial; the
  regression asserts downstream call count zero.
- `fallback.read=approval` → existing bounded approval-required path, no
  downstream execution until approval.
- `fallback.read=allow` → one downstream call, as an intentional operator choice.

This change removes a special-case bypass in the outage fallback path. It does
not change Runtime Gate `4xx` terminal rejection, classification, approval or
evidence contracts, or non-sandbox fallback behavior for write/destructive tools.

## Root cause

`_fallback_error_response()` called
`_read_only_sandbox_tool_allowed_when_gate_unavailable()`, which returned
`(None, None)` for certain read-only sandbox tools on filesystem/product routes.
That tuple tells passthrough to continue downstream without applying the
configured fallback policy — a separate automatic bypass unrelated to explicit
operator fallback configuration.

## Change

Removed the automatic sandbox read-only bypass from the Runtime Gate outage
fallback path in `passthrough.py`. Outage handling resolves through the existing
explicit fallback policy (`config.fallback.for_risk(...)`).

## Verification

`PYTHONPATH=.:packages/agentveil-mcp-proxy python3 -m pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_runtime_gate.py -q`
→ 89 passed.

New tests cover: outage + sandbox `read_file` on `filesystem` and
`list_workspace` on exact `product` server + `fallback.read=block` (downstream
call count zero); + `fallback.read=approval` (approval path, call count zero); +
`fallback.read=allow` (exactly one downstream call); non-sandbox write outage
unchanged; reached Runtime Gate `4xx` on sandbox read stays terminal with zero
downstream calls; fake server labels (`github`, `fake-filesystem`) do not reopen
automatic bypass during outage.

The removed legacy helper matched both `server="filesystem"` and exact
`server="product"` for tools in `SANDBOX_READ_ONLY_MCP_TOOLS`; both paths are
now proved by tests rather than inferred from the diff alone.
