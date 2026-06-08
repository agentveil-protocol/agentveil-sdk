# MCP Proxy Action Gate (P10A.1)

P10A.1 adds code-level enforcement for brokered MCP `tools/call` requests when an
operator configures a declared downstream tool surface.

## Scope

- Brokered MCP/tool path only.
- Compares operator-declared patterns in `tool_surface.allow` against the
  downstream-advertised tool set from `tools/list`.
- Fail-closes calls to downstream-advertised tools outside the declared surface
  before schema validation, local policy, Runtime Gate, approval, or downstream
  execution.
- Emits bounded Least Agency metadata through the existing local evidence store
  and proof export path.

P10A.2 adds fake-target controlled-path proof on the same brokered MCP/tool path.
Neither slice adds approval UI changes, shell/runtime hooks, or provider-native
controls.

## Activation

Action-gate checks are active when:

```json
"tool_surface": {
  "mode": "enforce",
  "allow": ["get_*", "list_*"]
}
```

`tool_surface.mode` must not be `off`, and `allow` must be non-empty.

## Enforcement order

For `tools/call`, the proxy evaluates in this order:

1. Declared-vs-observed downstream surface (P10A.1 action gate)
2. Operator tool-surface mode for undeclared tools not yet advertised
3. Unknown-tool gate (tool absent from downstream `tools/list`)
4. Schema validation, classification, local policy, Runtime Gate, approval,
   downstream execution

When a downstream-advertised tool is outside the declared surface, the proxy
returns a policy-blocked JSON-RPC error with
`reason=extra_undeclared_downstream_tool` and does not reach policy/backend
execution.

Negative test: `test_observe_mode_blocks_extra_downstream_tool_before_policy`
asserts no downstream forward and no policy call for the surface-mismatch case.

## Quarantine

After each downstream `tools/list` refresh, the proxy computes
`extra_undeclared_tools = observed - declared` and marks them quarantined in
the in-memory schema cache. A surface-drift security event is recorded when the
extra set is non-empty.

## Evidence metadata

Terminal action-gate denies persist `action_gate_metadata_jcs` on the evidence
record. The metadata is metadata-first and bounded:

- `declared_tool_surface`, `observed_tool_surface`, `extra_undeclared_tools`
- `declared_surface_hash`, `observed_surface_hash`
- `action_family`, `authority`, `escalation_trigger` (when present)
- `policy_decision`, `policy_rule`, `approval_status`, `execution_status`
- `request_id`, `request_chain`, `payload_hash`

Boundary: action-gate evidence stores bounded metadata and hashes; it does not
store raw MCP arguments, prompts, stdout/stderr, source code, secrets, or full
payloads in the P10A.1 evidence path.

Proof export surfaces parsed metadata as `action_gate_metadata` on each exported
record. Observability helpers expose the same bounded view under `action_gate`.

## Privacy

Boundary: security events and evidence records carry tool names, bounded hashes,
and surface summaries only. Negative tests must continue to prove representative
raw argument values are absent from policy-denied responses, security events,
evidence DB text, and exported bundles.

## P10A.2 fake-target controlled path

P10A.2 proves brokered `tools/call` target control with schema-aware fake
downstream fixtures (`tests/mcp_fake_downstream.py` controlled-path mode).

Product-path claims:

- **ALLOW** forwards to the fake downstream; `target_reached=true`.
- **BLOCK** returns `reason=local_policy_block`; the controlled-path negative
  test records no fake downstream `tools/call`; `target_reached=false`.
- **APPROVAL (pending)** returns `status=approval_required`; the controlled-path
  negative test records no fake downstream `tools/call` before approval;
  `target_reached=false`.
- **APPROVAL (retry)** after loopback approval and an identical retry reaches
  the fake downstream once; `target_reached=true`.

Bounded controlled-path metadata is stored on evidence rows as
`action_gate_metadata_jcs` and parsed by `parse_controlled_path_metadata()` /
observability export:

- `fixture_id`, `tool`, `policy_decision`, `policy_rule`
- `approval_status`, `execution_status`, `target_reached`
- `request_id`, `request_chain`, `payload_hash`

Fake-target outcome logs (`FAKE_TARGET_OUTCOME_LOG`) store fixture id, MCP
method, outcome (`reached` / `observed`), and a tool-call counter only. Boundary:
negative tests assert raw arguments, stdout/stderr, secrets, and full payloads
are absent from those logs.

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_passthrough.py \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_fake_target_controlled_path.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_fake_target_controlled_path_smoke.py
```
