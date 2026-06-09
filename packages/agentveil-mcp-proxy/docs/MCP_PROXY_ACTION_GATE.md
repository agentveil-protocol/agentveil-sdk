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

## P10A.3 role / authority policy gate

P10A.3 adds Least Agency role/authority enforcement on the brokered MCP/tool path.
It extends the existing policy/classification model; it does not add credential
custody, shell/runtime hooks, or provider-native controls.

Activation:

```json
"role_authority": {
  "mode": "enforce",
  "role": "reviewer",
  "authority": "review_only"
}
```

Policy rules and built-in role rules may match on `role`, `authority`, and
`action_family` in addition to server/tool/action/risk_class. Built-in reviewer
enforcement blocks implementation/write action families
(`write`, `create`, `update`, `delete`, `remove`, `exec`, `shell`) before
downstream execution with `reason=role_authority_denied`.

Product-path claims:

- **Reviewer + write/implement action** does not reach fake downstream;
  `target_reached=false`.
- **Reviewer + read action** and **implementer + write action** may reach fake
  downstream when local policy allows; `target_reached=true`.
- Controlled-path evidence stores bounded `role`, `authority`, and
  `action_family` beside `target_reached`.
- Strict `verify_evidence_bundle()` still rejects tampered parsed
  `action_gate_metadata`.

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_role_authority_policy.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python3 \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_role_authority_policy_smoke.py
```

## P10A.4 role presets / no-JSON setup

P10A.4 turns P10A.3 role/authority into a starter path without hand-editing
`role_authority` JSON. Operators choose a preset at init time:

```bash
agentveil-mcp-proxy init --role reviewer --plaintext
agentveil-mcp-proxy init --role readonly --plaintext
agentveil-mcp-proxy init --role implementer --plaintext
agentveil-mcp-proxy init --role build --plaintext
```

Generated config includes:

- `role_preset` — selected preset name
- `role_authority` — enforced `mode`, `role`, `authority` for that preset

Optional runtime override:

```bash
AVP_PROXY_ROLE=reviewer agentveil-mcp-proxy run --home ~/.avp ...
```

`client-config print --config <path>` emits run args with `--config` pointing at
the generated preset config and includes `role_preset` in JSON output.

Preset behavior:

- `reviewer` → `reviewer` / `review_only`; builtin denies mutation action families
- `readonly` → `readonly` / `read_only`; builtin denies mutation action families
- `implementer` / `build` → write-capable roles without reviewer builtin deny

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_role_presets.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python3 \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_role_presets_smoke.py
```

## P10A.5 explain / redirect / role doctor

P10A.5 makes P10A.4 role presets understandable and actionable. Deny and
approval-required JSON-RPC errors include bounded `explanation` text plus redirect
metadata:

- `next_step`
- `suggested_next_step_id`
- `redirect_playbook_id`

Examples:

- reviewer write deny → `create_implementer_task`
- readonly mutation deny → `use_read_only_tool`
- approval-required risky action → `request_approval`
- unknown high-risk block → `stop_and_classify_unknown_action`

Redirect guidance does not call downstream targets, mutate config, auto-approve,
or auto-execute.

Role doctor CLI:

```bash
agentveil-mcp-proxy explain role --preset reviewer
agentveil-mcp-proxy explain role --home ~/.avp
```

<!-- claim-check: allow "blocked" is bounded role-doctor status vocabulary. -->
Output lists allowed, approval-required, and blocked action families per preset
without raw prompts, secrets, stdout/stderr, or full payloads.

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_role_doctor.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python3 \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_role_doctor_smoke.py
```

## P10A.6 one-command agent templates

P10A.6 ships copy-paste runnable starter commands for the first Level 2
review/build/readonly agents. Templates reuse the normal product path:

```bash
agentveil-mcp-proxy templates print --template review --home ~/.avp-review-agent --sandbox ~/.avp-review-sandbox
agentveil-mcp-proxy templates print --template build --home ~/.avp-build-agent --sandbox ~/.avp-build-sandbox
agentveil-mcp-proxy templates print --template readonly --home ~/.avp-readonly-agent --sandbox ~/.avp-readonly-sandbox
```

Each template emits bounded commands for:

1. `init --role ... --quickstart-filesystem ...`
2. `client-config print`
3. `explain role`
4. `run --approval-ui-mode terminal`

Template behavior:

- `review` → reviewer preset blocks `write_file` before downstream target
- `build` → implementer preset reaches allowed quickstart read/list target; filesystem write goes to approval
- `readonly` → readonly preset denies mutation before downstream target

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_agent_templates.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python3 \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_agent_templates_smoke.py
```

## P10A.7 safe config wizard / all tools through proxy

P10A.7 generates and validates MCP desktop client config so configured MCP
tools route through `agentveil-mcp-proxy run --config <proxy-config>`, not a
direct downstream command in the desktop client.

Boundary: this covers MCP tools represented in generated client config entries
only. It does not claim host-wide shell control, terminal interception,
provider-native enforcement, Secure Runtime, or bypass prevention outside the
configured MCP client path.

```bash
agentveil-mcp-proxy wizard print --template review --home ~/.avp-review-agent --sandbox ~/.avp-review-sandbox --init
agentveil-mcp-proxy wizard print --template build --home ~/.avp-build-agent --sandbox ~/.avp-build-sandbox --init
agentveil-mcp-proxy wizard validate --input ./unsafe-mcp.json
```

Wizard output includes a bounded summary:

- role preset
- home/config path
- proxy command
- client target
- bypass status

Unsafe direct downstream configs (for example `npx @modelcontextprotocol/...` or
`quickstart_filesystem.py` as the desktop client command) are detected and
rejected with bounded guidance.

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_config_wizard.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python3 \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_config_wizard_smoke.py
```

## P10A.9 persistent Approval Center / any-client UX

P10A.9 makes the local Approval Center a stable product path for any MCP client
turn. A one-shot `agentveil-mcp-proxy run` no longer owns the only loopback
approval HTTP server.

Start the stable center once per AVP home:

```bash
agentveil-mcp-proxy approval-center serve --home ~/.avp
```

Product behavior:

- `agentveil-mcp-proxy run` reuses the stable Approval Center when its manifest
  and process are alive.
- Approval URLs point at the stable center port/token, not a transient per-run
  server.
- Terminal approved/denied pages render from durable local evidence when the
  original in-memory prompt is gone.
- Ephemeral in-process Approval Center remains the fallback when the stable
  center is not running.

Boundary: this is the MCP proxy any-client approval path. It does not depend on
Agent Console, backend APIs, VPS deploy, or provider-native hooks.

Verification:

```bash
PYTHONPATH=.:packages/agentveil-mcp-proxy pytest \
  packages/agentveil-mcp-proxy/tests/test_mcp_proxy_persistent_approval_center.py -q

PYTHONPATH=.:packages/agentveil-mcp-proxy python3 \
  packages/agentveil-mcp-proxy/tests/live/mcp_proxy_persistent_approval_center_smoke.py
```
