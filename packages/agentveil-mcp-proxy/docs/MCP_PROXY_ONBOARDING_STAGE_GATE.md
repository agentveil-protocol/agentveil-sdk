# MCP Proxy Onboarding Stage Gate

Product-path acceptance for the **onboarding stage** (cold client, candidate wheel on top of
T1 `client-config print`). Heavier than pytest; run before merging onboarding slices or tagging
an onboarding-stage RC.

For publish-time proof, still run
[`MCP_PROXY_RELEASE_ACCEPTANCE.md`](MCP_PROXY_RELEASE_ACCEPTANCE.md).

## Run

From the repository root:

```bash
packages/agentveil-mcp-proxy/scripts/mcp_proxy_onboarding_stage_gate.py
```

Pre-built wheel and kept artifacts:

```bash
packages/agentveil-mcp-proxy/scripts/mcp_proxy_onboarding_stage_gate.py \
  --wheel packages/agentveil-mcp-proxy/dist/agentveil_mcp_proxy-*.whl \
  --work-dir /tmp/avp-onboarding-gate \
  --keep-tmp
```

Local iteration without backend registration:

```bash
packages/agentveil-mcp-proxy/scripts/mcp_proxy_onboarding_stage_gate.py --skip-backend
```

Run from a neutral cwd (for example `/tmp`) so `PYTHONPATH` does not shadow the installed wheel.

## What It Verifies

From an **installed wheel** in a clean virtualenv and an isolated `--home`, the
gate verifies the public onboarding path:

- init, doctor, smoke, and client config output;
- MCP initialize/tools/list and one safe routed tool call;
- one risky routed tool call requiring approval before target mutation;
- approval, deny, evidence export, and verification surfaces;
- privacy-bounded JSON, human output, and retained artifacts.

Final stdout is one bounded JSON object with release metrics and a privacy scan
summary.

## Stage Gate Rule

Do not call the onboarding stage **done** unless this runner passes on the candidate wheel built
from the onboarding branch (T1 base + T3 gate), or the report documents an approved skip.

`--skip-backend` is for local debugging only, not for a stage sign-off that claims backend
onboarding works.

## Proof Boundary

- Loopback approval via HTTP (no real browser, no operator click).
- `run` subprocesses pass `--approval-ui-mode none` so the gate does not open browser
  tabs or OS notifications; `approval_url` in JSON-RPC is still used internally for
  HTTP approve only.
- Does not launch an IDE or mutate the operator’s `~/.avp`.
- VPS replay is optional later (same commands on a clean Linux host).
