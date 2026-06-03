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

From an **installed wheel** in a clean virtualenv and an isolated `--home`:

1. `init --quickstart-filesystem --json`
2. `doctor --full --json`
3. `smoke --json`
4. `client-config print --json` (cursor + claude_desktop, dry-run, privacy-checked)
5. Optional `register` + `doctor --check-backend` (unless `--skip-backend`)
6. Persistent `run`: `initialize`, `tools/list`, allow `list_workspace`
7. Risky `write_file` → `approval_required`, sandbox file **absent**
8. Approval Center `GET …/api/approvals` when the wheel exposes it and a pending item exists
9. HTTP approve + **one** successful retry; third identical call must **not** execute again
10. Separate `run --approval-ui-mode none --headless --auto-deny` → deny path, deny probe file absent
11. `events list --json` (approved, executed, denied)
12. `export-evidence` + strict `verify --output json`
13. Privacy scan on bundle, events, client-config JSON, runner output, and final report

Final stdout is one JSON object with metrics (`candidate_git_sha`, `wheel_sha256`,
`installed_package_path`, `client_config_print_ok`, `approval_center_api`, etc.). The
`approval_center_api` output is checked to omit the loopback bearer token and full
`/approval/<token>/…` URL; it keeps redacted host/port/path metadata plus `pending_count`.

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
