# MCP Proxy Quickstart

This is the cold customer path for wrapping one downstream MCP server with the
AgentVeil MCP Proxy and producing an evidence bundle that is verifiable offline
in strict/proof-grade mode with an externally pinned signer DID. Every
step describes behavior that is implemented and locally verifiable. Anything
this quickstart does not cover yet is listed under
[What this quickstart does NOT prove](#what-this-quickstart-does-not-prove).

For day-2 operations, headless mode, multi-IDE deployment, evidence vacuum, and
identity migration, see [`MCP_PROXY_OPERATIONS.md`](MCP_PROXY_OPERATIONS.md).

## Prerequisites

- Python 3.10+ on macOS or Linux. Windows is supported but the proxy README
  flags a known orphan-process race on Windows; use a supervisor on Windows.
- A downstream MCP server you want to wrap. The downstream can be any MCP
  server: filesystem, GitHub, custom company server. You provide its launch
  command and arguments.
- Backend access: the proxy verifies signed AgentVeil Runtime Gate
  `decision_receipt/3` artifacts against a pinned signer-DID set. For
  `https://agentveil.dev` the trusted DIDs are bundled with the SDK; for any
  other base URL pass `--trusted-signer-did` to `init`.

Fresh Ubuntu 24.04 images often have `python3` but not the packaging tools
needed for a virtualenv install. Install them first:

```bash
sudo apt-get update
sudo apt-get install -y python3.12-venv python3-pip
```

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install agentveil
```

This installs the core `agentveil` SDK and registers the
`agentveil-mcp-proxy` console script.

## Step 1 — `agentveil-mcp-proxy init`

```bash
agentveil-mcp-proxy init
```

For a zero-dependency local smoke path, use the built-in sandboxed filesystem
downstream and filesystem policy pack instead of manually installing a
downstream MCP server:

```bash
agentveil-mcp-proxy init --quickstart-filesystem ./sandbox
```

Agent/non-interactive equivalent:

```bash
printf '%s\n' 'replace-with-a-long-local-passphrase' > ./passphrase.txt
chmod 600 ./passphrase.txt

agentveil-mcp-proxy init \
  --home ./avp-home \
  --passphrase-file ./passphrase.txt \
  --policy-pack filesystem \
  --downstream-name filesystem \
  --downstream-command /path/to/mcp-server \
  --downstream-arg /workspace \
  --json
```

By default this creates an **encrypted local identity**, a self-issued
delegation receipt scoped to the `mcp_proxy` category, and a starter config at
`~/.avp/mcp-proxy/config.json`. The encrypted-identity passphrase is collected
interactively, from `--passphrase-file`, or from the `AVP_PROXY_PASSPHRASE`
environment variable. See
[`MCP_PROXY_OPERATIONS.md#security-trade-offs-by-passphrase-source`](MCP_PROXY_OPERATIONS.md#security-trade-offs-by-passphrase-source).

### What `init` actually does

- Generates a fresh Ed25519 keypair locally.
- Writes the identity, control grant, and config under `~/.avp/` with
  owner-only permissions (0o600).
- Issues a local self-signed delegation receipt (issuer = subject = the new
  agent DID), scoped to the `mcp_proxy` category.
- When `--quickstart-filesystem <path>` is passed, writes downstream config for
  the built-in sandboxed filesystem MCP server and selects the filesystem
  policy pack.

### What `init` does NOT do

- It does not register the new agent with the AgentVeil backend.
- It does not contact `--base-url` at all.
- Until the agent is registered with the backend (see Step 3
  `agentveil-mcp-proxy register`), the proxy cannot exchange Runtime
  Gate decisions with `https://agentveil.dev`.

Custom base URL example:

```bash
agentveil-mcp-proxy init \
  --base-url https://your-private-avp.example \
  --trusted-signer-did did:key:zYourPinnedSignerDid
```

## Step 2 — `agentveil-mcp-proxy doctor` (local-only)

```bash
agentveil-mcp-proxy doctor
```

This validates local files only. Output on a fresh successful `init` looks
like:

```text
OK: config /home/me/.avp/mcp-proxy/config.json
OK: identity /home/me/.avp/agents/agentveil-mcp-proxy.json
OK: control grant /home/me/.avp/mcp-proxy/agentveil-mcp-proxy.control-grant.json
OK: trusted signers 2
OK: circuit breaker thresholds (5 failures, 60s window, 30s cooldown)
```

`doctor` checks: file permissions are 0600, the identity decrypts with the
configured passphrase, the agent DID matches its stored identity, the control
grant is signed by that identity, issuer/subject match, the trusted-signer DID
set is non-empty, and the control grant has not expired.

`doctor` exits non-zero on any of these failures, with a specific FAIL line.
It is intentionally offline: it does not call the backend.

If a downstream is already configured, add `--full` to launch it and verify MCP
`initialize` plus `tools/list`:

```bash
agentveil-mcp-proxy doctor --full
```

## Step 3 — `agentveil-mcp-proxy register`

```bash
agentveil-mcp-proxy register
```

Machine-readable equivalent:

```bash
agentveil-mcp-proxy register --json
```

Registers the exact identity created by `init` (same DID, same key) with
the backend at the `base_url` from your proxy config. This is the bridge
between local identity creation and the next step
(`doctor --check-backend`). Registration is required once per identity;
re-runs are idempotent.

### What `register` actually does

- Loads the same proxy identity file `doctor` and `run` use (encrypted
  with the same passphrase mechanism).
- Calls the SDK's `AVPAgent.register()` against the configured
  `base_url`: registration POST → Proof-of-Work solve → verify POST.
- Updates the local identity file's `registered` flag to `true`.
- Preserves the identity's encrypted-at-rest format (no plaintext
  downgrade).

### What `register` does NOT do

- It does not provision an agent card / capabilities / endpoint URL /
  provider on the backend. If you need those, use the `agentveil` SDK
  directly with the keyword arguments documented on
  `AVPAgent.register(...)`.
- It does not exchange Runtime Gate decisions or attestations on its
  own; that happens later when the proxy actually serves tool calls.
- It does not prove the proxy can ship a verified evidence bundle —
  that still requires Steps 7-9 below.

### Expected output

Success:

```text
OK: agent did:key:z6Mk... registered at https://agentveil.dev
```

Idempotent re-run when the agent already exists on the backend:

```text
OK: agent did:key:z6Mk... already registered at https://agentveil.dev
```

Sanitized failure shapes:

```text
FAIL: registration rejected at <base_url>: status 4xx
FAIL: registration failed at <base_url>: status 5xx
FAIL: backend unreachable at <base_url>: <ExceptionClass>
```

Raw response bodies and stack traces are never printed. Re-run after
fixing the underlying issue.

## Step 4 — `agentveil-mcp-proxy doctor --check-backend`

```bash
agentveil-mcp-proxy doctor --check-backend
```

Adds two read-only HTTP GETs against the configured backend:

- `GET /v1/health` — confirms the backend is reachable.
- `GET /v1/onboarding/{did}` — confirms the proxy agent identity is
  registered with the backend.

On success the output adds one extra line:

```text
OK: backend reachable at https://agentveil.dev, agent registered
```

On failure the output starts with one of:

```text
FAIL: backend unreachable at <base_url>: <ExceptionClass>
FAIL: backend health check failed at <base_url>: status <code>
FAIL: agent <did> is not registered with backend at <base_url>; run `agentveil-mcp-proxy register` to register this identity
FAIL: backend onboarding status check failed: status <code>
```

These failures are sanitized — raw response bodies and stack traces are not
printed. If you see "not registered", re-run Step 3
(`agentveil-mcp-proxy register`) before continuing.

`doctor` skips the backend preflight when any local check has already
failed.

## Step 5 — Configure the downstream MCP server

Use the helper to set `downstream.command` and `downstream.args` without
hand-editing JSON. Example for a filesystem MCP server:

```bash
agentveil-mcp-proxy downstream set \
  --name filesystem \
  --command npx \
  --arg -y \
  --arg @modelcontextprotocol/server-filesystem \
  --arg /Users/me/work
```

`name` is the server label the proxy uses internally and in evidence records.
`env` and `env_passthrough` are also supported; see
[`MCP_PROXY_OPERATIONS.md`](MCP_PROXY_OPERATIONS.md). The proxy refuses to
forward any `AVP_*` environment variable to the downstream — those names are
reserved for proxy-internal secrets.

Then run:

```bash
agentveil-mcp-proxy doctor --full
agentveil-mcp-proxy smoke
```

`doctor --full` and `smoke` both launch the configured downstream and require
valid MCP `initialize` and `tools/list` responses. They do not call Runtime
Gate and they do not execute any downstream tool.

`agentveil-mcp-proxy configure-downstream` remains as a backward-compatible
alias for `agentveil-mcp-proxy downstream set`.

## Machine-readable setup checks

Agents can request JSON output for setup and local checks:

```bash
agentveil-mcp-proxy doctor --full --json
agentveil-mcp-proxy smoke --json
agentveil-mcp-proxy events list --json
```

The JSON shape includes stable top-level fields:

```json
{
  "ok": true,
  "errors": [],
  "warnings": [],
  "downstream": {"configured": true, "name": "filesystem"},
  "evidence_count": 0
}
```

## Step 6 — Point your MCP client at the proxy

Configure your IDE / MCP client to run `agentveil-mcp-proxy run` as its
server entry point. The MCP Proxy README documents wiring for Claude Desktop,
Cursor, Windsurf, and VS Code:
[`agentveil_mcp_proxy/README.md`](../agentveil_mcp_proxy/README.md).

When the client starts the proxy:

```bash
agentveil-mcp-proxy run
```

The proxy: re-validates the local files via `doctor`, launches the downstream
MCP server, starts the local HTTP approval UI, and begins serving stdio
JSON-RPC.

## Step 7 — Trigger one MCP tool call

Use your MCP client (Claude Desktop, Cursor, Windsurf, VS Code, or any stdio
JSON-RPC client) to invoke a tool on the downstream server. The proxy
classifies the call, applies local policy, and:

- **ALLOW** policy decisions are forwarded to the downstream server. If the
  policy rule routes the call through Runtime Gate (`ASK_BACKEND`), the
  verified backend `decision_receipt/3` and the downstream result hash are
  recorded into the local SQLite evidence store **when an evidence store is
  configured for the run** (this is the default for `agentveil-mcp-proxy run`).
- **APPROVAL** policy decisions open the local browser approval UI bound to
  the exact payload hash and matched policy rule. The MCP client receives an
  immediate JSON-RPC `approval_required` error with `record_id`,
  `record_status`, and `approval_url`; after approving, retry the tool call
  from the MCP client.
- **BLOCK** policy decisions return a JSON-RPC error and never reach the
  downstream server. Runtime Gate BLOCK decisions taken on the `ASK_BACKEND`
  path are also recorded into the local evidence store with the backend's
  signed receipt attached.
- **OBSERVE** policy decisions are forwarded without further gating.

Slice-level note: recording verified Runtime Gate `ALLOW` and `BLOCK`
decisions into the local evidence store is a recent change. Before it
landed, only the approval-required path created proxy-side evidence
records. See `agentveil_mcp_proxy/passthrough.py` and
`agentveil_mcp_proxy/approval/manager.py` for the exact flow.

## Step 8 — Export the evidence bundle

After one or more tool calls:

```bash
agentveil-mcp-proxy export-evidence ./my-bundle.json
```

The CLI returns a summary line of the form:

```text
Evidence exported: ./my-bundle.json (N records, M signed receipts)
```

`N` is the count of local evidence records (one per gated tool call); `M` is
the count of backend-signed `decision_receipt/3` artifacts the proxy was
able to fetch via `agent.get_decision_receipt(audit_id)` and embed in the
bundle. If a record references an `audit_id` but the receipt could not be
fetched or the digest did not match, the CLI prints a `WARN` and the
bundle's `unverified_receipt_count` increases.

The exported bundle file is written with 0600 permissions.

## Step 9 — Verify the bundle offline

```bash
agentveil-mcp-proxy verify ./my-bundle.json \
  --trusted-signer-did did:key:zYourPinnedSignerDid
```

`verify` is strict and proof-grade: it trusts only the signer DID(s) you pin
with `--trusted-signer-did` and never the signer set embedded in the bundle. A
bundle that carries signed receipts fails closed (non-zero exit,
`status: invalid`) unless you pass `--trusted-signer-did`, and a referenced
signed receipt missing from the bundle is a hard failure rather than a warning.
Always pass the signer DID you independently trust.

Successful output:

```text
OK: bundle integrity verified, N records, M signed receipts
```

The verifier checks, offline:

1. Local record chain `prev_event_hash` and `record_hash` for every record.
2. Bundle-level `chain_root_hash` matches the last record's hash.
3. For every embedded signed receipt:
   - The SHA-256 of the byte-exact JCS receipt matches its key in
     `signed_receipts`.
   - The DataIntegrityProof / `eddsa-jcs-2022` signature verifies against
     one of the pinned signer DIDs.
   - `schema_version` is in the accepted set (`decision_receipt/1`,
     `decision_receipt/2`, `decision_receipt/3`). The current backend emits
     `decision_receipt/3`; `/1`,`/2` are accepted as legacy.
   - `audit_id` is present and well-formed.
4. Field cross-checks between record and embedded receipt:
   - `record.payload_hash` == `receipt.payload_hash`
   - `record.risk_class` == `receipt.client_risk_class`
   - `record.policy_context_hash` == `receipt.client_policy_context_hash`
   - `record.decision_audit_id` == `receipt.audit_id`

The verifier exits non-zero with a specific `EvidenceVerificationError`
message on any of these failures.

## What this quickstart proves

After the steps above, the bundle you produced contains, for each gated
tool call:

- A privacy-preserving local evidence record describing the action class,
  risk class, payload hash, policy rule, and decision audit ID.
- The backend-signed Runtime Gate `decision_receipt/3` artifact for every
  `ASK_BACKEND` Runtime Gate decision (`ALLOW` / `BLOCK` /
  `WAITING_FOR_HUMAN_APPROVAL`) that the proxy issued.
- The downstream result hash for forwarded calls that completed.

These artifacts are independently verifiable offline in strict/proof-grade mode
with an externally pinned backend signer DID set (the default
`verify_evidence_bundle` / CLI `verify` path). Verification fails closed when no
external signer DID is pinned — it never trusts the signer list embedded in the
bundle.

## What this quickstart does NOT prove

This list is the honest counterpart to the section above. The bundle
**does not** currently contain or prove any of the following:

- That the **production** AgentVeil backend at `https://agentveil.dev`
  signed receipts in any internal demo artifact you may have seen. The
  Action Proof Pack v1.2 internal proof harness runs against a local dev
  backend with a deterministic dev key, not the production signer set. v1.2
  is an internal proof, not customer production evidence.
- A backend-signed `human_approval_receipt/2` for the WAITING /
  approval-required path. The MCP Proxy currently uses a local browser
  approval UI; it does not call the backend Human Control API. The bundle
  carries the proxy-side local approval record but not a backend-signed
  approval artifact.
- A backend-signed `execution_receipt/2`. The backend `/v1/execute`
  endpoint exists for capabilities the backend itself adapts; the MCP
  Proxy forwards the call to your downstream MCP server instead. There is
  no backend-attested execution claim for proxy-forwarded calls.
- Control over agent actions that bypass the MCP Proxy. The proxy gates
  only calls that flow through it; raw shell, raw API access, or any path
  the MCP client takes without going through the proxy are out of scope.
- Sandbox replacement. The proxy does not contain or restrict the
  downstream MCP server's process; use OS-level sandboxing
  (container/VM/sandbox) separately if process containment matters.
- A fix to model behavior or model alignment. The proxy controls actions,
  not model reasoning or output.

## Failure modes you may hit

- `FAIL: agent <did> is not registered with backend at <base_url>` — the
  proxy identity was created locally but never onboarded. Run Step 3
  (`agentveil-mcp-proxy register`) and then re-run
  `doctor --check-backend`.
- `WARN: control grant expires in N days` — the local self-issued
  delegation is approaching expiry. Run
  `agentveil-mcp-proxy reissue-grant`.
- `FAIL: strict verification requires externally supplied trusted_signer_dids`
  from `verify` — you omitted `--trusted-signer-did` on a receipt-bearing
  bundle. Strict verify never trusts the bundle's embedded signer list; pass
  the signer DID you independently trust.
- `WARN: N records have decision_audit_id but no matching signed receipt
  in bundle` from `export-evidence` — the receipt fetch failed or the
  digest did not match. Check network reachability and that the agent
  identity matches the agent that produced the records.

## Where to go next

- Operations / day-2 reference:
  [`MCP_PROXY_OPERATIONS.md`](MCP_PROXY_OPERATIONS.md).
- MCP Proxy README with IDE wiring examples:
  [`agentveil_mcp_proxy/README.md`](../agentveil_mcp_proxy/README.md).
- Data handling boundaries:
  [`DATA_HANDLING.md`](DATA_HANDLING.md).
- SDK / API surface:
  [`API.md`](API.md).
