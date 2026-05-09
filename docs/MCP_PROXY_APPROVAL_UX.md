# MCP Proxy Approval UX Design

## Overview

This document defines the P6 approval UX contract for the MCP Proxy adapter.
P6 turns `WAITING_FOR_HUMAN_APPROVAL` and local `approval` policy decisions into
an operator decision before the proxy forwards a risky MCP `tools/call` request
to a downstream server. The design is intentionally scoped to the MCP Proxy
adapter surface; durable approval state and evidence are provided by P7a before
the P6 UI implementation can safely ship.

## Positioning

MCP Proxy approval UX is one of multiple possible approval surfaces; backend
approval primitive is gateway-agnostic.

The approval primitive belongs in the AVP backend and `agentveil` SDK:
protocol-level approval state, signed approval receipts, scope semantics, and
receipt verification. The MCP Proxy owns only the local adapter surface:
loopback web server, browser launch, OS notification, CLI prompt, and local
request correlation for MCP clients.

Other adapters, including Bedrock integrations, AgentMesh integrations, browser
extensions, and future hosted gateways, will build their own approval surfaces
against the same gateway-agnostic approval primitive. P6 must not encode
MCP-only assumptions into backend approval semantics.

## Decision 1: Local Approval Server Authentication

Decision:

- Bind the approval server to `127.0.0.1:<port>` only.
- Generate a high-entropy per-process approval session token at proxy startup.
- Put the token in the approval URL path, for example
  `/approval/<session_token>/pending/<approval_id>`.
- On the first authenticated GET, set a `HttpOnly`, `SameSite=Strict`,
  loopback-only session cookie containing an HMAC over the session token and a
  server nonce.
- Every approve or deny POST must include the token path segment, the HMAC
  session cookie, and a per-form CSRF token.
- Rotate the session token on every proxy restart and whenever the local
  approval server is restarted. P6 may add an explicit `doctor` line that
  reports only whether an approval server token is active, never the token
  value.

Token delivery:

- Interactive `agentveil-mcp-proxy run` prints the loopback approval URL only
  when a pending approval exists or when the user asks for current pending
  approvals.
- Browser launch uses the full URL with token.
- The token is not written to the proxy config. If P7a stores a pending
  approval before UI render, it stores only a token hash.

Rationale:

Loopback binding prevents network access but does not defend against other
local processes. A path token makes accidental cross-process POSTs unlikely.
The HMAC cookie and CSRF token add browser-origin and form-submission binding
without requiring OS keychain support in v0.1.

Rejected alternatives:

- `127.0.0.1` isolation alone is insufficient; local malware or another local
  process can reach the loopback endpoint.
- A static config-file token is rejected because config files are copied,
  backed up, and reused across sessions.
- OS-keychain-bound sessions are deferred to later hardening because P5.7
  already keeps keychain integration out of the v0.1 path.

## Decision 2: Scope Expansion Semantics

Decision:

Default approval scope is risk-class dependent:

| Risk class | Default approval scope | Default expiry |
| --- | --- | --- |
| `destructive` | exact request only: server, tool, resource, payload hash, environment, request ID | 300 seconds |
| `production` | exact request only: server, tool, resource, payload hash, environment, request ID | 300 seconds |
| `financial` | exact request only: server, tool, resource, payload hash, environment, request ID | 300 seconds |
| `write` | server, tool, resource, environment, and payload hash by default; user may approve similar calls for 5 minutes only when policy allows it | 300 seconds exact, 300 seconds similar |
| `unknown` | exact request only unless policy explicitly maps it to `write` behavior | 300 seconds |
| `read` | approval should rarely be requested; if requested, exact request by default | 300 seconds |

User override:

- The UI may offer "approve similar for 5 minutes" only for `write` risk and
  only when local policy explicitly allows scope expansion for that rule.
- The UI must not offer broad session-wide approval for `destructive`,
  `production`, or `financial` actions.
- Scope expansion choices are evidence fields: requested scope, granted scope,
  expiry, risk class, matched policy rule, user decision timestamp, and token
  hash.

Rationale:

Approval should remove a specific block, not silently create a broad exception.
Risk-sensitive defaults prevent one click from authorizing a class of
high-impact actions.

Rejected alternatives:

- "Approve all actions this session" is rejected for v0.1 because it weakens
  the Action Gateway guarantee.
- Tool-name-only approval across all resources is rejected for `destructive`,
  `production`, and `financial` risk because resource is part of the safety
  boundary.

## Decision 3: Notification Escalation Chain

Decision:

Default notification chain:

1. Persist pending approval in the P7a approval store.
2. Print a CLI line with the sanitized approval URL and request summary.
3. Attempt to open the loopback browser URL.
4. Send an OS notification when enabled and available:
   macOS notification center, Windows Toast, or Linux `libnotify`/`notify-send`.
5. Continue serving the pending item in the web UI until approval timeout.
6. On timeout, deny by default and write timeout evidence.

Channel controls:

- Browser open is enabled by default in interactive sessions and disabled by
  default in headless mode.
- OS notifications are enabled by default only when the platform capability is
  detected. Users can disable them in config.
- CLI fallback is always enabled.
- Push to phone and email are out of scope for v0.1.

Behavior when no channel succeeds:

- The approval remains pending only until its configured timeout.
- The proxy returns a sanitized approval-required or timeout response to the MCP
  client when timeout is reached.
- No downstream action is forwarded unless a valid approval is recorded.

Rationale:

The CLI line is the reliable baseline. Browser and OS notification improve
operator ergonomics without changing safety behavior.

Rejected alternatives:

- Phone push and email are deferred because they require account-level routing,
  delivery guarantees, and additional consent/configuration.
- Silent background pending approvals are rejected because automation and IDE
  users need an observable reason for a blocked call.

## Decision 4: Multi-Pending Approval Correlation

Decision:

Default topology for v0.1 is one proxy process per MCP client configuration.
Each proxy process has its own local approval server token, local evidence
store, and downstream subprocess. Shared multi-client routing is out of scope
for v0.1.

Correlation fields shown in the approval UI:

- client identifier: configured `client.name` when present, otherwise process
  label plus PID;
- MCP client session ID generated at proxy startup;
- downstream server name;
- request timestamp;
- request ID;
- action breadcrumb: `server.tool`;
- resource display according to privacy config;
- risk class;
- payload hash prefix;
- matched policy rule ID when available.

When multiple proxy instances run side-by-side, the browser page title and OS
notification title include the client identifier and session ID suffix. The
approval URL includes only the local session token and approval ID; it does not
expose raw request arguments.

Rationale:

Per-process proxy ownership matches existing MCP client configuration patterns
and avoids a shared router before P9 concurrency work. Strong display
correlation prevents the user from approving the wrong pending item.

Rejected alternatives:

- Shared proxy with multi-client routing is deferred until the proxy has a
  tested client handshake and routing layer.
- Inferring the IDE name from process inspection is rejected as a security
  signal; explicit config or generated session labels are more reliable.

## Decision 5: Privacy Display Mode

Decision:

Approval UI defaults to a redacted summary:

- action display follows `privacy.action`;
- resource display follows `privacy.resource`;
- payload display is hash-only;
- raw MCP arguments, prompts, outputs, source code, secrets, tokens, and private
  logs are never shown by default.

The UI may include a "show local details" expansion only when local config
allows it. Even then, approval-time disclosure must never be more detailed than
what got logged in P5 backend metadata under the same privacy mode. If
`privacy.resource` is `hash`, the UI shows the resource hash and does not show
the raw resource. If `privacy.action` is `redacted`, the UI shows a redacted
action label plus risk class, not the raw action.

Rationale:

Screenshares, screenshots, and visible monitors are realistic leak paths.
Approval UX is part of the privacy boundary, not an exception to it.

Rejected alternatives:

- Always showing raw arguments is rejected because it violates the proxy privacy
  contract.
- A separate "UI privacy mode" is rejected for v0.1 because it can drift from
  backend metadata privacy. P6 must use the same privacy config.

## Decision 6: Headless And CI Mode

Decision:

Headless mode is explicit. It can be enabled with config or CLI flags:

- `--headless` disables browser launch and OS notification attempts.
- `--auto-deny` denies all approval-required actions after recording pending
  and denial evidence.
- `--headless-policy <path>` loads pre-approved exact scopes for automation.

Headless policy behavior:

- The file contains bounded exact or narrow scopes: server, tool, resource or
  resource hash, environment, risk class, and maximum expiry.
- Missing pre-approval means deny.
- Headless mode refuses to silently allow risky actions.
- `destructive`, `production`, and `financial` scopes require exact payload
  hash unless the policy rule explicitly allows a narrower non-payload match.

Rationale:

CI and scheduled jobs cannot wait for a browser prompt. They need deterministic
policy outcomes that remain deny-by-default.

Rejected alternatives:

- `--skip-approval-for destructive` style broad flags are rejected for v0.1.
- Hanging forever is rejected because CI systems need bounded failure.
- Silent allow on missing pre-approval is rejected because it breaks the Action
  Control Plane promise.

## Approval Persistence Requirements

Approval that doesn't survive a `kill -9` isn't an approval — it's a UI
suggestion. P6 implementation depends on P7a durable approval/evidence core
landing first.

Every approval record must be:

1. Scoped: specific bounded action including server, tool, resource,
   payload hash, environment, and time window.
2. Expiring: explicit `expires_at`, never indefinite, default 300 seconds and
   configurable per risk class.
3. Non-replayable: bound to specific request ID and payload hash.
4. Correlated to exact request hash: P4 `payload_hash` is part of the approval
   record.
5. Persisted before user sees it: durable WAL write happens before the UI
   renders the approval prompt.
6. Written back as evidence after approve or deny: decision, timestamp, and
   token hash are appended to the durable evidence log.

If P7a cannot persist the pending approval, P6 must not render an approval UI
that can authorize downstream execution. It must return a sanitized failure or
fall back according to policy.

## Out Of Scope For v0.1

- Phone push approvals.
- Email approvals.
- Federated team approval and multi-approver quorum.
- Web3 wallet approvals.
- Hosted shared approval portal for local MCP proxy instances.
- OS keychain-bound local approval sessions.
- Shared proxy routing across multiple IDE clients.
- Broad session-wide approval.

## P6 Implementation Acceptance Checklist

P6 implementation review must verify:

- local approval server binds only to `127.0.0.1`;
- approval URL requires per-session path token;
- POST requires path token, HMAC cookie, and CSRF token;
- token hash, not raw token, is stored in durable evidence;
- pending approval is written durably before UI render;
- approve, deny, and timeout outcomes append evidence;
- `destructive`, `production`, and `financial` approvals default to exact
  request scope;
- optional `write` scope expansion is policy-gated and captured in evidence;
- UI shows client identifier, session ID, request timestamp, action breadcrumb,
  privacy-filtered resource, risk class, payload hash prefix, and policy rule;
- approval UI never shows more detail than the configured backend metadata
  privacy mode permits;
- CLI fallback is always available;
- headless mode is deny-by-default and never silently allows risky actions;
- P6 does not implement backend approval semantics inside MCP-specific code;
- no downstream execution occurs for approval-required calls without a valid
  durable approval.

## Deferred Questions

- Which OS notification implementation should become the first-class packaged
  path per platform.
- Whether a later shared proxy should support explicit MCP client handshake and
  multi-client routing.
- Whether enterprise deployments should bind local approval sessions to OS
  keychain-backed credentials.
- Whether teams need quorum approval or delegated approver roles.
