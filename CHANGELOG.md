# Changelog

All notable changes to the `agentveil` SDK.

## [Unreleased]

No unreleased changes.

## [0.7.20] - 2026-06-01

Verifier-readiness release for `execution_receipt/3` and
`human_approval_receipt/3`. `agentveil.proof.verify_proof_packet` now accepts
the full `/3` receipt family (decision, execution, human approval) routed
through the first-party data-integrity (`eddsa-jcs-2022`) hashData verifier.
<!-- claim-check: allow release note names the implemented local verifier path, not third-party certification -->
This is not a third-party conformance certification.

### Added
- Added `execution_receipt/3` and `human_approval_receipt/3` to the
  data-integrity verifier routing set alongside `decision_receipt/3`.
- Added `_STRICT_EXECUTION_SCHEMAS` and `_STRICT_APPROVAL_SCHEMAS` so `/3`
  inherits `/2` strictness for shared intent fields and `decision_receipt_hash`
  mandatory-field checks.
- Added focused tests covering happy path, tamper rejection, role separation,
  missing/mismatched `decision_receipt_hash`, missing/mismatched shared intent
  fields, `proofPurpose` stripped/changed, and proof `@context` mismatch for
  both new receipt families.

### Unchanged
- Legacy `/1` and `/2` receipt verification stays on the raw-JCS path
  (`verify_signed_jcs`).
- `decision_receipt/3` verification behavior is unchanged from 0.7.19.

## [0.7.19] - 2026-05-31

PyPI package alignment release for the MCP Proxy split.

The public `agentveil` package is released as `0.7.19` because `agentveil==0.7.18`
already exists on PyPI and cannot be overwritten. This release publishes the
SDK code required by the separately packaged MCP Proxy, including the
`agentveil.data_integrity` verifier module used by proxy receipt verification.

The first public `agentveil-mcp-proxy` package is also versioned `0.7.19` and
depends on `agentveil>=0.7.19,<0.8`. New proxy installs remain one command:
`pip install agentveil-mcp-proxy`.

## [0.7.18] - 2026-05-28

MCP Proxy and proof verification hardening release. This release closes the
0.7.17 approval-required stdio gap, moves the MCP Proxy into a separate
source-available package, and tightens proof/evidence verification defaults.

The root `agentveil` package still contains the public SDK, hosted MCP server,
and Paperclip helper. The MCP Proxy is now packaged separately as
`agentveil-mcp-proxy` under the Business Source License 1.1.

### Added
- Added `decision_receipt/3` signing and verification helpers. The SDK verifies
  `/3` through its first-party Data Integrity verifier; this is not a
  third-party conformance certification.
- Added `decision_receipt/3` support to `verify_proof_packet` while preserving
  legacy `/1` and `/2` raw-JCS receipt verification paths.
- Added `--json` support to `agentveil-mcp-proxy register`.
- Added an MCP Proxy release acceptance runner that builds or consumes a wheel,
  installs it into a clean virtualenv, drives the quickstart filesystem MCP
  server through the proxy, approves a risky action through the loopback UI,
  retries the action, and verifies events/evidence export.
- Added a declared tool-surface configuration for MCP Proxy
  (`tool_surface.mode = off | observe | enforce`) with an operator-managed
  allowlist.
- Added a separate `agentveil-mcp-proxy` package under
  `packages/agentveil-mcp-proxy/`. The `agentveil-mcp-proxy` console command is
  preserved.

### Changed
- `verify_evidence_bundle` / `verify_evidence_bundle_file` now default to
  strict verification (`strict=True`). Proof-grade verification requires
  externally pinned signer DIDs.
- In proof-grade mode a receipt-bearing bundle requires externally pinned
  `trusted_signer_dids`; the bundle's embedded signer list is not an accepted
  trust anchor, and a referenced-but-missing signed receipt fails closed.
- `decision_receipt/1` and `/2` remain explicit legacy raw-JCS verification
  paths. The historical self-asserted in-bundle-trust behavior is available
  only via `strict=False` / `verify_evidence_bundle_legacy(...)` and is not
  proof-grade.
- Corrected Microsoft AGT / AgentMesh docs wording so `AVPProvider` remains
  named while AgentVeil is described as an external trust and reputation
  integration.
- Changed MCP Proxy approval-required stdio calls to return an immediate
  structured `approval_required` response with the local evidence record ID and
  approval URL instead of holding the MCP request open until timeout.
- Approved exact local approval records now authorize one identical retry, so
  clients can complete the approved MCP tool call after the user approves it in
  the local browser approval UI.
- Changed the default Runtime Gate unavailable fallback for read-class tool
  calls from `allow` to `approval`. Operators may still explicitly configure
  `read = "allow"` as an opt-in risk decision.
- Changed `similar_5m` approval reuse so it requires an extracted
  `resource_hash`. Calls without a resource binding require a fresh approval.
- Changed the MCP Proxy packaging split: root `agentveil` wheels no longer ship
  the proxy package or the `agentveil-mcp-proxy` console entry point. Install
  the proxy with `pip install agentveil-mcp-proxy`; it installs the core
  `agentveil` SDK as a dependency.
- Documented the MCP Proxy release acceptance procedure as a release gate for
  serious MCP Proxy setup, passthrough, approval, evidence, and Runtime Gate
  changes.

### Fixed
- Fixed MCP Proxy argument validation so tool-call arguments are checked before
  approval when the downstream tool schema is available.
- Fixed classifier exception handling so a classifier failure on `tools/call`
  fails closed instead of forwarding without policy or Runtime Gate evaluation.
- Fixed unsafe filesystem tool paths so path traversal and secret-like file
  reads are rejected before approval and downstream forwarding.
- Fixed the Runtime Gate unavailable fallback path so the default read-class
  behavior is approval-required rather than silent allow.
- Fixed the `ASK_BACKEND` library-embed path without a Runtime Gate factory so
  it fails closed with `runtime_gate_not_configured` instead of forwarding.

### Notes
- The GitHub release workflow still publishes the root `agentveil` package
  only. Publishing the separate `agentveil-mcp-proxy` package requires a
  separate release/publishing decision.
- The `agentveil-mcp-proxy` source is visible under
  `packages/agentveil-mcp-proxy/` and is licensed separately from the root SDK.

## [0.7.17] - 2026-05-28

MCP Proxy first-run repair release. The published `0.7.16` wheel did not
include the newer `register` and `doctor --check-backend` CLI path that the
GitHub docs described; this patch version is the releasable package state for
that customer path plus local downstream/operator visibility helpers.

### Added
- Added `agentveil-mcp-proxy configure-downstream` to write downstream MCP
  server config without manual JSON edits, plus the preferred
  `agentveil-mcp-proxy downstream set` command spelling.
- Added `agentveil-mcp-proxy init --quickstart-filesystem <path>` with a
  built-in sandboxed filesystem downstream for zero-dependency local smoke
  testing.
- Added `agentveil-mcp-proxy doctor --full` and `agentveil-mcp-proxy smoke` to
  launch the configured downstream and verify MCP `initialize` / `tools/list`.
- Added privacy-safe `events list`, `events tail`, and `evidence-summary`
  operator views.
- Added JSON output for non-interactive setup and checks (`init`, downstream
  setup, `doctor`, `smoke`, and event views).

### Changed
- Updated MCP Proxy quickstart docs with Ubuntu packaging prerequisites,
  virtualenv install commands, downstream helper usage, full doctor/smoke
  checks, JSON output, and the new event views.

## [0.7.16] - 2026-05-26

Paperclip MCP integration helper release. Adds read-only local helper commands
for operators who route Paperclip-managed Claude/Codex tool calls through the
AgentVeil MCP proxy.

### Added
- Added `agentveil paperclip doctor` and `agentveil-paperclip doctor` for
  read-only local readiness checks covering the AgentVeil MCP proxy and local
  Claude/Codex runtime configuration presence.
- Added `agentveil paperclip init --dry-run` and
  `agentveil-paperclip init --dry-run` for a non-mutating setup preview. Plain
  `init` remains refused in this release.
- Added privacy-by-default redaction of local filesystem paths in Paperclip
  helper output, with `--show-paths` as an explicit local diagnostic opt-in.

### Changed
- Added a Paperclip integration guide documenting the MCP-routed action
  boundary, the read-only helpers, and current sandbox/remote limitations.

## [0.7.15] - 2026-05-12

Post-launch polish release: discoverability fixes for the v0.1 MCP Proxy
adapter and Tier 1 differentiator framing per the AgentVeil design principles
roadmap. Zero production code changes; documentation, metadata, and design
narrative only.

### Changed
- Bumped PyPI `Development Status` classifier from `4 - Beta` to
  `5 - Production/Stable` to match the project's commercial-bar discipline.
- Surfaced the `agentveil-mcp-proxy` MCP transport proxy adapter in the
  top-level `README.md` integrations table alongside framework adapters,
  Bedrock, and Microsoft AgentMesh.
- Surfaced the MCP transport proxy in `README_PYPI.md` features list and
  added a dedicated section with quick-start commands and a link to the
  subproject README.
- Added `mcp-proxy` keyword to `pyproject.toml` for PyPI search discovery.
- Reframed customer-facing authorization narrative as capability tokens
  (signed, scoped, time-bounded, replay-resistant, attenuatable) per Mark
  Miller (2006) and Macaroons (NDSS 2014) discipline. AVP's existing
  `similar_5m` scope expansion already implements these properties; this
  release names them explicitly.
- Adjusted customer copy to acknowledge HRU 1976 undecidability of the general
  access-control safety problem. AVP claims constrained, auditable, reversible
  decisions within the practically decidable policy subset, not unconditional
  safety.
- Updated public repository URL references in `README.md`, `README_PYPI.md`,
  `pyproject.toml`, `AGENTS.md`, and `agentveil_mcp/server.py`, and refreshed
  customer-facing example paths in `agentveil_mcp/README.md`,
  `examples/proof_pack/README.md`, and `mcp_server/README.md` from `avp-sdk`
  to `agentveil-sdk` after the GitHub repository rename for brand consistency
  with the `agentveil` PyPI package name. Operator-local
  `/Users/.../avp-sdk-public` release-smoke paths remain unchanged.
- Added an MCP transport proxy "what's new" callout to the top-level
  `README.md` hero section surfacing the v0.7.15 ship and IDE client coverage
  without disrupting the AVP product-led hero tagline.

### Added
- New design principles document at
  [`docs/MCP_PROXY_DESIGN_PRINCIPLES.md`](docs/MCP_PROXY_DESIGN_PRINCIPLES.md)
  mapping AgentVeil MCP Proxy architecture to the eight Saltzer-Schroeder
  (1975) principles: economy of mechanism, fail-safe defaults, complete
  mediation, open design, separation of privilege, least privilege, least
  common mechanism, and psychological acceptability.

### Audit References
- Discoverability fixes: PL-1, PL-2, PL-3, PL-4, caught reviewer-side after
  the P11.5 ceremony.
- Differentiator items: #1 Saltzer-Schroeder citation, #2 HRU honest framing,
  #3 capability discipline reframing - Tier 1 free items from
  `avp_mcp_proxy_differentiators_roadmap.md`.

### Validation
- No production code changes. Pytest baseline unchanged: 642 passed, 1 skipped.
- Bandit static analysis unchanged: 6 LOW, 0 MEDIUM, 0 HIGH.
- All refined customer-facing wording scans (AI-attribution, prohibited
  product terminology, production-grade strict reading) return zero matches
  post-edit.

## [0.7.14] - 2026-05-11

AgentVeil MCP Proxy v0.1 first public release. Action Control Plane for IDE
MCP clients wrapping downstream MCP servers with runtime decision gating,
human approval routing, durable signed evidence, and replay defense.

### Added
- Added the `agentveil-mcp-proxy` console script and
  `python -m agentveil_mcp_proxy` entry point for MCP transport proxy
  operation.
- Added encrypted local proxy identity storage with Argon2id and SecretBox,
  passphrase-file support, `AVP_PROXY_PASSPHRASE`, a 12-character minimum for
  new identities, and documented passphrase-source trade-offs.
- Added Runtime Gate integration with DecisionReceipt verification, schema
  enforcement, audit ID binding, payload hash binding, risk class binding,
  policy context hash binding, and circuit breaker handling.
- Added a local TTL-capped DecisionReceipt replay cache as a v0.1 compensating
  control before the backend nonce/freshness protocol update.
- Added the loopback browser approval server with CSRF checks, HMAC cookies,
  per-prompt tokens, Content-Length bounds, socket timeouts, and
  `ThreadingHTTPServer`.
- Added a durable SQLite evidence store with WAL mode, hash chaining, fsync
  durability, owner-only permissions, and auxiliary WAL/SHM permission
  hardening after commits.
- Added offline evidence bundle export and verification covering chain
  integrity, signed receipt validation, receipt binding checks, audit ID
  matching, and receipt-reference dedupe.
- Added headless approval mode and bounded headless policy support with
  owner-only policy-file validation.
- Added built-in policy packs for `default`, `github`, `filesystem`, and
  `shell`, including broadened destructive coverage for `purge_*`,
  `truncate_*`, `wipe_*`, `format_*`, `rm`, `rmdir_*`, `unlink_*`, and
  `clean_*` patterns where applicable.
- Expanded destructive classification prefixes with `purge`, `truncate`,
  `wipe`, `format`, `rm`, `rmdir`, `unlink`, and `clean`.
- Added cross-platform CI coverage across 3 operating systems and 4 Python
  versions, workflow dispatch support, pinned GitHub Actions SHAs, and
  `permissions: contents: read`.
- Added `env_passthrough` blocking for the reserved `AVP_*` prefix so proxy
  secrets cannot be forwarded to downstream MCP servers by configuration.
- Added the MCP Proxy subproject README and the operations guide at
  `docs/MCP_PROXY_OPERATIONS.md`.

### Security
- Completed the P10.5 security audit remediation train: 12 MEDIUM and 8 LOW
  findings were identified across independent passes; 10 MEDIUM findings were
  closed in P10.6-P10.10, M-2 received the local replay-cache mitigation, and
  M-10 was deferred to v0.1.1.
- Completed the post-P10.9 mid-train audit: 2 MEDIUM and 3 LOW findings were
  identified; MT-1, MT-2, and MT-3 were closed in P10.10, while MT-4 and MT-5
  were accepted as v0.1 LOW risk.
- Annotated the 14-site Bandit B608 SQL false-positive cluster with narrow
  `# nosec B608` rationale comments.
- Verified public documentation surfaces for attribution wording and prohibited
  product terminology.
- Added receipt `audit_id` cross-checking and duplicate receipt-reference
  rejection to the offline verifier.
- Added positive-value validation for RuntimeGateClient replay-cache settings.
- Hardened CLI identity, config, and grant writes with file fsync and parent
  directory fsync.
- Added a 1 MiB client-to-proxy JSON-RPC line cap matching the downstream
  message cap.
- Bounded downstream response bookkeeping with in-flight ID tracking,
  TTL-pruned timed-out IDs, unsolicited-response counting, and retained
  response caps.
- Required DecisionReceipt schema, audit ID, and receipt binding fields in
  offline evidence verification.

### Known Limitations
- **Backend protocol nonce/freshness:** the local replay cache mitigates
  same-process replays within a five-minute window. The v0.1.1 protocol update
  adds backend-issued nonce plus `issued_at` and `expires_at` fields to a new
  `decision_receipt/3` schema. Same-intent replays across proxy restarts and
  against a compromised backend response channel remain possible in v0.1.
- **Windows Job Object race:** Windows downstream process containment has a
  narrow `start()` window where a child process can spawn descendants before
  assignment to the Job Object. Use an external Windows service supervisor for
  production Windows deployments until the v0.1.1 fix lands.
- **OS keychain identity storage:** v0.1 uses passphrase-encrypted Argon2id
  identity files. v0.1.1+ adds opt-in macOS Keychain, Linux Secret Service, and
  Windows Credential Manager integration.
- **P7a WAL/SHM creation-window race:** the evidence store chmods auxiliary
  SQLite files after every commit; a small in-flight transaction window still
  depends on the user umask. Accepted as v0.1 LOW risk.
- **P7b runtime-only chain validation:** chain integrity is validated at store
  open and after write transactions; there is no periodic background chain
  validation during a long-running proxy. Periodic restarts are the v0.1
  mitigation.
- **MT-4 receipt cache eviction under sustained burst:** sustained high-volume
  legitimate receipts can evict captured receipts before the nominal TTL,
  weakening local replay defense in adversarial timing scenarios. The v0.1.1
  protocol nonce/freshness fix supersedes this mitigation.
- **MT-5 `granted_by_request_id` reference validation:** the verifier does not
  dereference cache-hit `granted_by_request_id` values to prove the referenced
  record exists in the same bundle. Manual auditors should cross-check those
  references when reviewing cache-hit evidence.

### Audit References
- Closed P10.5-security findings: M-1, M-3, M-4, M-5, M-6, M-7, M-8, M-9.a,
  M-9.b, M-11, M-12, L-1, L-2, L-3, Codex MEDIUM-1, Codex LOW-2, and
  Codex LOW-3.
- Closed mid-train audit findings: MT-1, MT-2, and MT-3.
- Partial mitigation: M-2 local replay cache; full protocol fix deferred to
  v0.1.1.
- Deferred v0.1.1: M-2 and M-10.
- Accepted as v0.1 LOW risk: MT-4, MT-5, P7a residual, and L-4 through L-8.
- Commits: `0e6583c` (P10.6), `5c14f37` (P10.7), `5a89148` (P10.8),
  `de43147` (P10.9), `3577e4b` (P10.10), and `bddf600` (P10.11).

### Validation
- P11 release gate passed: main CI matrix green on 12/12 cells, full local
  pytest passed with `642 passed, 1 skipped`, Bandit reported 0 HIGH and
  0 MEDIUM findings, pip-audit reported 0 known vulnerabilities, public-surface
  wording scans passed, console scripts worked, build artifacts included the
  MCP Proxy README, and license/security metadata was verified.

## [0.7.13] - 2026-05-08

Fresh release for the MCP action-control toolbox expansion.

### Added
- Added 8 local/full `agentveil-mcp` action-control tools:
  `runtime_evaluate_action`, `controlled_action`, `get_approval_request`,
  `approve_action`, `deny_action`, `execute_after_approval`,
  `get_decision_receipt`, and `get_execution_receipt`.

### Changed
- Updated MCP docs and instructions to position the server as an explicit
  action-control toolbox for Runtime Gate, approval, and signed receipt
  workflows. Local/full mode now exposes 20 tools; hosted read-only mode
  remains at 8 tools.
- Refreshed Glama metadata, roadmap, PyPI README, skill instructions, and MCP
  integration examples so public-facing descriptions match the 20-tool
  local/full MCP surface.

### Validation
- MCP-1 production live smoke passed against `https://agentveil.dev`, covering
  full/readonly tool registration, Runtime Gate evaluation, controlled action
  allow/wait/block outcomes, approval get/approve/deny, approved execution,
  and DecisionReceipt / ExecutionReceipt fetches with sha256 verification.
- `python -m pytest tests/test_mcp_hosted.py tests/test_mcp_packaging.py -q`
  passed with `36 passed`.
- `python -m pytest -q` passed with `262 passed, 1 warning`.

## [0.7.12] - 2026-05-08

Self-service developer adoption: Proof Packet export helper, corrected
approval payload references, Live Developer Adoption Smoke evidence path, and
Mode A onboarding docs.

### Added
- Added `AVPAgent.get_decision_receipt(audit_id: str) -> str` so customers can
  fetch exact signed Runtime Gate DecisionReceipt JSON text and pass it into
  `build_proof_packet(...)` without parsing and re-serializing the signed
  bytes. See `docs/PROOF_PACKET.md` and `docs/API.md`.
- Added the production release-gate smoke
  `examples/live_developer_adoption_smoke.py` with
  `docs/LIVE_DEVELOPER_ADOPTION_SMOKE.md`. It validates the self-service path
  against `https://agentveil.dev`: DelegationReceipt issue/verify, all three
  Runtime Gate outcomes, approval resume, Proof Packet export, strict offline
  verification, and typed SDK errors.
- Added Mode A and advanced network onboarding docs:
  `docs/MODE_A_QUICKSTART.md` for the Project Owner path and
  `docs/ADVANCED_AGENT_NETWORK.md` for reputation, attestations, DID identity,
  and W3C VC primitives.

### Fixed
- Corrected approval-required snippets, docs, examples, and mocks to use
  `outcome.approval["approval_id"]`, matching the production payload. Previous
  docs used either `outcome.approval_id` (not populated on the initial
  `approval_required` outcome) or `outcome.approval["id"]` from mock-only
  examples. See `docs/APPROVAL_ROUTING.md`,
  `docs/CUSTOMER_INTEGRATION.md`, and `examples/approval_flow.py`.
- Corrected the README `attest_batch(...)` example so the negative attestation
  includes both `context` and a 64-character lowercase hex `evidence_hash`.
  The `# 3, 0` success/failure comment now matches the server contract.

### Changed
- Linked the new release smoke from the README documentation table and
  cross-linked the Proof Packet, approval, registration, delegation, and error
  guides so the self-service flow has a complete evidence path.
- Repositioned the public docs around the primary action-control path while
  keeping advanced agent-network primitives discoverable for customers who need
  reputation, attestations, or credential workflows.

### Validation
- Live Developer Adoption Smoke passed against production `agentveil.dev` with
  strict trusted signer DID verification.
- `python -m pytest -q` passed with `256 passed, 1 warning`.

## [0.7.11] — 2026-05-08

### Changed
- Reframed PyPI metadata around action-control positioning:
  - `pyproject.toml` description now leads with posture checks, action gates,
    signed receipts, and proof packets instead of identity-first phrasing.
  - `README_PYPI.md` Quick Start now uses `issue_delegation_receipt(...)` and
    `verify_delegation_receipt(...)`, matching the main README action-control
    lead.

No functional SDK changes. `agentveil.__version__` was updated to match the
wheel metadata. Same API surface as 0.7.10.

### Validation
- `python3 -m build` passed.
- `python3 -m twine check` passed for the built wheel and sdist.
- `python3 -m pytest -q` passed with `236 passed, 19 skipped, 1 warning`.
- PyPI Quick Start snippet verified in a clean venv: `delegation valid: True`,
  `scope: deploy`.

## [0.7.10] — 2026-05-07

### Changed
- Added a PyPI-specific project description with absolute links and no embedded
  GitHub-relative images, so the PyPI project page renders cleanly.
- Polished the GitHub README hero with the AgentVeil logo, centered product
  heading, compact badges, and simplified quick links.

### Validation
- `python3 -m build --outdir /tmp/avp-0710-build` passed.
- `python3 -m twine check` passed for the built wheel and sdist.
- `python3 -m pytest -q` passed with `236 passed, 19 skipped`.

## [0.7.7] — 2026-05-06

### Changed
- Aligned public API docs, security notes, roadmap, skill instructions, and
  examples around AgentVeil action control: Runtime Gate, signed receipts,
  advisory reputation APIs, and MCP profile/audit surfaces.
- Updated MCP server instructions and Docker entrypoints to use the
  `agentveil-mcp` console command and clarify the SDK Runtime Gate path for
  risky action execution.
- Updated the quickstart and wheel verification examples to run against the
  current package metadata without requiring a live backend.
- Replaced the default DelegationReceipt purpose text with neutral
  controlled-action wording.
- Made the PyPI publish workflow idempotent when artifacts already exist.

### Validation
- `PYTHONPATH=. pytest tests/test_delegation_issuance.py tests/test_controlled_action.py -q`
  passed.
- `PYTHONPATH=. python3 examples/quickstart.py` passed.

## [0.7.6] — 2026-05-06

### Changed
- Reframed the public README around AgentVeil action control: local smoke test,
  production integration shape, Runtime Gate, approvals, signed receipts, and
  controlled-action proof packets.
- Moved advisory reputation APIs into a dedicated reference section while
  keeping existing `can_trust(...)`, `@avp_tracked(...)`, and framework tool
  documentation discoverable.
- Updated Features, Security, Proof Pack, and Integrations copy to reduce
  overclaims and match the current SDK/API surface.
- Added Gemini and PydanticAI examples to the integrations table.
- Updated PyPI metadata keywords for action-control, runtime-gate,
  controlled-actions, and signed-receipts positioning.
- Clarified the Microsoft Agent Governance Toolkit / AgentMesh integration and
  softened the Glama directory label while retaining the verified listing.

### Validation
- README local/mock snippets pass from a clean editable install.
- Markdown/link sanity checks passed for README tables, fences, and local docs
  links.
- `agentmesh-avp==0.1.1` verified to export `AVPProvider`; README avoids an
  unverified `TrustEngine(...)` constructor claim.

## [0.7.5] — 2026-05-05

### Changed
- `AVPAgent.get_onboarding_challenge()` now signs the owner-only onboarding
  challenge GET request automatically with AVP-Sig. This keeps SDK onboarding
  helpers compatible with the backend onboarding privacy tightening where
  challenge details are no longer public.
- `auto_answer_onboarding_challenge()` inherits the signed challenge fetch
  because it delegates to `get_onboarding_challenge()`.

### Required action
- Upgrade before using this SDK with backend deployments where
  `GET /v1/onboarding/{did}/challenge` is owner-only. Older SDK versions may
  receive `401` from `get_onboarding_challenge()` after that backend change.

## [0.7.4] — 2026-04-30

### Added
- `verify_signed_jcs(...)` for offline DataIntegrityProof /
  `eddsa-jcs-2022` signature verification of signed JCS proof artifacts.
- `verify_proof_packet(...)` for AVP-level semantic verification of
  DelegationReceipt, DecisionReceipt, HumanApprovalReceipt, and
  ExecutionReceipt proof chains.
- Role-specific trusted signer DID configuration for DecisionReceipt,
  ExecutionReceipt, and HumanApprovalReceipt verification.
- Optional `decision_receipt_jcs` support in `ProofPacket` and
  `AVPAgent.build_proof_packet(...)`.

### Changed
- Customer integration docs now include an offline proof verification recipe,
  receipt schema/version matrix, and trust-anchor guidance.

## [0.7.3] — 2026-04-30

### Added
- `ProofPacket` typed result object and `AVPAgent.build_proof_packet(...)` for
  bundling explicit controlled-action proof artifacts while preserving raw
  signed receipt strings.
- `AVPAgent.issue_delegation_receipt(...)` and
  `AVPAgent.verify_delegation_receipt(...)` ergonomic wrappers around the
  existing DelegationReceipt v1 issue/verify primitives.
- `docs/PILOT_READINESS_CHECKLIST.md` for guided first customer integrations.

### Changed
- `AVPAgent.integration_preflight()` now distinguishes `agent_revoked`,
  `agent_migrated`, and `nonce_replay` setup/auth states.
- Customer integration docs now clarify that DelegationReceipt v1 covers
  current backend-enforced category and financial predicates, while requested
  action, resource, and environment are supplied to Runtime Gate and
  cross-checked there.
- `pyproject.toml` now uses SPDX license metadata syntax: `license = "MIT"`.

## [0.7.2] — 2026-04-29

### Added
- `AVPAgent.integration_preflight()` for safe customer integration checks before
  the first controlled action. The helper verifies local identity loading,
  API reachability, public agent registration/verification state, and a signed
  read path without mutating backend state.
- Typed `IntegrationPreflightReport` with customer-clear statuses such as
  `ready`, `unregistered`, `signature_invalid`, `unverified_or_forbidden`,
  `agent_suspended`, `rate_limited`, and `backend_or_config_unavailable`.
- `examples/first_controlled_action.py` template for the first preflight-gated
  controlled action with explicit DelegationReceipt handoff.

### Changed
- Signed SDK requests with non-empty query parameters now emit AVP-Sig v2,
  binding a canonicalized query string into the Ed25519 signature.
- Signed requests without query parameters remain AVP-Sig v1 during the
  backend compatibility window.

### Validation
- Production backend v2 acceptance was deployed before this SDK release
  candidate.
- Production smoke against `https://agentveil.dev` passed with
  `integration_preflight()` ready and signed v2 remediation case discovery.

### Known limitations
- AVP-Sig v1 query-bearing requests remain accepted by the backend during the
  migration window and are warning-logged until a future sunset.

## [0.7.1] — 2026-04-29

### Changed
- Reworded public controlled-action documentation and release notes to use
  clear customer-facing integration language.

## [0.7.0] — 2026-04-29

### Added — Controlled-action integration
- Runtime Control wrappers for `runtime_evaluate()`,
  `get_runtime_decision()`, `execute()`, and `get_execution_receipt()`.
- Human Approval wrappers for `create_approval()`, `get_approval()`,
  `approve()`, and `deny()`.
- Governance and Remediation wrappers for policy/risk-event/case flows.
- High-level `controlled_action()` orchestration and
  `execute_after_approval()` resume path.
- Typed `ControlledActionOutcome` result object with attribute access,
  light dict-style compatibility, and `to_dict()`.
- `docs/CUSTOMER_INTEGRATION.md` covering secrets, first controlled action,
  approval resume, error map, and compliance packet.

### Changed
- HTTP response handling now accepts both `200` and `201` success
  responses.
- Signed execution and approval receipt endpoints preserve exact raw JSON
  text for offline proof instead of parsing and re-serializing.
- `429` handling now parses `Retry-After` defensively.

### Validation
- Production API smoke passed against `https://agentveil.dev` on
  2026-04-29 using a signed read path and safe `runtime_evaluate()`
  for `infra.resource.inspect`.

### Known limitations
- AVP-Sig v1 still signs the path without query-string binding to match
  the deployed backend protocol. This is tracked for a future coordinated
  AVP-Sig v2 backend + SDK rollout.
- `controlled_action()` does not auto-approve human-control decisions.
  Callers must resume with `execute_after_approval()` after principal
  approval.

## [0.6.2] — 2026-04-27

### Added — DelegationReceipt primitive
- New `agentveil.delegation` module shipping a minimal AVP runtime-
  control primitive: a W3C Verifiable Credential v2.0 receipt that
  records who authorized which agent to act, within what scope, and
  for how long.
- `issue_delegation()` signs a receipt with the principal's Ed25519
  `did:key`. Scope predicates supported in v1: `max_spend`
  (ISO 4217 currency + amount) and `allowed_category` (string value).
  Validity is bounded by `validFrom` / `validUntil`. Receipts are
  canonicalized with RFC 8785 JCS before signing.
- `verify_delegation()` performs offline verification: structure
  checks, expiration window, scope-predicate validation,
  `eddsa-jcs-2022` Data Integrity Proof. No network calls, no
  AVP backend dependency.
- Standalone reference verifier (~180 lines, only `pynacl` /
  `base58` / `jcs` dependencies, no `agentveil` SDK import) at
  `examples/delegation/verify.py` — auditors can read and run it
  without trusting the SDK.
- JSON-LD context pinned at `https://agentveil.dev/contexts/delegation/v1.jsonld`.

### Schema stability
- `DelegationReceipt` v1 wire format is intended to be stable. Future
  extensions add new optional predicates rather than alter existing
  ones — anything else would invalidate already-signed receipts.

### Not changed
- All existing reputation, attestation, registration, MCP, and
  webhook-alert surfaces are untouched.

## [0.6.1] — 2026-04-23

### Added (B3 — negative attestation DX)
- `AVPAgent.attest()` now raises `AVPValidationError` client-side when
  `outcome="negative"` is passed without both `context` and a valid SHA-256
  `evidence_hash` (64 lowercase hex chars). Mirrors the server-side
  requirement in `app/api/v1/attestations.py` so callers fail fast with a
  clear message instead of chasing a 400 from the server.
- Same validation added to `AVPMockAgent.attest()` so mock-mode code paths
  surface the issue before hitting a real backend.
- Docstring updated to mark `context` and `evidence_hash` as REQUIRED for
  negative outcomes.

### Added (B9 partial — explainability for starter floor)
- `ReputationResponse` and `TrustCheckResponse` now expose explicit
  `raw_score`, `display_score`, `floor_applied: bool`, `floor_reason` fields.
- `TrustCheckResponse.reason` includes a human-readable `[starter floor
  applied …]` suffix when applicable.
- `docs/PROTOCOL.md` now has a "Starter Floor Semantics" section.

### Known limitation
- `raw_score` is `null` whenever the starter floor is applied. The backend
  currently stores only the gated score, so the pre-floor signal is not
  recoverable after the fact. `floor_applied = true` is the truthful signal;
  `raw_score` exposure requires a DB migration tracked separately.

### Not changed
- Reputation computation, decision logic, `allowed` / `tier` / `risk_level`
  semantics, and the single source-of-truth (`get_latest_score`).

## [0.6.0] — 2026-04-23

### Changed (behavior change — not backward compatible)
- `register()` no longer blocks on onboarding completion. Onboarding runs
  server-side in the background after `/verify`; the call returns as soon as
  the agent is verified. Prior versions implicitly waited up to ~30s for an
  LLM-driven onboarding challenge and auto-answered it.
- `register()` return dict now includes `onboarding_pending: bool` so callers
  can branch without polling.

### Added
- `auto_answer_onboarding_challenge(max_wait=30.0)` — explicit, opt-in helper
  that reproduces the pre-v0.6.0 behavior (poll challenge, auto-submit a stock
  answer). Returns the challenge result dict or `None`.
- `wait_for_onboarding(timeout=60.0, poll_interval=2.0)` — explicit helper that
  blocks until onboarding reaches a terminal state (`completed` / `failed` /
  `not_started`). Raises `TimeoutError` on timeout.
- Structured `challenge_expired` handling: backend now returns `409` with
  `fresh_challenge` / `fresh_pow_challenge` / `fresh_pow_difficulty` in the
  error body so clients can retry `/verify` without a new `/register` call.

### Deprecated
- `_auto_handle_onboarding_challenge()` — retained as an internal alias for
  one release. New code must use `auto_answer_onboarding_challenge()`.

### Migration
- If you relied on the implicit onboarding wait inside `register()`, add an
  explicit call to `agent.auto_answer_onboarding_challenge()` and/or
  `agent.wait_for_onboarding()` after `register()`.
- If you only care about registration being verified, no code change is
  needed — `register()` now just returns faster.

### Onboarding state semantics (explicit)
`GET /v1/onboarding/{did}` — exact states returned:
- Unknown DID → HTTP 404 "Agent not found".
- Agent exists but `/verify` has not run yet (post-register, pre-verify) →
  200 with `status="not_started"`. Synthetic response (no session row yet).
- Agent verified, no card published, session waiting → 200 with
  `status="pending"` (session row created at verify; pipeline idle).
- Agent verified, card present, background pipeline running → 200 with
  `status="in_progress"` + `current_stage`.
- Terminal states → `status="completed"` or `status="failed"`.

The `not_started` window is narrow (between `/register` and `/verify`) but
real. Clients must treat `status` — not HTTP code — as the source of truth
for onboarding lifecycle.

### Performance note
Latency numbers observed in local validation (register ~0.2s, 5 agents
sequential ~1.4s total) were measured with `POW_DIFFICULTY_BITS=18` — the
documented **development override**. Production default remains **28 bits**;
real client-side PoW solve adds 10-150s on single-threaded CPUs depending
on hardware. What v0.6.0 fixes is the **hidden onboarding-wait block**, not
PoW latency. The two are independent; PoW ergonomics are tracked separately.

## [0.5.8] — 2026-04-22

### Changed
- README: replaced Glama MCP Directory image badge with a plain text link.
  The badge rendered the current Glama quality score ("not tested") which
  looked weak on the PyPI package page. The directory listing is still
  linked, just without the score card image.

### Notes
- No runtime, API, or behavior changes. Pure README/package-metadata update.

## [0.5.7] — 2026-04-17

### Fixed
- `_auto_handle_challenge` no longer blocks the event loop when called from an
  async context. Polling work is now offloaded to a daemon thread
  (`avp-challenge-{name}`); sync callers behave exactly as before.

> Note: versions 0.5.3–0.5.6 were published to PyPI without changelog entries.
> See git history for what changed in those releases.

## [0.5.2] — 2026-04-09

### Added
- `can_trust()` method — advisory trust decision (score + tier + risk + explanation)
- Connects to `GET /v1/reputation/{did}/trust-check` endpoint

## [0.5.1] — 2026-04-09

### Fixed
- Decorator 409 handling — verify actual state from server before retry
- 3 critical SDK bugs: credential field mismatch, version sync, async blocking

### Changed
- Documentation updates for accuracy

## [0.5.0] — 2026-04-08

### Added
- Webhook alerts: `set_alert()`, `alert_url` param in `@avp_tracked`, `AVP_ALERT_URL` env var
- Auto-subscribe to score drop alerts via environment variable

## [0.4.2] — 2026-04-07

### Added
- Hermes Agent skill for agentskills.io
- Jobs Layer demo (`examples/jobs_demo.py`)
- Author metadata, SECURITY.md, expanded keywords

## [0.4.0] — 2026-04-06

### Added
- Onboarding feedback warnings when capabilities missing
- Hermes integration (MCP + skill)

## [0.3.9] — 2026-04-05

### Added
- Auto-challenge in `register()` flow
- `private_key_hex` property for key export
- `save=False` mode with key security warning

## [0.3.8] — 2026-04-04

### Added
- Encrypted key storage (Fernet + machine-derived key)
- HTTP TLS warning when connecting to non-HTTPS endpoints

## [0.3.6] — 2026-04-03

### Added
- `attest_batch()` — submit up to 50 attestations at once
- `get_reputation_bulk()` — query up to 100 agents at once

## [0.3.3] — 2026-04-01

### Added
- One-step registration with auto card creation
- Onboarding challenge support

## [0.3.0] — 2026-03-28

### Added
- Verifiable credentials with Ed25519 signatures and dynamic TTL
- Reputation tracks (per-category scoring)
- Reputation velocity (1d/7d/30d trend)
- Mock mode (`AVPAgent.create(mock=True)`)
- 6 framework integrations: CrewAI, LangGraph, AutoGen, OpenAI, Paperclip, Claude MCP
- MCP server with 11 tools

## [0.2.0] — 2026-03-22

### Added
- `@avp_tracked` decorator for zero-config integration
- Renamed package from `avp-sdk` to `agentveil`

## [0.1.1] — 2026-03-19

### Added
- Initial release: DID identity, attestations, reputation queries
