# Changelog

All notable changes to the `agentveil` SDK.

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
