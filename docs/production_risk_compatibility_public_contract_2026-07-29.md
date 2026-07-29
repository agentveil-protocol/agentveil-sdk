# Production risk compatibility — public proof (C0-4B, 2026-07-29)

<!-- claim-check: ignore-file bounded compatibility vocabulary and evidence,
not a customer-readiness claim. -->

Tests/fixture/docs-only proof that the existing public MCP proxy risk vocabulary
is compatible with the exact private C0-4A public handoff manifest.

## Fixture shape (exact)

`tests/fixtures/production_risk_compatibility_public_contract.json` contains
exactly these four top-level fields:

- `contract_version`
- `vocabulary_version`
- `vocabulary_hash`
- `mapping_metadata`

No additional public commentary fields are stored in the fixture.
Public compatibility expectations live in the test module as constants.

## What this proves

- Public `RiskClass` values are exactly the legacy vocabulary:
  `read`, `write`, `destructive`, `production`, `financial`, `unknown`.
- Private canonical impact vocabulary does **not** include `production`.
- Legacy `production` is an environment compatibility check label only.
- Public Runtime Gate requests keep `risk_class` and `environment` separate and
  do not send `impact_class` / `canonical_impact_class`.
- `vocabulary_hash` is recomputed from fixture metadata (self-verifying), not
  only compared to a decorative constant.
- Existing tools `git_push`, `merge_pull_request`, `create_release`, and
  `deploy_release` remain `RiskClass.PRODUCTION` in classifier heuristics.

## Non-claims / non-goals

- No public production code changes in this slice
- No private AVP imports or private implementation copy
- No Team / provider / entitlement / customer / route / signer / approval /
  payload / credential / dispatch / protected authority
- Phase 0 and G0 remain HOLD until later private C0-5 work

## Proof

`packages/agentveil-mcp-proxy/tests/test_production_risk_compatibility_contract.py`
loads the exact four-field fixture, recomputes `vocabulary_hash` from
`mapping_metadata`, and freezes the public/private vocabulary boundary against
live public symbols.
