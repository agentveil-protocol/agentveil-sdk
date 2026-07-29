# Runtime Gate public wire contract corrective (2026-07-28)

Bounded schema-fixture correction only.

## Change

`tests/fixtures/runtime_gate_public_wire_contract.json` `response.public_fields`
gains two already-public bounded projection names:

- `paid_policy_provider_decision`
- `paid_approval_center_projection`

Inventory size: 14 → 16. Order of existing fields is unchanged.

## Non-goals

- No runtime behavior change in `agentveil/` or `packages/`
- No private paid lifecycle, entitlements, billing, KMS, AWS, or deployment details
- No package metadata / README / changelog updates in this slice

## Proof

Public regression
`tests/test_runtime_install_clone_context.py::test_public_wire_contract_response_field_inventory_is_exact`
<!-- claim-check: allow contract-test boundary: the public marker denylist is asserted by this regression. -->
freezes the exact 16-name inventory and the existing public-safe marker denylist.
