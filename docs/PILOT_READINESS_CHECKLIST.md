# Pilot Readiness Checklist

This checklist is for the first guided customer integration using
the production AVP API. It is an operating checklist for one controlled-action
rollout.

## Scope

Use this checklist for one bounded controlled-action workflow with a known
principal, one customer agent DID, and one explicit action/resource/environment
scope.

Out of scope for this pilot checklist:

- unattended onboarding without principal or workflow setup
- automatic DelegationReceipt issuance
- dashboard or inbox workflows
- production deploy, SDK release, tag, or PyPI publish
- marketing, website, or public positioning changes

## Before Starting

- Confirm the customer use case has one concrete controlled action.
- Confirm the action can be safely tested with non-destructive parameters first.
- Confirm the principal or workflow owner is identified.
- Confirm who can approve the action if Human Approval is required.
- Confirm where proof artifacts will be stored by the customer.
- Confirm no private keys, cloud credentials, raw private logs, or secrets will
  be sent to AVP.

## Environment Setup

- Install the pinned SDK:

  ```bash
  python -m pip install agentveil==0.7.8
  ```

- Create or load the local agent identity.
- Store the local Ed25519 private key securely.
- Use `AVPAgent.save(passphrase=...)` when persisting the identity.
- Register the DID with AVP.
- Verify that the DID is accepted for signed runtime requests.
- Treat a locally generated DID as incomplete until the production API knows and
  verifies it.

## Preflight Gate

Run preflight before any Runtime Gate or execution call:

```python
report = agent.integration_preflight()
```

Proceed only when:

- `report.ready` is true;
- API reachability passed;
- the DID is registered;
- verification status is acceptable when visible;
- the safe signed read check succeeds.

If preflight fails:

- follow `report.next_action`;
- respect `report.retry_after` when present;
- do not call `controlled_action(...)` yet.

Setup/auth readiness states:

| Status | Pilot meaning |
|---|---|
| `ready` | Setup/auth is ready to attempt `controlled_action(...)`. |
| `unregistered` | DID is local-only or unknown to AVP. |
| `unverified_or_forbidden` | DID exists but is not verified or cannot use the signed read path. |
| `agent_suspended` | DID is suspended. |
| `agent_revoked` | DID is revoked. |
| `agent_migrated` | DID has moved to a successor DID. |
| `signature_invalid` | Signature failed or timestamp expired. |
| `nonce_replay` | Signed headers or nonce were reused. |

This preflight does not execute actions, create approvals, or prove that the
customer's DelegationReceipt is valid for a specific action.

## Signed Query Check

Confirm the customer environment is using the current signed-query path.

- SDK must be `agentveil==0.7.8` or a later release containing the documented
  signed-query and onboarding challenge helper behavior.
- Signed requests with query parameters must use AVP-Sig v2.
- AVP-Sig v1 remains valid only for signed requests without query parameters.
- A `401` on signed query requests should be treated as a setup/auth issue
  until proven otherwise.

## DelegationReceipt

Before the first controlled action, obtain a DelegationReceipt from the
principal or workflow owner.

For the guided pilot path, the principal can issue the current v1 receipt
locally with:

```python
from datetime import timedelta

receipt = principal.issue_delegation_receipt(
    agent_did=agent.did,
    allowed_categories=["infrastructure"],
    valid_for=timedelta(hours=1),
)
```

The receipt binds:

- principal or workflow owner identity;
- agent DID;
- allowed category predicates;
- validity window;
- any customer-specific constraints needed for review.

DelegationReceipt v1 does not emit exact action, resource, or environment
predicates. Runtime Gate and execution cross-check the requested action,
resource, and environment after the receipt is supplied.

Provide the signed receipt to the first-action template through
`AVP_DELEGATION_RECEIPT_FILE` or `AVP_DELEGATION_RECEIPT_JSON`.

## First Controlled Action

Use `examples/first_controlled_action.py` as the operating template.

Start with the default safe path:

```bash
python examples/first_controlled_action.py
```

Proceed to Runtime Gate only after preflight is ready and the action scope has
been reviewed:

```bash
AVP_RUN_CONTROLLED_ACTION=1 \
AVP_DELEGATION_RECEIPT_FILE=/path/to/delegation_receipt.json \
python examples/first_controlled_action.py
```

For the first pilot run, prefer a read-only or inspection-style action such as
`infra.resource.inspect` in a non-production environment unless the customer
has explicitly approved a higher-risk path.

## Outcome Handling

The integration must handle all controlled-action outcomes.

`executed`:

- store `receipt_jcs` exactly as returned;
- store the Runtime Gate `audit_id`;
- export a proof packet with `agent.build_proof_packet(...)` if the workflow
  needs one bundled artifact for review;
- record the action, resource, environment, and SDK version used.

`approval_required`:

- store the Runtime Gate `audit_id`;
- store the `approval_id`;
- route approval to the principal;
- resume only after the principal approves;
- store the signed approval receipt and final execution receipt when available.

`blocked`:

- do not execute the action outside AVP;
- surface the block reason to the operator or customer workflow owner;
- preserve the decision metadata needed for review.

SDK/API errors:

- `401`: check signature, timestamp, nonce, DID registration, and AVP-Sig v2 for
  query-bearing requests;
- `403`: check verification, suspension, revocation, and role permissions;
- `409`: handle unsafe or incomplete workflow state such as approval required;
- `429`: back off and respect retry guidance;
- `503`: treat as backend unavailable or fail-closed signing dependency.

## Proof Artifacts

Retain these artifacts for the pilot record:

- DelegationReceipt;
- agent DID and public key;
- Runtime Gate `audit_id`;
- raw signed execution receipt text (`receipt_jcs`);
- raw signed Runtime Gate DecisionReceipt text, when fetched for review;
- proof packet generated from explicit local artifacts, if used;
- signed approval receipt, if approval was required;
- remediation case IDs and evidence hashes, if contested;
- SDK version and base URL;
- timestamped operator notes for any manual customer step.

Do not rewrite signed receipt text. Store the raw JCS string as the proof
artifact and use parsed receipt fields only as a convenience view.

## Verify Proof Artifacts Offline

For external review, keep signature verification separate from AVP semantic
verification:

- `verify_signed_jcs(...)` checks one signed JCS artifact and returns the signer
  DID, schema version, body, and SHA-256 digest.
- `verify_proof_packet(...)` checks trusted AVP backend signer DID(s), receipt
  hashes, and action/resource/environment/agent linkage across the packet.

Use role-specific trusted AVP signer DID sets for DecisionReceipt,
ExecutionReceipt, and HumanApprovalReceipt. Do not accept an AVP-issued receipt
solely because it has a valid signature from an arbitrary DID. The
`trusted_backend_signer_dids` fallback is only for deployments that
intentionally use one backend signer for all AVP-issued receipt types.

Required artifacts by flow:

| Flow | Required proof artifacts |
| --- | --- |
| Blocked | DelegationReceipt, DecisionReceipt |
| Executed without approval | DelegationReceipt, DecisionReceipt, ExecutionReceipt |
| Executed after approval | DelegationReceipt, DecisionReceipt, HumanApprovalReceipt, ExecutionReceipt |
| Contested/remediated | Same as the underlying flow, plus remediation case IDs/evidence hashes |

Current signed receipt schemas:

| Receipt | Current schema |
| --- | --- |
| DecisionReceipt | `decision_receipt/3` |
| HumanApprovalReceipt | `human_approval_receipt/2` |
| ExecutionReceipt | `execution_receipt/2` |

<!-- claim-check: allow "W3C"/"eddsa-jcs-2022" are literal protocol identifiers, not conformance claims; the externally pinned verifier boundary is tested in tests/test_decision_receipt_v3.py. -->
The Runtime Gate DecisionReceipt is `decision_receipt/3` (W3C Data Integrity, <!-- claim-check: allow eddsa-jcs-2022 is a literal cryptosuite identifier, not a conformance claim; pinned verification is tested in tests/test_decision_receipt_v3.py. -->
`eddsa-jcs-2022`): verify a `/3` receipt with
`verify_eddsa_jcs_2022(..., expected_signer_did=...)` or, when embedded in an
evidence bundle, through the strict bundle verifier with an externally pinned
signer DID. `verify_signed_jcs(...)` / `verify_proof_packet(...)` above cover
the legacy `/1`,`/2` raw-JCS schema. HumanApprovalReceipt and ExecutionReceipt
remain `/2` raw-JCS. `verify_eddsa_jcs_2022(...)` requires an externally pinned
signer DID and is the SDK's own first-party Data Integrity verifier, not a
third-party standard-conformance certification.

## Go/No-Go Criteria

The pilot is ready for the first customer-controlled action when:

- SDK install is pinned to `agentveil==0.7.8` or a later release containing
  the documented signed-query and onboarding challenge helper behavior;
- local identity is created or loaded securely;
- DID registration and verification state are acceptable;
- `integration_preflight()` is ready;
- signed query requests use AVP-Sig v2;
- a DelegationReceipt exists for the reviewed category and financial scope;
- the requested action, resource, and environment are explicitly reviewed before Runtime Gate submission;
- `executed`, `approval_required`, and `blocked` paths are handled;
- proof artifact storage is defined before execution.

Do not treat the workflow as ready for unattended rollout if any step requires
operator interpretation or manual backend intervention.

## Current Limitations

- DelegationReceipt issuance is still an integration-owned step.
- Proof packet export is manual: collect the receipt, `audit_id`, approval
  receipt, and remediation references explicitly.
- Approval discovery/routing depends on the integration's workflow.
- Error handling still requires some mapping from HTTP status and SDK exception
  type to customer-facing next action.
- A successful preflight is required but not sufficient for action execution;
  Runtime Gate, Governance, Human Approval, and execution can still block or
  require approval.
