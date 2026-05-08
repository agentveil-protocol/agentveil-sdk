# Live Developer Adoption Smoke

This smoke is the 0.7.12 release-train gate for the self-service developer
path. It runs against `https://agentveil.dev` with pre-provisioned smoke
identities and validates the production Runtime Gate, approval, signed receipt,
Proof Packet, offline verification, and typed-error paths.

## What It Validates

| # | Criterion | Evidence line |
|---|---|---|
| 1 | Production integration path mirrors README flow | `CRITERION 1 PASS: production path mirrored` |
| 2 | DelegationReceipt issues and verifies offline | `CRITERION 2 PASS: delegation_receipt_hash=...` |
| 3 | `controlled_action(...)` returns executed / approval_required / blocked | `CRITERION 3 PASS: executed=true, approval_required=true, blocked=true` |
| 4 | Approval grants and resumes execution | `CRITERION 4 PASS: approval_id=...` |
| 5 | Proof Packet export uses public SDK helpers | `CRITERION 5 PASS: packet has decision/execution/approval receipt jcs` |
| 6 | Offline verification succeeds with strict trusted signer DIDs | `CRITERION 6 PASS: signature_valid=True, linkage_valid=True, trust_set_strict=True` |
| 7 | Safe failures surface typed SDK exceptions | `CRITERION 7 PASS: triggered_exceptions=...` |

## Smoke Identities

The smoke loads existing local credentials and does not create new agents:

| Role | Saved agent name | DID |
|---|---|---|
| requester | `0_7_12_smoke_requester` | `did:key:z6Mks5BKfUngtUHUge7qJywv8b38jXJDzgeui1StCRi1zSYS` |
| approver | `0_7_12_smoke_approver` | `did:key:z6MkfHok1PNjpgXYyJiZcw8pZGmqHbPBFrQLZmzjQD8vVJMu` |

Both files must already exist under `~/.avp/agents/` and remain mode `0600`.

## Trusted Signers

The smoke uses strict signer DID sets captured during Phase 1 probing:

| Receipt | Trusted signer DID |
|---|---|
| DecisionReceipt | `did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3` |
| ExecutionReceipt | `did:key:z6MkkvQQ9SxaNX9eEVHd5NtEamVY3YiZSpHZE567Vxs5jQQ3` |
| HumanApprovalReceipt | `did:key:z6Mkjw22249tpNN4LJGLyq1oGSq1Skh3ks94fiMrgi4oqveo` |

Signer drift is a release-gate failure. The script logs both captured and
pinned signer DIDs.

## Fixtures

| Expected outcome | Action | Resource | Environment |
|---|---|---|---|
| executed | `infra.resource.inspect` | `infra_sandbox:resource:synthetic-vol-1` | `production` |
| approval_required | `infra.volume.delete` | `infra_sandbox:resource:smoke-9b-0-7-12` | `production` |
| blocked | `github.read_file` | `repo:agentveil/smoke` | `production` |

The script probes each fixture before the full controlled-action path. Any
unexpected decision is treated as fixture drift and exits non-zero.

The approval fixture resumes through the gateway and produces a signed
ExecutionReceipt. The sandbox adapter may report receipt `status=FAILED` if the
synthetic resource is absent; that is still valid evidence that approval
resolution, execution receipt retrieval, and proof verification ran end-to-end.

## Typed Error Scenarios

The smoke avoids unsafe production probes such as rate-limit or forced 5xx
tests. Criterion 7 uses three safe typed-error paths:

| Scenario | SDK call | Expected exception |
|---|---|---|
| Empty batch validation | `attest_batch([])` | `AVPValidationError` |
| Unknown approval id | `get_approval("urn:uuid:00000000-0000-0000-0000-000000000000")` | `AVPNotFoundError` or `AVPAuthError` |
| Unregistered requester | unsaved agent `runtime_evaluate(...)` | `AVPAuthError` |

## Reproduce

```bash
python -m venv /tmp/avp-slice9b-venv
source /tmp/avp-slice9b-venv/bin/activate
python --version
pip install -e /Users/olegboiko/Desktop/avp-sdk-public
AVP_BASE_URL=https://agentveil.dev \
python examples/live_developer_adoption_smoke.py
```

Capture release evidence with:

```bash
python --version 2>&1 | tee ~/Desktop/AVP_test_logs/2026-05-08_slice-9b-live-developer-adoption_<sha>.log
pip install -e /Users/olegboiko/Desktop/avp-sdk-public 2>&1 | tee -a ~/Desktop/AVP_test_logs/2026-05-08_slice-9b-live-developer-adoption_<sha>.log
AVP_BASE_URL=https://agentveil.dev \
python examples/live_developer_adoption_smoke.py 2>&1 | tee -a ~/Desktop/AVP_test_logs/2026-05-08_slice-9b-live-developer-adoption_<sha>.log
```

## Safety Notes

- The script does not register new agents and does not modify `~/.avp/agents/`.
- It creates production Runtime Gate decisions, approval requests, approval
  receipts, and execution receipts as release-validation evidence.
- It does not intentionally trigger rate limits or server errors.
- It checks for `/tmp/avp-slice9b-home-*` leftovers and fails if any are present.
