# Delegation Receipts — reference verifier

A delegation receipt is a W3C VC v2.0 credential signed by a *principal* that
authorizes an *agent* to act within a stated scope. Receipts are verifiable
**offline** by anyone — no network, no AVP backend, no SDK required.

This directory contains runnable DelegationReceipt examples plus a standalone
reference verifier you can read end to end and run against any AgentVeil
delegation receipt.

## Files

| File | Purpose |
|---|---|
| `issue_and_verify_offline.py` | Minimal SDK example: issue and verify locally in mock mode. |
| `persist_and_reload.py` | Save a receipt as JSON, reload it, and verify it offline. |
| `multi_scope_delegation.py` | Issue one receipt with multiple categories and a spend cap. |
| `verify.py` | Standalone verifier. No `agentveil` SDK dependency. |
| `samples/valid.json` | Legacy proof receipt, properly signed, large validity window. |
| `samples/valid_hashdata.jsonld` | Current proof receipt, properly signed, large validity window. |
| `samples/expired.json` | Properly signed receipt with `validUntil` in the past. |
| `samples/tampered.json` | Receipt whose `scope` was altered after signing. |
| `_generate_samples.py` | Helper that regenerates the samples above. |

## Quick start

```bash
python issue_and_verify_offline.py
python persist_and_reload.py
python multi_scope_delegation.py

pip install pynacl base58 jcs

# pass a file
python verify.py samples/valid.json

# or pipe receipt JSON via stdin
cat samples/valid.json | python verify.py -
```

Exit codes:

- `0` — receipt is valid (parsed fields printed as JSON)
- `1` — receipt is invalid (`{"valid": false, "reason": "..."}`)
- `2` — usage / IO error

## What the verifier checks

1. `@context` includes both `https://www.w3.org/ns/credentials/v2` and
   `https://agentveil.dev/contexts/delegation/v1.jsonld`.
2. `type` includes both `VerifiableCredential` and `AgentDelegation`.
3. `issuer` is a `did:key:` resolving to a 32-byte Ed25519 public key.
4. `credentialSubject.id` is a `did:key:`.
5. `credentialSubject.scope` only contains supported predicates and
   well-formed values.
   - `max_spend` — `currency` is a 3-letter ISO 4217 code,
     `amount` is positive.
   - `allowed_category` — `value` is a non-empty string.
6. `validFrom` and `validUntil` are ISO 8601 (UTC, second resolution),
   `validUntil` is strictly after `validFrom`, current time is inside the
   window.
7. `proof.type` is `DataIntegrityProof` and `proof.cryptosuite` is
   `eddsa-jcs-2022`.
8. `proof.verificationMethod` references the same DID as `issuer`.
9. The Ed25519 signature in `proof.proofValue` (multibase-z / base58)
   verifies against the receipt's declared proof construction:
   - legacy receipts without `proofPurpose` verify against
     `jcs.canonicalize(receipt without proof)`;
   - receipts with `proofPurpose` verify against the data-integrity `hashData`
     message: `SHA256(JCS(proofConfig)) || SHA256(JCS(receipt without proof))`.

Any failure raises `ValueError(reason)` and the script exits non-zero.

## Test fixtures only

The keypair seeds in `_generate_samples.py`
(`PRINCIPAL_SEED_HEX`, `AGENT_SEED_HEX`) are **fixed disposable fixture
values** checked into the repository so the sample receipts are
reproducible byte-for-byte. They are public and unsafe for production use.

> **Test fixture only. Do not use this keypair for production delegation.**

A real principal must use its own private key, kept outside the repo. Real
agent identities are typically derived from the operator's existing
`AVPAgent` keypair (see the SDK).

## Schema stability

The receipt format is stable. Changing it after publication invalidates
existing signed receipts. Future schema changes must add **new optional
predicates** rather than alter existing ones. The current supported
predicates are:

- `max_spend` (currency, amount)
- `allowed_category` (value)

`validFrom` / `validUntil` belong to the W3C VC base layer, not to scope.
