# AVP Proof Pack — end-to-end walkthrough

One runnable local-backend evidence walkthrough for AgentVeil reputation evidence and audit verification:

> **The demo shows a real local backend flow: registration → advisory check → DelegationReceipt issuance → negative attestation → score recompute → advisory deny → webhook alert → audit trail verification.**

This is the canonical proof-oriented demo for the SDK. For a quick visual overview, see the GIF at the top of the [main README](../../README.md). For a no-server tour of the SDK API, see [`standalone_demo.py`](../standalone_demo.py).

---

## What this demo proves

| Scene | Artifact | What it shows |
|---|---|---|
| 1 | `01_registration.json` | Two real DIDs, PoW + verify path |
| 2 | `02_initial_trust_check.json` | `can_trust` returns `allowed=true` initially |
| 3 | `03_delegation_receipt.json` | Local DelegationReceipt issuance and offline verification for the controlled-action path |
| 4 | `04_negative_attestation.json` | Real `POST /v1/attestations` with `outcome=negative` |
| 5 | `05_score_drop.json` | Real EigenTrust recompute run; score before/after |
| 6 | `06_trust_check_denied.json` | Same `can_trust` call now returns different tier / deny |
| 7 | `07_webhook_alert.json` | Real dispatcher payload delivered via HTTP to local receiver |
| 8 | `08_audit_trail.json` | Full audit chain for the worker agent |
| 9 | `09_chain_verification.json` | **Client-side subset integrity** — recomputes every entry hash in the per-DID trail. Proves per-entry tamper resistance. |
| 9b | `09b_server_full_chain_reference.json` | **Server-side full-chain reference** — result of `GET /v1/audit/verify` walking the entire global chain. Included as a reference check, trusts the server. |

Only the webhook **transport** is local (HTTP to `localhost:8765`). Payload,
trigger conditions, and dispatcher path are production code.

---

## Prerequisites

1. **A local AVP backend** running via `docker compose`:
   ```bash
   cd /path/to/your/avp-backend
   # Ensure .env has ENVIRONMENT=development so /v1/alerts accepts http:// URLs
   docker compose up -d
   curl http://localhost:8000/v1/health   # should return ok
   ```
   The hosted instance at [agentveil.dev](https://agentveil.dev) does not accept
   `http://` webhook targets, so this walkthrough requires a local backend in
   development mode.
2. **Python deps** in this directory:
   ```bash
   pip install agentveil httpx pynacl base58
   ```

---

## Run

Terminal A (webhook sink, must be up first):
```bash
cd agentveil-sdk/examples/proof_pack
python webhook_receiver.py            # listens on http://127.0.0.1:8765/hook
```

Terminal B (orchestrator):
```bash
cd agentveil-sdk/examples/proof_pack
python run_demo.py \
    --server http://localhost:8000 \
    --compose-service api \
    --compose-dir /path/to/avp \
    --webhook-url http://host.docker.internal:8765/hook \
    --threshold 0.99
```

Expected runtime: **under 5 minutes**. End state: `artifacts/` has 9 JSON files
and the orchestrator prints `PROOF PACK DEMO COMPLETE`.

### Common parameters

| Flag | Default | Purpose |
|---|---|---|
| `--server` | `http://localhost:8000` | Local AVP backend |
| `--compose-service` | `api` | Service name in `docker-compose.yml` (NOT container name) |
| `--compose-dir` | cwd | Directory containing `docker-compose.yml` |
| `--webhook-url` | `http://host.docker.internal:8765/hook` | URL the AVP container posts to. On Linux, use `http://172.17.0.1:8765/hook` or wire a bridge network alias. |
| `--threshold` | `0.99` | Alert fires below this score. Set this high so the first negative attestation trips the alert during the demo run; production deployments typically use a much lower value. |

---

## Offline chain verification (standalone)

**Subset trail verification ≠ global chain integrity verification.**

`verify_chain.py` has **zero AVP dependencies** (stdlib only — hashlib, json):

```bash
# Subset mode (default): per-entry hash recompute. Safe on /v1/audit/{did}.
python verify_chain.py artifacts/08_audit_trail.json --verbose

# Full-chain mode: additionally checks adjacent previous_hash linkage.
# Only correct on a full global chain dump, NOT on a per-DID trail.
python verify_chain.py full_chain_dump.json --full-chain --verbose
```

**What this verifier proves (subset mode):** every entry in the trail has a
stored `entry_hash` that correctly recomputes from its fields. Any tampering
with any field (including `previous_hash`) breaks the recompute. This proves
per-entry tamper resistance without trusting the server.

**What it does NOT prove:** that the global audit chain has no missing or
inserted entries outside the returned subset. `GET /v1/audit/{did}` is
intentionally a subset — the backend trail endpoint skips unrelated events.
For global completeness, use the server-side `GET /v1/audit/verify` reference
(saved as `09b_server_full_chain_reference.json`).

Reference hash formula (matches the AVP backend implementation):

```
entry_hash = SHA256(
    previous_hash_or_empty
    + event_type
    + agent_did
    + canonical_json(payload)     # sort_keys=True, separators=(",",":")
    + iso8601_timestamp            # backend uses "+00:00"; API responses
                                   # emit "Z" — verifier normalizes back.
)
```

Any system — auditor, regulator, customer — can run this file against an AVP
audit trail JSON and independently verify per-entry integrity.

---

## How the pieces fit

- `verify_chain.py` is a **standalone reference verifier** — stdlib only,
  no dependency on the `agentveil` SDK. It is intentionally a separate
  re-implementation of the audit hash-chain rule so anyone can verify a trail
  without trusting either the AVP backend or the SDK.
- `run_demo.py` uses only the public `agentveil` SDK plus HTTP calls for the
  local webhook and audit endpoints. It does not depend on other example files.
- `webhook_receiver.py` is a tiny stdlib HTTP sink — it has no AVP-specific
  logic; the payload it records is produced entirely by the AVP dispatcher.

---

## Known gotchas

- **`host.docker.internal`** works on Docker Desktop (macOS/Windows) out of the
  box. On Linux, add `extra_hosts: ["host.docker.internal:host-gateway"]` to
  the `api` service or use the host bridge IP.
- **`ENVIRONMENT=development`** is required in `.env` — production config
  rejects non-HTTPS webhook URLs.
- **Recompute timing**: the dispatcher fires synchronously during the compute
  process. If no alert lands in `07_webhook_alert.json`, check the recompute stdout
  (saved in `05_score_drop.json.recompute.stdout_tail`).
- **Threshold 0.99** is intentionally high so the demo's first negative
  attestation crosses it. Real deployments use a much lower value (around 0.5)
  and should not reuse the demo threshold.
- **Fresh DIDs per run.** Agents are not saved to disk (`save=False`). Run
  cleanup: `docker compose down -v` between runs if you want a clean slate.

---

## What a successful run looks like

On a clean run against a local AVP backend:

- 9 JSON artifacts appear under `artifacts/`
- Artifact `05_score_drop.json` shows different `before` and `after` scores
- Artifact `07_webhook_alert.json` contains a real dispatcher payload
- Artifact `09_chain_verification.json` reports `valid: true` with `checked > 0`
- `verify_chain.py` runs against `08_audit_trail.json` with no AVP imports

Want a stronger guarantee? Tamper with any field of any entry in
`08_audit_trail.json` and re-run `verify_chain.py` — it should report
`invalid`.
