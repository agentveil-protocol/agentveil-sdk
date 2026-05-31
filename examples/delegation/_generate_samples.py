"""
Regenerate sample delegation receipts for verify.py tests.

Test fixture only. Do not use the disposable keypair below for production
delegation. Re-run this script if the schema or signing helper changes:

  python examples/delegation/_generate_samples.py

Outputs three files in samples/:
  - valid.json           legacy proof, properly signed, in window
  - valid_hashdata.jsonld  current proof, properly signed, in window
  - expired.json         legacy proof, properly signed, validUntil in the past
  - tampered.json        legacy proof, scope altered after signing
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import types
from datetime import datetime, timedelta, timezone

import base58
import jcs
from nacl.signing import SigningKey

# Fixed disposable fixture values, checked in for reproducible samples.
# Public and unsafe for production delegation.
PRINCIPAL_SEED_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
AGENT_SEED_HEX = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SAMPLES_DIR = os.path.join(HERE, "samples")

# Import delegation.py directly (bypassing agentveil/__init__.py) so this
# fixture script runs in a minimal venv with pynacl + base58 + jcs, without
# pulling httpx and the rest of the SDK package surface.
_AGENTVEIL_DIR = os.path.join(REPO_ROOT, "agentveil")
_pkg = types.ModuleType("agentveil")
_pkg.__path__ = [_AGENTVEIL_DIR]
sys.modules.setdefault("agentveil", _pkg)

_DELEGATION_PATH = os.path.join(_AGENTVEIL_DIR, "delegation.py")
_spec = importlib.util.spec_from_file_location("agentveil.delegation", _DELEGATION_PATH)
_delegation = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _delegation
_spec.loader.exec_module(_delegation)
issue_delegation = _delegation.issue_delegation
_public_key_to_did = _delegation._public_key_to_did


def _did_for(seed_hex: str) -> str:
    sk = SigningKey(bytes.fromhex(seed_hex))
    return _public_key_to_did(bytes(sk.verify_key))


def _write(name: str, receipt: dict) -> None:
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    path = os.path.join(SAMPLES_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {path}")


def _format_iso8601(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _issue_legacy_delegation(
    principal_seed: bytes,
    *,
    agent_did: str,
    scope: list[dict],
    purpose: str,
    valid_for: timedelta,
    valid_from: datetime,
    receipt_id: str,
) -> dict:
    signing_key = SigningKey(principal_seed)
    principal_did = _public_key_to_did(bytes(signing_key.verify_key))
    body = {
        "@context": [_delegation.VC_CONTEXT_V2, _delegation.DELEGATION_CONTEXT_V1],
        "type": [_delegation.VC_TYPE, _delegation.DELEGATION_TYPE],
        "id": receipt_id,
        "issuer": principal_did,
        "validFrom": _format_iso8601(valid_from),
        "validUntil": _format_iso8601(valid_from + valid_for),
        "credentialSubject": {
            "id": agent_did,
            "scope": copy.deepcopy(scope),
            "purpose": purpose,
        },
    }
    signature = signing_key.sign(jcs.canonicalize(body)).signature
    body["proof"] = {
        "type": _delegation.PROOF_TYPE,
        "cryptosuite": _delegation.CRYPTOSUITE,
        "verificationMethod": f"{principal_did}#{principal_did[len('did:key:'):]}",
        "proofValue": "z" + base58.b58encode(signature).decode("ascii"),
    }
    return body


def main() -> None:
    principal_seed = bytes.fromhex(PRINCIPAL_SEED_HEX)
    agent_did = _did_for(AGENT_SEED_HEX)

    scope = [
        {"predicate": "max_spend", "currency": "USD", "amount": 100},
        {"predicate": "allowed_category", "value": "office_supplies"},
    ]
    purpose = "Procure office supplies for Q2 onboarding kits"

    # --- valid: wide window so the sample stays valid for sample-doc demos ---
    valid_window_start = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
    valid = _issue_legacy_delegation(
        principal_seed,
        agent_did=agent_did,
        scope=scope,
        purpose=purpose,
        valid_for=timedelta(days=400),
        valid_from=valid_window_start,
        receipt_id="urn:uuid:11111111-1111-4111-8111-111111111111",
    )
    _write("valid.json", valid)

    # --- valid_hashdata: same semantics, current data-integrity proof shape ---
    valid_hashdata = issue_delegation(
        principal_seed,
        agent_did=agent_did,
        scope=scope,
        purpose=purpose,
        valid_for=timedelta(days=400),
        valid_from=valid_window_start,
        receipt_id="urn:uuid:33333333-3333-4333-8333-333333333333",
    )
    _write("valid_hashdata.jsonld", valid_hashdata)

    # --- expired: issued in the past, validUntil < now -----------------------
    past = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    expired = _issue_legacy_delegation(
        principal_seed,
        agent_did=agent_did,
        scope=scope,
        purpose=purpose,
        valid_for=timedelta(days=1),
        valid_from=past,
        receipt_id="urn:uuid:22222222-2222-4222-8222-222222222222",
    )
    _write("expired.json", expired)

    # --- tampered: identical to `valid` except `credentialSubject.scope` was
    #     altered AFTER signing. Every other field (including `id`) is
    #     preserved so the sample demonstrates exactly one failure mode:
    #     scope tampering invalidates the signature.
    tampered = copy.deepcopy(valid)
    tampered["credentialSubject"]["scope"] = [
        {"predicate": "max_spend", "currency": "USD", "amount": 9999},
        {"predicate": "allowed_category", "value": "office_supplies"},
    ]
    _write("tampered.json", tampered)


if __name__ == "__main__":
    main()
