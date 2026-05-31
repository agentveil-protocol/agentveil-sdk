"""Dual-path verification tests for ``agentveil.delegation.verify_delegation``.

Legacy delegation proofs (no ``proofPurpose``) verify through the raw-JCS path;
new proofs that carry ``proofPurpose`` verify through the shared data-integrity
hashData path. Time and seeds are pinned so the tests are deterministic.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from agentveil._did import _public_key_to_did
from agentveil.data_integrity import DataIntegrityError, sign_eddsa_jcs_2022
from agentveil.delegation import (
    DelegationInvalid,
    issue_delegation,
    verify_delegation,
)

PRINCIPAL_SEED = bytes.fromhex("33" * 32)
AGENT_SEED = bytes.fromhex("44" * 32)
OTHER_SEED = bytes.fromhex("55" * 32)

PRINCIPAL_DID = _public_key_to_did(bytes(SigningKey(PRINCIPAL_SEED).verify_key))
AGENT_DID = _public_key_to_did(bytes(SigningKey(AGENT_SEED).verify_key))
OTHER_DID = _public_key_to_did(bytes(SigningKey(OTHER_SEED).verify_key))

FIXED_FROM = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
VALID_FOR = timedelta(hours=1)
WITHIN_WINDOW = FIXED_FROM  # inside [validFrom, validUntil]

SCOPE = [{"predicate": "allowed_category", "value": "infrastructure"}]

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples" / "delegation" / "samples"


def _legacy_receipt() -> dict:
    return issue_delegation(
        principal_private_key=PRINCIPAL_SEED,
        agent_did=AGENT_DID,
        scope=SCOPE,
        purpose="dual-path test",
        valid_for=VALID_FOR,
        valid_from=FIXED_FROM,
    )


def _new_receipt() -> dict:
    """A receipt secured through the data-integrity hashData path.

    Built from the same VC body ``issue_delegation`` produces (so issuer equals
    the signer DID), then signed with ``sign_eddsa_jcs_2022`` so the emitted
    proof carries ``proofPurpose`` and the document ``@context``.
    """
    body = {k: v for k, v in _legacy_receipt().items() if k != "proof"}
    secured = sign_eddsa_jcs_2022(body, PRINCIPAL_SEED)
    return json.loads(secured)


def test_legacy_issue_delegation_receipt_still_verifies():
    result = verify_delegation(_legacy_receipt(), now=WITHIN_WINDOW)
    assert result["valid"] is True
    assert result["issuer"] == PRINCIPAL_DID
    assert result["subject"] == AGENT_DID


def test_committed_valid_sample_verifies_with_pinned_now():
    receipt = json.loads((SAMPLES_DIR / "valid.json").read_text(encoding="utf-8"))
    assert "proofPurpose" not in receipt["proof"]  # the committed sample is legacy
    pinned = datetime.strptime(receipt["validFrom"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    result = verify_delegation(receipt, now=pinned)
    assert result["valid"] is True


def test_new_hashdata_receipt_verifies():
    receipt = _new_receipt()
    assert receipt["proof"]["proofPurpose"] == "assertionMethod"
    result = verify_delegation(receipt, now=WITHIN_WINDOW)
    assert result["valid"] is True
    assert result["issuer"] == PRINCIPAL_DID
    assert result["subject"] == AGENT_DID


def test_legacy_receipt_with_injected_proofpurpose_fails():
    # Adding proofPurpose to a legacy receipt routes it to the new path, where
    # the legacy signature (over raw document JCS) cannot validate.
    receipt = _legacy_receipt()
    receipt["proof"]["proofPurpose"] = "assertionMethod"
    with pytest.raises(DelegationInvalid):
        verify_delegation(receipt, now=WITHIN_WINDOW)


def test_new_receipt_without_proofpurpose_fails():
    # Removing proofPurpose from a new receipt routes it to the legacy path,
    # where the hashData signature cannot validate (no silent downgrade).
    receipt = _new_receipt()
    del receipt["proof"]["proofPurpose"]
    with pytest.raises(DelegationInvalid):
        verify_delegation(receipt, now=WITHIN_WINDOW)


def test_signer_did_mismatch_fails():
    other_vm = f"{OTHER_DID}#{OTHER_DID[len('did:key:'):]}"
    legacy = _legacy_receipt()
    legacy["proof"]["verificationMethod"] = other_vm
    with pytest.raises(DelegationInvalid, match="verificationMethod does not match issuer"):
        verify_delegation(legacy, now=WITHIN_WINDOW)
    new = _new_receipt()
    new["proof"]["verificationMethod"] = other_vm
    with pytest.raises(DelegationInvalid, match="verificationMethod does not match issuer"):
        verify_delegation(new, now=WITHIN_WINDOW)


def test_invalid_proofpurpose_raises_delegation_invalid_not_data_integrity_error():
    receipt = _new_receipt()
    receipt["proof"]["proofPurpose"] = "authentication"  # present but not accepted
    with pytest.raises(DelegationInvalid) as exc_info:
        verify_delegation(receipt, now=WITHIN_WINDOW)
    assert not isinstance(exc_info.value, DataIntegrityError)
