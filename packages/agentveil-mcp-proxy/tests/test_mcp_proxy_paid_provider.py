"""Bounded paid provider discovery contract tests."""

from __future__ import annotations

import pytest

from agentveil_mcp_proxy.paid_provider import (
    ERROR_CONTRACT_INCOMPATIBLE,
    ERROR_PROVIDER_RESPONSE_INVALID,
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    STATUS_MISSING,
    PaidProviderSnapshot,
    activate_with_paid_provider,
    assert_no_private_provider_markers,
    discover_paid_provider,
    normalize_provider_response,
    set_paid_provider_loader,
)


@pytest.fixture(autouse=True)
def _reset_provider_loader():
    set_paid_provider_loader(None)
    yield
    set_paid_provider_loader(None)


def test_discover_paid_provider_absent_by_default():
    snapshot = discover_paid_provider()
    assert snapshot.provider_present is False
    assert snapshot.status == STATUS_MISSING
    assert snapshot.public_fallback_available is True


def test_normalize_provider_response_accepts_bounded_active_snapshot():
    snapshot = normalize_provider_response(
        {
            "provider_present": True,
            "provider_id": "private_v1",
            "provider_contract_version": PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
            "status": STATUS_ACTIVE,
            "private_provider_enabled": True,
            "public_fallback_available": True,
            "summary": "Installed private_v1 bridge.",
            "error_code": None,
        }
    )
    assert snapshot == PaidProviderSnapshot(
        provider_present=True,
        provider_id="private_v1",
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=True,
        summary="Installed private_v1 bridge.",
        error_code=None,
    )


def test_normalize_provider_response_rejects_unknown_keys():
    snapshot = normalize_provider_response(
        {
            "provider_present": True,
            "provider_id": "private_v1",
            "provider_contract_version": PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
            "status": STATUS_ACTIVE,
            "private_provider_enabled": True,
            "public_fallback_available": True,
            "summary": "ok",
            "error_code": None,
            "rule_graph": {"secret": True},
        }
    )
    assert snapshot.status == "error"
    assert snapshot.error_code == ERROR_PROVIDER_RESPONSE_INVALID
    assert snapshot.public_fallback_available is True


def test_normalize_provider_response_rejects_incompatible_contract():
    snapshot = normalize_provider_response(
        {
            "provider_present": True,
            "provider_id": "private_v1",
            "provider_contract_version": "999",
            "status": STATUS_ACTIVE,
            "private_provider_enabled": True,
            "public_fallback_available": True,
            "summary": "ok",
            "error_code": None,
        }
    )
    assert snapshot.error_code == ERROR_CONTRACT_INCOMPATIBLE
    assert snapshot.public_fallback_available is True


def test_activate_with_loader_returns_bounded_snapshot():
    class _Provider:
        provider_id = "private_v1"
        provider_contract_version = PUBLIC_PAID_PROVIDER_CONTRACT_VERSION

        def activate(self, *, license_key: str):
            del license_key
            return {
                "provider_present": True,
                "provider_id": self.provider_id,
                "provider_contract_version": self.provider_contract_version,
                "status": STATUS_ACTIVE,
                "private_provider_enabled": True,
                "public_fallback_available": True,
                "summary": "activated",
                "error_code": None,
            }

        def status(self):
            return self.activate(license_key="unused")

        def deactivate(self):
            return {
                "provider_present": False,
                "provider_id": None,
                "provider_contract_version": self.provider_contract_version,
                "status": STATUS_MISSING,
                "private_provider_enabled": False,
                "public_fallback_available": True,
                "summary": None,
                "error_code": None,
            }

    set_paid_provider_loader(lambda: _Provider())
    snapshot = activate_with_paid_provider(license_key="avp_live_provider_test_key")
    assert snapshot.status == STATUS_ACTIVE
    assert snapshot.provider_id == "private_v1"
    blob = str(snapshot.to_dict())
    assert_no_private_provider_markers(blob)
    assert "avp_live_provider_test_key" not in blob
