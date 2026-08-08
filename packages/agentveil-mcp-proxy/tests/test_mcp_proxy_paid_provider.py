"""Bounded paid provider discovery contract tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from agentveil_mcp_proxy.paid_install import (
    ERROR_VENDORED_PROVIDER_MISSING,
    PaidInstallError,
    discover_exact_vendored_paid_provider_entry,
    install_state_path,
    install_wheel_to_vendor,
    sha256_hex,
    vendor_root,
    write_install_state,
)
from agentveil_mcp_proxy.paid_provider import (
    ERROR_CONTRACT_INCOMPATIBLE,
    ERROR_PROVIDER_RESPONSE_INVALID,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
    PAID_PROVIDER_ENTRYPOINT_GROUP,
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

PACKAGE_NAME = "agentveil-private-policy"
PACKAGE_VERSION = "0.1.0"
MODULE_NAME = PACKAGE_NAME.replace("-", "_")
TOKEN = "console-device-token-secret"

SUCCESS_HOOK_SOURCE = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""

VENDORED_PROVIDER_SOURCE = """
class _Provider:
    provider_id = "private_v1"
    provider_contract_version = "1"

    def status(self):
        return {
            "provider_present": True,
            "provider_id": self.provider_id,
            "provider_contract_version": self.provider_contract_version,
            "status": "active",
            "private_provider_enabled": True,
            "public_fallback_available": True,
            "summary": "Vendored provider active.",
            "error_code": None,
        }

    def activate(self, *, license_key):
        del license_key
        return self.status()

    def deactivate(self):
        return {
            "provider_present": False,
            "provider_id": None,
            "provider_contract_version": self.provider_contract_version,
            "status": "missing",
            "private_provider_enabled": False,
            "public_fallback_available": True,
            "summary": None,
            "error_code": None,
        }

def build_vendored_provider():
    return _Provider()
"""

INCOMPATIBLE_PROVIDER_SOURCE = """
class _Provider:
    provider_id = "private_v1"
    provider_contract_version = "999"

    def status(self):
        return {
            "provider_present": True,
            "provider_id": self.provider_id,
            "provider_contract_version": self.provider_contract_version,
            "status": "active",
            "private_provider_enabled": True,
            "public_fallback_available": True,
            "summary": "bad contract",
            "error_code": None,
        }

    def activate(self, *, license_key):
        del license_key
        return self.status()

    def deactivate(self):
        return self.status()

def build_vendored_provider():
    return _Provider()
"""

EXCEPTION_PROVIDER_SOURCE = """
class _Provider:
    provider_id = "private_v1"
    provider_contract_version = "1"

    def status(self):
        raise RuntimeError("provider exploded")

    def activate(self, *, license_key):
        del license_key
        return self.status()

    def deactivate(self):
        return self.status()

def build_vendored_provider():
    return _Provider()
"""


def _entry_points_text(*, provider_target: str) -> str:
    return (
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
        f"{MODULE_NAME}.handoff_hook:run_activation_handoff\n"
        f"\n"
        f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {provider_target}\n"
    )


def _build_wheel(
    tmp_path: Path,
    *,
    entry_points: str | None = None,
    provider_source: str = VENDORED_PROVIDER_SOURCE,
) -> tuple[bytes, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    if entry_points is None:
        entry_points = _entry_points_text(
            provider_target=f"{MODULE_NAME}.vendored_provider:build_vendored_provider",
        )
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{MODULE_NAME}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{MODULE_NAME}/handoff_hook.py", SUCCESS_HOOK_SOURCE)
        archive.writestr(f"{MODULE_NAME}/vendored_provider.py", provider_source)
        archive.writestr(
            f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info/entry_points.txt",
            entry_points,
        )
        archive.writestr(
            f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    data = wheel_path.read_bytes()
    return data, sha256_hex(data)


def _install_active_state(home: Path, *, wheel_bytes: bytes) -> None:
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    wheel_path = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    wheel_path.parent.mkdir(parents=True, exist_ok=True)
    wheel_path.write_bytes(wheel_bytes)
    install_wheel_to_vendor(
        home=home,
        wheel_path=wheel_path,
        target_dir=vendor_dir,
        expected_package_name=PACKAGE_NAME,
        expected_package_version=PACKAGE_VERSION,
        require_empty_target=True,
    )
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "private_v1",
            "package_name": PACKAGE_NAME,
            "package_version": PACKAGE_VERSION,
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
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


def test_discover_vendored_provider_from_install_state(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, _digest = _build_wheel(tmp_path / "wheel")
    _install_active_state(home, wheel_bytes=wheel_bytes)
    snapshot = discover_paid_provider()
    assert snapshot.status == STATUS_ACTIVE
    assert snapshot.provider_id == "private_v1"
    assert snapshot.private_provider_enabled is True
    assert TOKEN not in str(snapshot.to_dict())


def test_discover_vendored_provider_missing_without_install_state(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, _digest = _build_wheel(tmp_path / "wheel")
    _install_active_state(home, wheel_bytes=wheel_bytes)
    install_state_path(home).unlink()
    assert discover_paid_provider().status == STATUS_MISSING


def test_discover_vendored_provider_rejects_provider_id_mismatch(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, _digest = _build_wheel(tmp_path / "wheel")
    _install_active_state(home, wheel_bytes=wheel_bytes)
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "other_provider",
            "package_name": PACKAGE_NAME,
            "package_version": PACKAGE_VERSION,
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )
    assert discover_paid_provider().status == STATUS_MISSING


def test_discover_vendored_provider_rejects_symlink_vendor_dir(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, _digest = _build_wheel(tmp_path / "wheel")
    _install_active_state(home, wheel_bytes=wheel_bytes)
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    outside = tmp_path / "outside-vendor"
    outside.mkdir()
    vendor_dir.rename(outside)
    vendor_dir.symlink_to(outside)
    assert discover_paid_provider().status == STATUS_MISSING


def test_discover_exact_vendored_provider_entry_missing_provider(tmp_path):
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    dist_info = vendor_dir / f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Name: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
        f"{MODULE_NAME}.handoff_hook:run_activation_handoff\n",
        encoding="utf-8",
    )
    with pytest.raises(PaidInstallError, match=ERROR_VENDORED_PROVIDER_MISSING):
        discover_exact_vendored_paid_provider_entry(
            vendor_dir,
            package_name=PACKAGE_NAME,
            package_version=PACKAGE_VERSION,
            provider_id="private_v1",
        )


def test_discover_vendored_provider_rejects_incompatible_contract(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, _digest = _build_wheel(
        tmp_path / "wheel",
        provider_source=INCOMPATIBLE_PROVIDER_SOURCE,
    )
    _install_active_state(home, wheel_bytes=wheel_bytes)
    snapshot = discover_paid_provider()
    assert snapshot.status == "error"
    assert snapshot.error_code == ERROR_CONTRACT_INCOMPATIBLE


def test_discover_vendored_provider_rejects_provider_exception(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, _digest = _build_wheel(
        tmp_path / "wheel",
        provider_source=EXCEPTION_PROVIDER_SOURCE,
    )
    _install_active_state(home, wheel_bytes=wheel_bytes)
    snapshot = discover_paid_provider()
    assert snapshot.status == "error"
    assert snapshot.error_code == ERROR_PROVIDER_RESPONSE_INVALID
    assert TOKEN not in str(snapshot.to_dict())


def test_environment_entry_point_discovery_still_works():
    class _Provider:
        provider_id = "private_v1"
        provider_contract_version = PUBLIC_PAID_PROVIDER_CONTRACT_VERSION

        def activate(self, *, license_key: str):
            del license_key
            return self.status()

        def status(self):
            return {
                "provider_present": True,
                "provider_id": self.provider_id,
                "provider_contract_version": self.provider_contract_version,
                "status": STATUS_ACTIVE,
                "private_provider_enabled": True,
                "public_fallback_available": True,
                "summary": "loader provider",
                "error_code": None,
            }

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
    snapshot = discover_paid_provider()
    assert snapshot.status == STATUS_ACTIVE
    assert snapshot.summary == "loader provider"
