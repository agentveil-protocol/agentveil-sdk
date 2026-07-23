"""Zero-config paid activation bridge + public contract fixture tests."""

from __future__ import annotations

from dataclasses import dataclass
import io
import json
from pathlib import Path
import zipfile

import pytest

from agentveil_mcp_proxy.paid_activation import (
    ACTIVATION_FILENAME,
    BOUNDED_ACTIVATION_KEYS,
    ERROR_ACTIVATION_STATE_UNREADABLE,
    STATUS_ACTIVE,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_MISSING,
    activation_path,
    build_paid_deactivate_payload,
    build_paid_status_payload,
    load_activation_state,
    map_public_paid_enablement,
    public_install_hints,
    run_paid_activate_cli,
    run_paid_status_cli,
    write_activation_state,
)
from agentveil_mcp_proxy.paid_install import (
    BOUNDED_INSTALL_KEYS,
    DEFAULT_PAID_API_BASE_URL,
    INSTALL_FILENAME,
    PROVIDER_ID,
    ActivationValidateResult,
    EntitlementResult,
    HttpPaidBackendClient,
    InstallSafetyResult,
    PackageAuthorizeResult,
    install_state_path,
    load_install_state,
    resolve_paid_backend_client,
    set_paid_backend_client,
    sha256_hex,
    write_install_state,
)

PACKAGE_NAME = "agentveil-private-policy"
PACKAGE_VERSION = "0.1.0"
RAW_LICENSE_KEY = "avp_live_bridge_secret_key_do_not_leak_abcdef"
ENTITLEMENT_TOKEN = "avp_ent_bridge.token.secret.do.not.leak"
_CONTRACT_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "paid_activation_public_contract.json"
)
FORBIDDEN_MARKERS = (
    RAW_LICENSE_KEY,
    ENTITLEMENT_TOKEN,
    "https://",
    "http://",
    "/Users/",
    "/private/",
    "presigned",
    "artifact_id",
    "art_pkg_",
    "entitlement_token",
    "install_token",
    "X-Amz-",
    "backend_url",
)


def _public_paid_contract() -> dict:
    return json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))


@dataclass
class _FakeBackend:
    wheel_bytes: bytes
    artifact_hash: str
    artifact_size: int

    def validate_activation(self, license_key: str) -> ActivationValidateResult:
        assert license_key == RAW_LICENSE_KEY
        activation_accepted = True
        return ActivationValidateResult(
            valid=activation_accepted,
            customer_ref_fingerprint="cust_fp",
            plan="builder",
            license_status="active",
            subscription_status="active",
            period_end=None,
            public_fallback_available=True,
            error_code=None,
        )

    def issue_entitlement(self, license_key: str, validation: ActivationValidateResult) -> EntitlementResult:
        del license_key, validation
        return EntitlementResult(
            entitlement_token=ENTITLEMENT_TOKEN,
            entitlement_id="ent_bridge_001",
            expires_at=None,
        )

    def check_install_safety(self, entitlement_token: str) -> InstallSafetyResult:
        assert entitlement_token == ENTITLEMENT_TOKEN
        return InstallSafetyResult(
            ok=True,
            decision="allow",
            reason_code="workspace_registry_trusted",
            install_safety_state="verified",
            live_enforcement="HOLD",
            public_warning=None,
            error_code=None,
        )

    def authorize_package(
        self,
        entitlement_token: str,
        *,
        artifact_id: str,
        platform_name: str,
        python_version: str,
    ) -> PackageAuthorizeResult:
        del artifact_id, platform_name, python_version
        assert entitlement_token == ENTITLEMENT_TOKEN
        return PackageAuthorizeResult(
            download_authorized=True,
            artifact_id="art_pkg_private_policy_001",
            package_name=PACKAGE_NAME,
            package_version=PACKAGE_VERSION,
            artifact_hash=self.artifact_hash,
            artifact_size_bytes=self.artifact_size,
            download_authorization_id="dlauth_bridge_001",
            public_fallback_available=True,
            error_code=None,
        )

    def download_package(self, authorization: PackageAuthorizeResult) -> bytes:
        assert authorization.download_authorization_id == "dlauth_bridge_001"
        return self.wheel_bytes


def _wheel_bytes(tmp_path: Path) -> tuple[bytes, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    module = PACKAGE_NAME.replace("-", "_")
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{module}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(
            f"{module}-{PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{module}-{PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    data = wheel_path.read_bytes()
    return data, sha256_hex(data)


@pytest.fixture(autouse=True)
def _reset_backend(monkeypatch):
    set_paid_backend_client(None)
    monkeypatch.setenv("AVP_PAID_API_BASE_URL", "")
    yield
    set_paid_backend_client(None)


def _assert_privacy(text: str) -> None:
    for marker in FORBIDDEN_MARKERS:
        assert marker not in text


def test_public_paid_contract_fixture_is_stable_and_privacy_safe():
    contract = _public_paid_contract()
    assert contract["schema_version"] == "avp.paid_activation.public_contract.v1"
    assert contract["default_paid_api_base_url"] == DEFAULT_PAID_API_BASE_URL
    activation_keys = set(contract["durable_files"]["activation_json"]["allowed_keys"])
    install_keys = set(contract["durable_files"]["install_json"]["allowed_keys"])
    assert activation_keys == set(BOUNDED_ACTIVATION_KEYS)
    assert install_keys == set(BOUNDED_INSTALL_KEYS)
    assert contract["durable_files"]["install_json"]["active_example"]["provider_id"] == PROVIDER_ID
    assert "private_consumer" in contract["notes"]


def test_unset_paid_api_base_url_uses_packaged_default(monkeypatch):
    monkeypatch.delenv("AVP_PAID_API_BASE_URL", raising=False)
    client = resolve_paid_backend_client()
    assert isinstance(client, HttpPaidBackendClient)
    assert client._base_url == DEFAULT_PAID_API_BASE_URL
    assert client._base_url == _public_paid_contract()["default_paid_api_base_url"]


def test_blank_paid_api_base_url_disables_network(monkeypatch):
    monkeypatch.setenv("AVP_PAID_API_BASE_URL", "")
    assert resolve_paid_backend_client() is None


def test_activate_writes_compatible_activation_and_install(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(wheel_bytes=wheel, artifact_hash=digest, artifact_size=len(wheel))
    )

    from agentveil_mcp_proxy.paid_activation import build_paid_activate_payload

    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE
    assert payload["install"]["provider_id"] == PROVIDER_ID
    assert payload["install"]["package_name"] == PACKAGE_NAME

    activation_file = home / "paid" / ACTIVATION_FILENAME
    install_file = home / "paid" / INSTALL_FILENAME
    assert sorted(p.name for p in (home / "paid").iterdir() if p.suffix == ".json") == [
        ACTIVATION_FILENAME,
        INSTALL_FILENAME,
    ]
    saved_activation = json.loads(activation_file.read_text(encoding="utf-8"))
    saved_install = json.loads(install_file.read_text(encoding="utf-8"))
    contract = _public_paid_contract()
    assert set(saved_activation) <= set(
        contract["durable_files"]["activation_json"]["allowed_keys"]
    )
    assert set(saved_install) <= set(contract["durable_files"]["install_json"]["allowed_keys"])
    assert saved_activation["status"] == STATUS_ACTIVE
    assert saved_install["status"] == STATUS_ACTIVE
    assert saved_install["provider_id"] == "private_v1"
    entitlement_status, enabled = map_public_paid_enablement(saved_activation, saved_install)
    assert entitlement_status == STATUS_ACTIVE
    assert enabled is True
    hints = public_install_hints(saved_install)
    assert hints == {
        "package_name": PACKAGE_NAME,
        "package_version": PACKAGE_VERSION,
        "provider_id": "private_v1",
    }
    _assert_privacy(activation_file.read_text(encoding="utf-8"))
    _assert_privacy(install_file.read_text(encoding="utf-8"))
    _assert_privacy(json.dumps(payload, sort_keys=True))


def test_stdin_activate_cli_writes_bridge_files(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(wheel_bytes=wheel, artifact_hash=digest, artifact_size=len(wheel))
    )
    out = io.StringIO()
    code = run_paid_activate_cli(
        license_key=None,
        license_key_stdin=True,
        home=home,
        out=out,
        stdin=io.StringIO(f"{RAW_LICENSE_KEY}\n"),
    )
    assert code == 0
    text = out.getvalue()
    assert "Status: active" in text
    assert "Provider: private_v1" in text
    _assert_privacy(text)
    activation = load_activation_state(activation_path(home))
    install = load_install_state(install_state_path(home))
    assert activation is not None and install is not None
    assert map_public_paid_enablement(activation, install) == (STATUS_ACTIVE, True)
    assert "provider_id=" not in text
    assert "package_name=" not in text


def test_backend_unavailable_activate_is_non_zero_and_not_active(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_PAID_API_BASE_URL", "http://127.0.0.1:1")
    out = io.StringIO()
    from agentveil_mcp_proxy.paid_activation import PaidActivationError

    with pytest.raises(PaidActivationError) as exc_info:
        run_paid_activate_cli(
            license_key=RAW_LICENSE_KEY,
            home=home,
            out=out,
        )
    assert exc_info.value.exit_code != 0
    assert not (home / "paid" / INSTALL_FILENAME).exists()
    if (home / "paid" / ACTIVATION_FILENAME).exists():
        saved = json.loads((home / "paid" / ACTIVATION_FILENAME).read_text(encoding="utf-8"))
        assert saved.get("status") != STATUS_ACTIVE
    combined = out.getvalue() + str(exc_info.value)
    assert "Traceback" not in combined
    assert "/Users/" not in combined
    assert RAW_LICENSE_KEY not in combined


@pytest.mark.parametrize("row", _public_paid_contract()["enablement"]["core_fallback_matrix"])
def test_enablement_matrix_matches_public_contract_fixture(row):
    activation = {
        "status": row["activation_status"],
        "provider_present": row["activation_status"] == STATUS_ACTIVE,
        "license_id": "lic_x",
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": "2026-07-23T00:00:00+00:00",
        "public_fallback_available": True,
        "error_code": None,
    }
    install = {
        "status": row["install_status"],
        "provider_id": "private_v1",
        "package_name": PACKAGE_NAME,
        "package_version": PACKAGE_VERSION,
        "public_fallback_available": True,
        "error_code": None,
        "last_installed_at": "2026-07-23T00:00:00+00:00",
        "install_safety_state": "verified",
        "install_safety_reason": None,
    }
    assert map_public_paid_enablement(activation, install) == (
        row["entitlement_status"],
        row["provider_enabled"],
    )


def test_status_preserves_expired_activation_for_core_fallback(tmp_path):
    home = tmp_path / "avp-home"
    write_activation_state(
        activation_path(home),
        {
            "status": STATUS_EXPIRED,
            "provider_present": True,
            "license_id": "lic_expired",
            "customer_id": None,
            "expires_at": "2026-01-01T00:00:00+00:00",
            "last_checked_at": "2026-07-01T00:00:00+00:00",
            "public_fallback_available": True,
            "error_code": STATUS_EXPIRED,
        },
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
            "last_installed_at": "2026-07-01T00:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )

    payload = build_paid_status_payload(home=home)
    assert payload["activation"]["status"] == STATUS_EXPIRED
    assert payload["paid_activation_available"] is False
    assert payload["public_fallback_active"] is True
    saved = load_activation_state(activation_path(home))
    assert saved is not None
    assert saved["status"] == STATUS_EXPIRED
    assert map_public_paid_enablement(saved, load_install_state(install_state_path(home))) == (
        STATUS_EXPIRED,
        False,
    )
    _assert_privacy(json.dumps(payload, sort_keys=True))


def test_deactivate_disables_paid_state(tmp_path):
    home = tmp_path / "avp-home"
    write_activation_state(
        activation_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_present": True,
            "license_id": "lic_active",
            "customer_id": None,
            "expires_at": None,
            "last_checked_at": "2026-07-23T00:00:00+00:00",
            "public_fallback_available": True,
            "error_code": None,
        },
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
            "last_installed_at": "2026-07-23T00:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )

    payload = build_paid_deactivate_payload(home=home)
    assert payload["activation"]["status"] == STATUS_MISSING
    assert payload["paid_activation_available"] is False
    assert payload["public_fallback_active"] is True
    assert load_install_state(install_state_path(home)) is None
    activation = load_activation_state(activation_path(home))
    assert activation is not None
    assert map_public_paid_enablement(activation, None) == (STATUS_MISSING, False)


def test_package_mismatch_stays_core_fallback_compatible():
    activation = {
        "status": STATUS_ACTIVE,
        "provider_present": True,
        "license_id": "lic_x",
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": "2026-07-23T00:00:00+00:00",
        "public_fallback_available": True,
        "error_code": None,
    }
    install = {
        "status": STATUS_ACTIVE,
        "provider_id": "private_v1",
        "package_name": "agentveil-private-policy-team",
        "package_version": "9.9.9",
        "public_fallback_available": True,
        "error_code": None,
        "last_installed_at": "2026-07-23T00:00:00+00:00",
        "install_safety_state": "verified",
        "install_safety_reason": None,
    }
    status, enabled = map_public_paid_enablement(activation, install)
    assert status == STATUS_ACTIVE and enabled is True
    hints = public_install_hints(install)
    assert hints is not None
    assert hints["package_name"] == "agentveil-private-policy-team"
    _assert_privacy(json.dumps({"activation": activation, "install": install}))


def test_malformed_missing_files_are_core_fallback():
    assert map_public_paid_enablement(None, None) == (STATUS_MISSING, False)
    assert map_public_paid_enablement({"status": STATUS_ACTIVE}, None) == (
        STATUS_MISSING,
        False,
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"{not-json",
        b'["array"]',
        b'{"status":"active","extra":true}',
        b"",
    ],
)
def test_malformed_activation_bytes_status_cli_no_traceback(tmp_path, raw):
    home = tmp_path / "avp-home"
    path = activation_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    out = io.StringIO()
    code = run_paid_status_cli(home=home, output_json=True, out=out)
    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["paid_activation_available"] is False
    assert payload["public_fallback_active"] is True
    assert payload["activation"]["status"] in {STATUS_ERROR, STATUS_MISSING}
    if payload["activation"]["status"] == STATUS_ERROR:
        assert payload["activation"]["error_code"] == ERROR_ACTIVATION_STATE_UNREADABLE
    text = out.getvalue()
    assert "Traceback" not in text
    assert str(home) not in text
    assert "/Users/" not in text
    assert RAW_LICENSE_KEY not in text


@pytest.mark.parametrize(
    "raw",
    [
        b"{not-json",
        b'{"status":"active","provider_id":"x","extra":1}',
        b"",
    ],
)
def test_malformed_install_bytes_are_ignored_for_enablement(tmp_path, raw):
    home = tmp_path / "avp-home"
    write_activation_state(
        activation_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_present": True,
            "license_id": "lic_x",
            "customer_id": None,
            "expires_at": None,
            "last_checked_at": "2026-07-23T00:00:00+00:00",
            "public_fallback_available": True,
            "error_code": None,
        },
    )
    install_path = install_state_path(home)
    install_path.parent.mkdir(parents=True, exist_ok=True)
    install_path.write_bytes(raw)
    assert load_install_state(install_path) is None
    payload = build_paid_status_payload(home=home)
    assert payload["paid_activation_available"] is False
    assert map_public_paid_enablement(
        load_activation_state(activation_path(home)),
        load_install_state(install_path),
    )[1] is False
