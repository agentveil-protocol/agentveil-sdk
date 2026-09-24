# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

"""Tests for bounded Console free Builder preview client and install sync."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agentveil_mcp_proxy.console_credentials import (
    CredentialError,
    StoredCredential,
    save_credential,
)
from agentveil_mcp_proxy.console_free_builder_client import (
    CONSOLE_ORIGIN,
    FreeBuilderClientError,
    RawResponse,
    TransportError,
    assert_download_request_public_bounded,
    build_download_request_payload,
    run_paid_upgrade_free_builder_cli,
    sync_free_builder_install,
    upgrade_free_builder_to_paired,
)
from agentveil_mcp_proxy.paid_activation import activation_path
from agentveil_mcp_proxy.console_project_status_client import resolve_private_guardrails_status
from agentveil_mcp_proxy.paid_install import (
    COMPOSED_BASE_PACKAGE_NAME,
    COMPOSED_BASE_PACKAGE_VERSION,
    COMPOSED_INSTALL_COMPOSITION_VERSION,
    COMPOSED_THIN_PACKAGE_VERSION,
    COMPONENT_ROLE_BASE,
    COMPONENT_ROLE_THIN,
    DEFAULT_PACKAGE_NAME,
    ERROR_PACKAGE_NAME_MISMATCH,
    FreeBuilderInstallError,
    FreeBuilderWheelExpectations,
    install_state_path,
    install_wheel_to_vendor,
    resolve_vendored_controlled_alternative_authority,
    resolve_vendored_controlled_alternative_provider,
    resolve_vendored_paid_provider,
    run_free_builder_install_flow,
    run_free_builder_paired_install_flow,
    scan_paid_output_for_leaks,
    sha256_hex,
    vendor_root,
    verify_free_builder_wheel_artifact,
    write_install_state,
)
from agentveil_mcp_proxy.paid_provider import (
    PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    STATUS_EXPIRED,
    STATUS_REVOKED,
    STATUS_WITHIN_GRACE,
    PaidProviderSnapshot,
    discover_paid_provider,
    set_paid_provider_loader,
)
from agentveil_mcp_proxy.paid_provider import (
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
    PAID_PROVIDER_ENTRYPOINT_GROUP,
)
from agentveil_mcp_proxy.controlled_alternatives import (
    CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP,
)

TOKEN = "console-device-token-secret"
SECRET = "SECRET_FREE_BUILDER_CANARY"
PACKAGE_NAME = "agentveil-private-policy-thin"
PACKAGE_VERSION = "0.1.0"
MODULE_NAME = PACKAGE_NAME.replace("-", "_")

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
import os
from pathlib import Path

class _Provider:
    provider_id = "private_v1"
    provider_contract_version = "1"

    def _install_path(self):
        home = os.environ.get("AVP_HOME")
        if not home:
            return None
        return Path(home) / "paid" / "install.json"

    def status(self):
        install_path = self._install_path()
        if install_path is None or not install_path.is_file():
            return {
                "provider_present": True,
                "provider_id": self.provider_id,
                "provider_contract_version": self.provider_contract_version,
                "status": "missing",
                "private_provider_enabled": False,
                "public_fallback_available": True,
                "summary": "Awaiting install state.",
                "error_code": None,
            }
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


def _active_provider_snapshot(**overrides):
    base = PaidProviderSnapshot(
        provider_present=True,
        provider_id="private_v1",
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=STATUS_ACTIVE,
        private_provider_enabled=True,
        public_fallback_available=True,
        summary="Installed private_v1 bridge",
        error_code=None,
    )
    if not overrides:
        return base
    return PaidProviderSnapshot(**{**base.__dict__, **overrides})


def _json_response(status, obj, *, content_type="application/json"):
    body = json.dumps(obj).encode("utf-8")
    content_types = () if content_type is None else (content_type,)
    return RawResponse(status=status, content_types=content_types, body=body)


def _octet_response(status, body: bytes):
    return RawResponse(
        status=status,
        content_types=("application/octet-stream",),
        body=body,
    )


def _eligible_response(
    wheel_bytes: bytes,
    artifact_hash: str,
    *,
    package_name: str = PACKAGE_NAME,
    package_version: str = PACKAGE_VERSION,
) -> dict[str, object]:
    return {
        "eligible": True,
        "artifact_hash": artifact_hash,
        "artifact_size_bytes": len(wheel_bytes),
        "package_name": package_name,
        "package_version": package_version,
    }


def _v2_not_found_response() -> RawResponse:
    return _json_response(404, {"eligible": False})


def _with_v1_fallback(responses: list[RawResponse]) -> list[RawResponse]:
    return [_v2_not_found_response(), *responses]


def _v2_eligible_response(
    *,
    base_hash: str,
    base_size: int,
    thin_hash: str,
    thin_size: int,
) -> dict[str, object]:
    return {
        "eligible": True,
        "contract_version": "v2",
        "components": [
            {
                "role": COMPONENT_ROLE_BASE,
                "package_name": COMPOSED_BASE_PACKAGE_NAME,
                "package_version": COMPOSED_BASE_PACKAGE_VERSION,
                "artifact_hash": base_hash,
                "artifact_size_bytes": base_size,
            },
            {
                "role": COMPONENT_ROLE_THIN,
                "package_name": PACKAGE_NAME,
                "package_version": COMPOSED_THIN_PACKAGE_VERSION,
                "artifact_hash": thin_hash,
                "artifact_size_bytes": thin_size,
            },
        ],
    }


def _inactive_provider_snapshot(status):
    return PaidProviderSnapshot(
        provider_present=True,
        provider_id="private_v1",
        provider_contract_version=PUBLIC_PAID_PROVIDER_CONTRACT_VERSION,
        status=status,
        private_provider_enabled=False,
        public_fallback_available=True,
        summary=None,
        error_code=None,
    )


@dataclass
class BackendEchoTransport:
    calls: list[tuple[str, str, dict[str, str], bytes | None]] = field(default_factory=list)
    responses: list[RawResponse] = field(default_factory=list)

    def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> RawResponse:
        del timeout
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise TransportError()
        return self.responses.pop(0)


def _entry_points_text(*, target: str, provider_target: str | None = None) -> str:
    provider_target = provider_target or f"{MODULE_NAME}.vendored_provider:build_vendored_provider"
    return (
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = {target}\n"
        f"\n"
        f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {provider_target}\n"
    )


def _build_wheel(
    tmp_path: Path,
    *,
    package_name: str = PACKAGE_NAME,
    package_version: str = PACKAGE_VERSION,
    hook_source: str = SUCCESS_HOOK_SOURCE,
    include_paid_provider: bool = True,
    entry_points: str | None = None,
) -> tuple[bytes, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    module_name = package_name.replace("-", "_")
    wheel_path = tmp_path / f"{package_name}-{package_version}.whl"
    if entry_points is None:
        entry_points = _entry_points_text(target=f"{module_name}.handoff_hook:run_activation_handoff")
        if not include_paid_provider:
            entry_points = (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{module_name}.handoff_hook:run_activation_handoff\n"
            )
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{module_name}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{module_name}/handoff_hook.py", hook_source)
        if include_paid_provider:
            archive.writestr(f"{module_name}/vendored_provider.py", VENDORED_PROVIDER_SOURCE)
        archive.writestr(
            f"{module_name}-{package_version}.dist-info/METADATA",
            f"Name: {package_name}\nVersion: {package_version}\n",
        )
        archive.writestr(
            f"{module_name}-{package_version}.dist-info/entry_points.txt",
            entry_points,
        )
        archive.writestr(
            f"{module_name}-{package_version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    wheel_bytes = wheel_path.read_bytes()
    return wheel_bytes, sha256_hex(wheel_bytes)


def _build_base_wheel(tmp_path: Path) -> tuple[bytes, str]:
    module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    entry_points = (
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
        f"{module}.handoff_hook:run_activation_handoff\n\n"
        f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {module}.vendored_provider:build_vendored_provider\n"
    )
    return _build_wheel(
        tmp_path,
        package_name=COMPOSED_BASE_PACKAGE_NAME,
        package_version=COMPOSED_BASE_PACKAGE_VERSION,
        entry_points=entry_points,
    )


def _build_thin_wheel(tmp_path: Path) -> tuple[bytes, str]:
    module = PACKAGE_NAME.replace("-", "_")
    ca_source = """
class _Provider:
    calls = []
    def descriptor(self):
        self.calls.append('descriptor')
        return {'provider_id': 'private_v1'}
def build_provider():
    return _Provider()
"""
    entry_points = (
        f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {module}.controlled_provider:build_provider\n"
        "[agentveil_mcp_proxy.controlled_alternative_authorities]\n"
        f"ca_route_v1 = {module}.controlled_provider:build_provider\n"
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{module}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{module}/controlled_provider.py", ca_source)
        archive.writestr(
            f"{module}-{COMPOSED_THIN_PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {PACKAGE_NAME}\nVersion: {COMPOSED_THIN_PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{module}-{COMPOSED_THIN_PACKAGE_VERSION}.dist-info/entry_points.txt",
            entry_points,
        )
        archive.writestr(
            f"{module}-{COMPOSED_THIN_PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    wheel_bytes = wheel_path.read_bytes()
    return wheel_bytes, sha256_hex(wheel_bytes)


@pytest.fixture(autouse=True)
def _reset_paid_provider_loader():
    set_paid_provider_loader(None)
    yield
    set_paid_provider_loader(None)


def test_build_download_request_payload_accepts_only_bounded_fields():
    payload = build_download_request_payload(platform="linux", python_version="3.12")
    assert payload == {"platform": "linux", "python_version": "3.12"}
    assert_download_request_public_bounded(payload)


def test_build_download_request_payload_rejects_forbidden_fields():
    payload = {"platform": "linux", "python_version": "3.12", "artifact_id": "art_x"}
    with pytest.raises(FreeBuilderClientError, match="invalid_request"):
        assert_download_request_public_bounded(payload)


def test_sync_skipped_without_credential(tmp_path):
    transport = BackendEchoTransport()
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "skipped_no_credential"
    assert transport.calls == []


def test_sync_skipped_on_unsafe_credential(tmp_path):
    transport = BackendEchoTransport()

    def _unsafe(*, home=None):
        raise CredentialError("credential_invalid")

    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        load_credential_fn=_unsafe,
    )
    assert result == "skipped_unsafe_credential"
    assert transport.calls == []


def test_sync_skipped_on_wrong_scope(tmp_path):
    transport = BackendEchoTransport()
    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        load_credential_fn=lambda home=None: StoredCredential(
            scope="wrong_scope",
            token=TOKEN,
        ),
    )
    assert result == "skipped_unsafe_credential"
    assert transport.calls == []


def test_sync_skipped_when_already_active(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=_with_v1_fallback([_json_response(200, {"eligible": True})])
    )
    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=lambda: _active_provider_snapshot(),
    )
    assert result == "skipped_already_active"
    assert transport.calls == []


def test_sync_skipped_when_ineligible(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [_json_response(200, {"eligible": False, "error_code": "free_builder_capability_inactive"})]
        )
    )
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "skipped_ineligible"
    assert len(transport.calls) == 2
    assert transport.calls[0][0] == "GET"
    assert "/console/free-builder/package/v2/eligibility" in transport.calls[0][1]
    assert transport.calls[1][0] == "GET"
    assert transport.calls[1][1] == CONSOLE_ORIGIN + "/console/free-builder/package/eligibility"


def test_sync_rejected_when_eligible_missing_trusted_hash(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=_with_v1_fallback([_json_response(200, {"eligible": True})])
    )
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "rejected"
    assert len(transport.calls) == 2


def test_sync_skipped_existing_paid_terminal_state(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport()
    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=lambda: _inactive_provider_snapshot(STATUS_REVOKED),
    )
    assert result == "skipped_existing_paid_state"
    assert transport.calls == []


def test_sync_skipped_existing_paid_terminal_state_expired(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    result = sync_free_builder_install(
        home=tmp_path,
        transport=BackendEchoTransport(),
        discover_paid_provider_fn=lambda: _inactive_provider_snapshot(STATUS_EXPIRED),
    )
    assert result == "skipped_existing_paid_state"


def test_sync_skipped_existing_paid_terminal_state_disabled(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    result = sync_free_builder_install(
        home=tmp_path,
        transport=BackendEchoTransport(),
        discover_paid_provider_fn=lambda: _inactive_provider_snapshot(STATUS_DISABLED),
    )
    assert result == "skipped_existing_paid_state"


def test_sync_unavailable_on_transport_failure(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport()
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "unavailable"


def test_sync_rejected_on_malformed_eligibility(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [_json_response(200, {"eligible": True, "unexpected": True})]
        )
    )
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "rejected"


def test_sync_happy_path_installs(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [
                _json_response(200, _eligible_response(wheel_bytes, artifact_hash)),
                _octet_response(200, wheel_bytes),
            ]
        )
    )
    provider_checks = {"calls": 0}

    def _discover():
        provider_checks["calls"] += 1
        if provider_checks["calls"] >= 2:
            return _active_provider_snapshot()
        return PaidProviderSnapshot(provider_present=False)

    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=_discover,
    )
    assert result == "installed"
    assert len(transport.calls) == 3
    download_body = json.loads(transport.calls[2][3].decode("utf-8"))
    assert set(download_body) == {"platform", "python_version"}
    assert TOKEN not in json.dumps(download_body)
    assert SECRET not in json.dumps(download_body)


def test_sync_rejects_legacy_eligibility_before_download(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [
                _json_response(
                    200,
                    _eligible_response(
                        wheel_bytes, artifact_hash, package_name="agentveil-private-policy"
                    ),
                )
            ]
        )
    )
    result = sync_free_builder_install(
        home=tmp_path, transport=transport,
        discover_paid_provider_fn=lambda: PaidProviderSnapshot(provider_present=False),
    )
    assert result == "rejected"
    assert len(transport.calls) == 2
    assert not (tmp_path / "paid").exists()


@pytest.mark.parametrize("expected_name", [PACKAGE_NAME, "agentveil-private-policy"])
def test_free_builder_rejects_legacy_wheel_before_install(tmp_path, expected_name):
    wheel_bytes, artifact_hash = _build_wheel(
        tmp_path / "wheel", package_name="agentveil-private-policy",
    )
    home = tmp_path / "home"
    with pytest.raises(FreeBuilderInstallError, match=ERROR_PACKAGE_NAME_MISMATCH):
        run_free_builder_install_flow(
            wheel_bytes=wheel_bytes, home=home, activation_credential=TOKEN,
            expectations=FreeBuilderWheelExpectations(
                artifact_hash=artifact_hash, artifact_size_bytes=len(wheel_bytes),
                package_name=expected_name, package_version=PACKAGE_VERSION,
            ),
        )
    assert not home.exists()


def test_sync_production_path_rejects_hash_mismatch(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    wrong_hash = "0" * len(artifact_hash)
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [
                _json_response(200, _eligible_response(wheel_bytes, wrong_hash)),
                _octet_response(200, wheel_bytes),
            ]
        )
    )
    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=lambda: PaidProviderSnapshot(provider_present=False),
    )
    assert result == "skipped_install_failed"
    assert len(transport.calls) == 3


def test_sync_download_request_never_includes_forbidden_authority_fields(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [
                _json_response(200, _eligible_response(wheel_bytes, artifact_hash)),
                _octet_response(200, wheel_bytes),
            ]
        )
    )

    sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        install_flow_fn=lambda **kwargs: None,
        discover_paid_provider_fn=lambda: PaidProviderSnapshot(provider_present=False),
    )
    download_body = json.loads(transport.calls[2][3].decode("utf-8"))
    for forbidden in (
        "artifact_id",
        "workspace_id",
        "issuer_reference",
        "license_key",
        "license_id",
        "presigned_url",
    ):
        assert forbidden not in download_body


def test_sync_install_failure_is_silent_no_op(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [
                _json_response(200, _eligible_response(wheel_bytes, artifact_hash)),
                _octet_response(200, wheel_bytes),
            ]
        )
    )

    def _fail_install(**kwargs):
        raise FreeBuilderInstallError("install_failed")

    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        install_flow_fn=_fail_install,
        discover_paid_provider_fn=lambda: PaidProviderSnapshot(provider_present=False),
    )
    assert result == "skipped_install_failed"


def _expectations_for_wheel(wheel_bytes: bytes, artifact_hash: str) -> FreeBuilderWheelExpectations:
    return FreeBuilderWheelExpectations(
        artifact_hash=artifact_hash,
        artifact_size_bytes=len(wheel_bytes),
        package_name=PACKAGE_NAME,
        package_version=PACKAGE_VERSION,
    )


def test_verify_free_builder_wheel_rejects_wrong_hash(tmp_path):
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    wrong_hash = "0" * len(artifact_hash)
    with pytest.raises(FreeBuilderInstallError):
        verify_free_builder_wheel_artifact(
            wheel_bytes,
            expectations=_expectations_for_wheel(wheel_bytes, wrong_hash),
        )


def test_verify_free_builder_wheel_rejects_missing_hash(tmp_path):
    wheel_bytes, _artifact_hash = _build_wheel(tmp_path / "wheel")
    with pytest.raises(FreeBuilderInstallError, match="artifact_hash_required"):
        verify_free_builder_wheel_artifact(wheel_bytes, expectations=FreeBuilderWheelExpectations())


def test_verify_free_builder_wheel_rejects_wrong_package_name(tmp_path):
    wheel_bytes, artifact_hash = _build_wheel(
        tmp_path / "wheel",
        package_name="not-allowed-package",
    )
    with pytest.raises(FreeBuilderInstallError, match=ERROR_PACKAGE_NAME_MISMATCH):
        verify_free_builder_wheel_artifact(
            wheel_bytes,
            expectations=_expectations_for_wheel(wheel_bytes, artifact_hash),
        )


def test_run_free_builder_install_flow_requires_provider_active(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel", include_paid_provider=False)
    with pytest.raises(FreeBuilderInstallError, match="provider_not_active"):
        run_free_builder_install_flow(
            wheel_bytes=wheel_bytes,
            home=home,
            activation_credential=TOKEN,
            expectations=_expectations_for_wheel(wheel_bytes, artifact_hash),
        )


def test_run_free_builder_install_flow_discovers_vendored_provider(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    result = run_free_builder_install_flow(
        wheel_bytes=wheel_bytes,
        home=home,
        activation_credential=TOKEN,
        expectations=_expectations_for_wheel(wheel_bytes, artifact_hash),
    )
    assert result.install_state["status"] == STATUS_ACTIVE
    snapshot = discover_paid_provider()
    assert snapshot.provider_present is True
    assert snapshot.provider_id == "private_v1"
    assert snapshot.status == STATUS_ACTIVE
    assert snapshot.private_provider_enabled is True
    assert resolve_private_guardrails_status(snapshot) == "active"


def test_run_free_builder_install_flow_active_in_fresh_subprocess(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    run_free_builder_install_flow(
        wheel_bytes=wheel_bytes,
        home=home,
        activation_credential=TOKEN,
        expectations=_expectations_for_wheel(wheel_bytes, artifact_hash),
    )
    repo_root = Path(__file__).resolve().parents[3]
    package_root = repo_root / "packages" / "agentveil-mcp-proxy"
    env = {
        **os.environ,
        "AVP_HOME": str(home),
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": os.pathsep.join((str(repo_root), str(package_root))),
    }
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "from agentveil_mcp_proxy.paid_provider import discover_paid_provider;"
            "from agentveil_mcp_proxy.console_project_status_client import resolve_private_guardrails_status;"
            "snapshot = discover_paid_provider();"
            "print(snapshot.status, snapshot.provider_present, resolve_private_guardrails_status(snapshot))",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "active True active"
    assert TOKEN not in probe.stdout
    assert TOKEN not in probe.stderr
    assert str(home) not in probe.stdout


def test_run_free_builder_install_flow_succeeds_with_active_provider(tmp_path):
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    result = run_free_builder_install_flow(
        wheel_bytes=wheel_bytes,
        home=tmp_path,
        activation_credential=TOKEN,
        expectations=_expectations_for_wheel(wheel_bytes, artifact_hash),
        discover_paid_provider_fn=lambda: _active_provider_snapshot(),
    )
    assert result.install_state["status"] == STATUS_ACTIVE
    assert resolve_private_guardrails_status(_active_provider_snapshot()) == "active"


def test_sync_rejected_on_redirect(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=[RawResponse(status=302, content_types=("application/json",), body=b"")]
    )
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "rejected"


def test_sync_rejected_on_non_json_eligibility(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=[RawResponse(status=200, content_types=("text/plain",), body=b"eligible=true")]
    )
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "rejected"


def test_sync_v2_paired_install_success(tmp_path, monkeypatch):
    save_credential(TOKEN, home=tmp_path)
    monkeypatch.setenv("AVP_HOME", str(tmp_path))
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
            _octet_response(200, base_bytes),
            _octet_response(200, thin_bytes),
        ]
    )
    provider_checks = {"calls": 0}

    def _discover():
        provider_checks["calls"] += 1
        return PaidProviderSnapshot(provider_present=False)

    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=_discover,
    )
    assert result == "installed"
    assert provider_checks["calls"] == 1
    assert len(transport.calls) == 3
    assert transport.calls[0][0] == "GET"
    assert "platform=" in transport.calls[0][1]
    assert "python_version=" in transport.calls[0][1]
    assert transport.calls[1][0] == "POST"
    assert transport.calls[1][1] == CONSOLE_ORIGIN + "/console/free-builder/package/v2/download"
    base_body = json.loads(transport.calls[1][3].decode("utf-8"))
    assert set(base_body) == {"role", "platform", "python_version"}
    assert base_body["role"] == COMPONENT_ROLE_BASE
    thin_body = json.loads(transport.calls[2][3].decode("utf-8"))
    assert thin_body["role"] == COMPONENT_ROLE_THIN
    assert TOKEN not in json.dumps(base_body)
    install_state = json.loads(install_state_path(tmp_path).read_text(encoding="utf-8"))
    assert install_state["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    assert resolve_vendored_paid_provider(home=tmp_path) is not None
    provider, error = resolve_vendored_controlled_alternative_provider(home=tmp_path)
    assert error is None and provider is not None
    authority, authority_error = resolve_vendored_controlled_alternative_authority(home=tmp_path)
    assert authority_error is None and authority is not None


def test_sync_v2_ineligible_does_not_fallback_to_v1(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    transport = BackendEchoTransport(
        responses=[_json_response(200, {"eligible": False, "error_code": "capability_inactive"})]
    )
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "skipped_ineligible"
    assert len(transport.calls) == 1
    assert "/v2/eligibility" in transport.calls[0][1]


def test_sync_v2_404_falls_back_to_v1(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "wheel")
    transport = BackendEchoTransport(
        responses=_with_v1_fallback(
            [
                _json_response(200, _eligible_response(wheel_bytes, artifact_hash)),
                _octet_response(200, wheel_bytes),
            ]
        )
    )
    provider_checks = {"calls": 0}

    def _discover():
        provider_checks["calls"] += 1
        if provider_checks["calls"] >= 2:
            return _active_provider_snapshot()
        return PaidProviderSnapshot(provider_present=False)

    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=_discover,
    )
    assert result == "installed"
    assert len(transport.calls) == 3


def test_sync_v2_malformed_components_rejected(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    swapped = _v2_eligible_response(
        base_hash=base_hash,
        base_size=len(base_bytes),
        thin_hash=thin_hash,
        thin_size=len(thin_bytes),
    )
    components = swapped["components"]
    swapped["components"] = [components[1], components[0]]
    transport = BackendEchoTransport(responses=[_json_response(200, swapped)])
    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=lambda: PaidProviderSnapshot(provider_present=False),
    )
    assert result == "rejected"
    assert len(transport.calls) == 1


def test_sync_v2_duplicate_role_rejected(tmp_path):
    save_credential(TOKEN, home=tmp_path)
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    payload = _v2_eligible_response(
        base_hash=base_hash,
        base_size=len(base_bytes),
        thin_hash=base_hash,
        thin_size=len(base_bytes),
    )
    payload["components"] = [payload["components"][0], dict(payload["components"][0])]
    transport = BackendEchoTransport(responses=[_json_response(200, payload)])
    result = sync_free_builder_install(home=tmp_path, transport=transport)
    assert result == "rejected"


def test_run_free_builder_paired_install_flow_rollback_on_state_write_failure(
    tmp_path, monkeypatch,
):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    import agentveil_mcp_proxy.paid_install as paid_install_module

    original_write = paid_install_module.write_install_state

    def _fail_write(path, data):  # noqa: ANN001
        raise OSError("simulated state write failure")

    monkeypatch.setattr(paid_install_module, "write_install_state", _fail_write)
    with pytest.raises(FreeBuilderInstallError):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_bytes,
            thin_wheel_bytes=thin_bytes,
            home=home,
            activation_credential=TOKEN,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_bytes),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_bytes),
                package_name=PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
            discover_paid_provider_fn=lambda: _active_provider_snapshot(),
        )
    monkeypatch.setattr(paid_install_module, "write_install_state", original_write)
    assert not install_state_path(home).exists()
    assert not (vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").exists()


def test_sync_v2_success_ignores_post_install_discover_inactive(tmp_path, monkeypatch):
    save_credential(TOKEN, home=tmp_path)
    monkeypatch.setenv("AVP_HOME", str(tmp_path))
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
            _octet_response(200, base_bytes),
            _octet_response(200, thin_bytes),
        ]
    )
    provider_checks = {"calls": 0}

    def _discover():
        provider_checks["calls"] += 1
        if provider_checks["calls"] == 1:
            return PaidProviderSnapshot(provider_present=False)
        return _inactive_provider_snapshot(STATUS_REVOKED)

    result = sync_free_builder_install(
        home=tmp_path,
        transport=transport,
        discover_paid_provider_fn=_discover,
    )
    assert result == "installed"
    assert provider_checks["calls"] == 1
    install_state = json.loads(install_state_path(tmp_path).read_text(encoding="utf-8"))
    assert install_state["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    assert TOKEN not in json.dumps(install_state)
    assert SECRET not in json.dumps(install_state)
    assert resolve_vendored_paid_provider(home=tmp_path) is not None


def test_run_free_builder_paired_rollback_when_post_commit_vendored_provider_inactive(
    tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.paid_activation import activation_path
    from agentveil_mcp_proxy.paid_install import ERROR_VENDORED_PROVIDER_MALFORMED

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    install_path = install_state_path(home)
    install_path.parent.mkdir(parents=True, exist_ok=True)
    install_path.write_text(
        json.dumps(
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
            }
        ),
        encoding="utf-8",
    )
    prior_install_bytes = install_path.read_bytes()
    activation_file = activation_path(home)
    activation_file.parent.mkdir(parents=True, exist_ok=True)
    activation_file.write_text(
        json.dumps(
            {
                "status": STATUS_REVOKED,
                "provider_present": True,
                "license_id": "lic_prior",
                "customer_id": None,
                "expires_at": None,
                "last_checked_at": "2026-08-08T12:00:00+00:00",
                "public_fallback_available": True,
                "error_code": None,
            }
        ),
        encoding="utf-8",
    )
    prior_activation_bytes = activation_file.read_bytes()
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    legacy_wheel_bytes, _ = _build_wheel(tmp_path / "legacy-wheel")
    legacy_wheel_path = tmp_path / f"{PACKAGE_NAME}-{PACKAGE_VERSION}-legacy.whl"
    legacy_wheel_path.write_bytes(legacy_wheel_bytes)
    from agentveil_mcp_proxy.paid_install import install_wheel_to_vendor

    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel_path,
        target_dir=legacy_vendor,
        expected_package_name=PACKAGE_NAME,
        expected_package_version=PACKAGE_VERSION,
        require_empty_target=True,
    )
    legacy_marker = legacy_vendor / "legacy-marker.txt"
    legacy_marker.write_text("keep-me", encoding="utf-8")
    prior_vendor_bytes = legacy_marker.read_bytes()
    cache_path = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(b"prior-cache-wheel")
    prior_cache_bytes = cache_path.read_bytes()

    module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    postcommit_inactive_provider = """
import json
import os
from pathlib import Path

class _Provider:
    provider_id = 'private_v1'
    provider_contract_version = '1'

    def status(self):
        home = os.environ.get('AVP_HOME')
        install_path = Path(home) / 'paid' / 'install.json' if home else None
        if install_path is not None and install_path.is_file():
            return {
                'provider_present': True,
                'provider_id': 'private_v1',
                'provider_contract_version': '1',
                'status': 'revoked',
                'private_provider_enabled': False,
                'public_fallback_available': True,
                'summary': 'inactive after install',
                'error_code': None,
            }
        return {
            'provider_present': True,
            'provider_id': 'private_v1',
            'provider_contract_version': '1',
            'status': 'missing',
            'private_provider_enabled': False,
            'public_fallback_available': True,
            'summary': 'awaiting install state',
            'error_code': None,
        }

def build_vendored_provider():
    return _Provider()
"""
    handoff_writes_activation = """
def run_activation_handoff(request):
    from pathlib import Path
    import json
    activation = Path(request.avp_home) / 'paid' / 'activation.json'
    activation.parent.mkdir(parents=True, exist_ok=True)
    activation.write_text(json.dumps({
        "status": "active",
        "provider_present": True,
        "license_id": "lic_new",
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": "2026-01-01T00:00:00+00:00",
        "public_fallback_available": True,
        "error_code": None,
    }))
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    entry_points = (
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
        f"{module}.handoff_hook:run_activation_handoff\n\n"
        f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {module}.vendored_provider:build_vendored_provider\n"
    )
    base_dir = tmp_path / "base"
    base_dir.mkdir(parents=True, exist_ok=True)
    base_wheel_path = base_dir / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}.whl"
    with zipfile.ZipFile(base_wheel_path, "w") as archive:
        archive.writestr(f"{module}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{module}/handoff_hook.py", handoff_writes_activation)
        archive.writestr(f"{module}/vendored_provider.py", postcommit_inactive_provider)
        archive.writestr(
            f"{module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {COMPOSED_BASE_PACKAGE_NAME}\nVersion: {COMPOSED_BASE_PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt",
            entry_points,
        )
        archive.writestr(
            f"{module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    base_bytes = base_wheel_path.read_bytes()
    base_hash = sha256_hex(base_bytes)
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    with pytest.raises(FreeBuilderInstallError, match=ERROR_VENDORED_PROVIDER_MALFORMED):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_bytes,
            thin_wheel_bytes=thin_bytes,
            home=home,
            activation_credential=TOKEN,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_bytes),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_bytes),
                package_name=PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert install_path.read_bytes() == prior_install_bytes
    assert activation_file.read_bytes() == prior_activation_bytes
    assert legacy_marker.read_bytes() == prior_vendor_bytes
    assert cache_path.read_bytes() == prior_cache_bytes
    assert not (
        vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}"
    ).exists()
    assert not (vendor_root(home) / f"{PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}").exists()
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []


_PROXY_CONFIG_SENTINEL = b'{"schema":"sentinel-proxy-config-unchanged-v1"}\n'
_EVIDENCE_HISTORY_SENTINEL = b"SQLITE_SENTINEL_EVIDENCE_HISTORY_UNCHANGED_V1\n"


def _seed_proxy_config_and_evidence_sentinels(home: Path) -> tuple[bytes, bytes]:
    proxy_dir = home / "mcp-proxy"
    proxy_dir.mkdir(parents=True, exist_ok=True)
    (proxy_dir / "config.json").write_bytes(_PROXY_CONFIG_SENTINEL)
    (proxy_dir / "evidence.sqlite").write_bytes(_EVIDENCE_HISTORY_SENTINEL)
    return _PROXY_CONFIG_SENTINEL, _EVIDENCE_HISTORY_SENTINEL


def _assert_proxy_config_and_evidence_unchanged(
    home: Path,
    *,
    config_sentinel: bytes,
    evidence_sentinel: bytes,
) -> None:
    proxy_dir = home / "mcp-proxy"
    assert (proxy_dir / "config.json").read_bytes() == config_sentinel
    assert (proxy_dir / "evidence.sqlite").read_bytes() == evidence_sentinel


def _seed_legacy_active_thin_install(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    save_credential(TOKEN, home=home)
    wheel_bytes, artifact_hash = _build_wheel(tmp_path / "legacy-wheel")
    run_free_builder_install_flow(
        wheel_bytes=wheel_bytes,
        home=home,
        activation_credential=TOKEN,
        expectations=_expectations_for_wheel(wheel_bytes, artifact_hash),
    )
    install_state = json.loads(install_state_path(home).read_text(encoding="utf-8"))
    assert install_state.get("install_composition_version") is None
    skip = sync_free_builder_install(
        home=home,
        transport=BackendEchoTransport(
            responses=_with_v1_fallback([_json_response(200, {"eligible": True})])
        ),
        discover_paid_provider_fn=lambda: _active_provider_snapshot(),
    )
    assert skip == "skipped_already_active"
    return home


def test_upgrade_preview_without_apply_does_not_mutate_or_download(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    config_sentinel, evidence_sentinel = _seed_proxy_config_and_evidence_sentinels(home)
    prior_install_bytes = install_state_path(home).read_bytes()
    activation_file = activation_path(home)
    prior_activation_bytes = (
        activation_file.read_bytes() if activation_file.is_file() else None
    )
    legacy_marker_file = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}" / "legacy-marker.txt"
    legacy_marker_file.write_text("keep-me", encoding="utf-8")
    prior_marker_bytes = legacy_marker_file.read_bytes()

    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
        ]
    )
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "preview_ready"
    assert payload["apply"] is False
    assert payload["upgrade_available"] is True
    assert len(transport.calls) == 1
    assert install_state_path(home).read_bytes() == prior_install_bytes
    if prior_activation_bytes is None:
        assert not activation_file.is_file()
    else:
        assert activation_file.read_bytes() == prior_activation_bytes
    assert legacy_marker_file.read_bytes() == prior_marker_bytes
    _assert_proxy_config_and_evidence_unchanged(
        home,
        config_sentinel=config_sentinel,
        evidence_sentinel=evidence_sentinel,
    )
    rendered = json.dumps(payload, sort_keys=True)
    scan_paid_output_for_leaks(rendered, secrets=(TOKEN, SECRET))
    assert TOKEN not in rendered


def test_upgrade_apply_installs_exact_v2_pair_and_retains_legacy_vendor(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    config_sentinel, evidence_sentinel = _seed_proxy_config_and_evidence_sentinels(home)
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    legacy_marker = legacy_vendor / "legacy-marker.txt"
    legacy_marker.write_text("keep-me", encoding="utf-8")
    prior_marker_bytes = legacy_marker.read_bytes()
    prior_cache = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    prior_cache_bytes = prior_cache.read_bytes()

    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
            _octet_response(200, base_bytes),
            _octet_response(200, thin_bytes),
        ]
    )
    payload = upgrade_free_builder_to_paired(home=home, apply=True, transport=transport)
    assert payload["result_code"] == "upgraded"
    assert len(transport.calls) == 3
    install_state = json.loads(install_state_path(home).read_text(encoding="utf-8"))
    assert install_state["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    assert legacy_marker.read_bytes() == prior_marker_bytes
    assert prior_cache.read_bytes() == prior_cache_bytes
    assert resolve_vendored_paid_provider(home=home) is not None
    _assert_proxy_config_and_evidence_unchanged(
        home,
        config_sentinel=config_sentinel,
        evidence_sentinel=evidence_sentinel,
    )


def test_upgrade_v2_404_never_falls_back_to_v1(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    prior_install_bytes = install_state_path(home).read_bytes()
    transport = BackendEchoTransport(responses=[_v2_not_found_response()])
    payload = upgrade_free_builder_to_paired(home=home, apply=True, transport=transport)
    assert payload["result_code"] == "rejected"
    assert len(transport.calls) == 1
    assert "/v2/eligibility" in transport.calls[0][1]
    assert install_state_path(home).read_bytes() == prior_install_bytes


def test_upgrade_rejects_already_composed_install(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    install_path = install_state_path(home)
    composed = {
        "status": STATUS_ACTIVE,
        "provider_id": "private_v1",
        "package_name": COMPOSED_BASE_PACKAGE_NAME,
        "package_version": COMPOSED_BASE_PACKAGE_VERSION,
        "install_composition_version": COMPOSED_INSTALL_COMPOSITION_VERSION,
        "install_components": [
            {
                "role": COMPONENT_ROLE_BASE,
                "package_name": COMPOSED_BASE_PACKAGE_NAME,
                "package_version": COMPOSED_BASE_PACKAGE_VERSION,
            },
            {
                "role": COMPONENT_ROLE_THIN,
                "package_name": PACKAGE_NAME,
                "package_version": COMPOSED_THIN_PACKAGE_VERSION,
            },
        ],
        "public_fallback_available": True,
        "error_code": None,
        "last_installed_at": "2026-01-01T00:00:00+00:00",
        "install_safety_state": "verified",
        "install_safety_reason": None,
    }
    write_install_state(install_path, composed)
    transport = BackendEchoTransport()
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_already_composed"
    assert transport.calls == []


def test_upgrade_rejects_paid_license_install(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    save_credential(TOKEN, home=home)
    wheel_bytes, _ = _build_wheel(
        tmp_path / "paid-wheel",
        package_name=DEFAULT_PACKAGE_NAME,
        package_version="0.1.0",
    )
    wheel_path = tmp_path / f"{DEFAULT_PACKAGE_NAME}-0.1.0.whl"
    wheel_path.write_bytes(wheel_bytes)
    target_dir = vendor_root(home) / f"{DEFAULT_PACKAGE_NAME}-0.1.0"
    install_wheel_to_vendor(
        home=home,
        wheel_path=wheel_path,
        target_dir=target_dir,
        expected_package_name=DEFAULT_PACKAGE_NAME,
        expected_package_version="0.1.0",
        require_empty_target=True,
    )
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "private_v1",
            "package_name": DEFAULT_PACKAGE_NAME,
            "package_version": "0.1.0",
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-01-01T00:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )
    payload = upgrade_free_builder_to_paired(
        home=home,
        apply=False,
        transport=BackendEchoTransport(),
        discover_paid_provider_fn=lambda: _active_provider_snapshot(),
    )
    assert payload["result_code"] == "rejected_paid_license_state"


def test_upgrade_apply_post_commit_failure_restores_prior_bytes(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    config_sentinel, evidence_sentinel = _seed_proxy_config_and_evidence_sentinels(home)
    install_path = install_state_path(home)
    prior_install_bytes = install_path.read_bytes()
    activation_file = activation_path(home)
    prior_activation_bytes = (
        activation_file.read_bytes() if activation_file.is_file() else None
    )
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    legacy_marker = legacy_vendor / "legacy-marker.txt"
    legacy_marker.write_text("keep-me", encoding="utf-8")
    prior_marker_bytes = legacy_marker.read_bytes()
    cache_path = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    prior_cache_bytes = cache_path.read_bytes()

    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")

    module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    postcommit_inactive_provider = """
import os
from pathlib import Path

class _Provider:
    provider_id = 'private_v1'
    provider_contract_version = '1'

    def status(self):
        home = os.environ.get('AVP_HOME')
        install_path = Path(home) / 'paid' / 'install.json' if home else None
        if install_path is not None and install_path.is_file():
            return {
                'provider_present': True,
                'provider_id': 'private_v1',
                'provider_contract_version': '1',
                'status': 'revoked',
                'private_provider_enabled': False,
                'public_fallback_available': True,
                'summary': 'inactive after install',
                'error_code': None,
            }
        return {
            'provider_present': True,
            'provider_id': 'private_v1',
            'provider_contract_version': '1',
            'status': 'missing',
            'private_provider_enabled': False,
            'public_fallback_available': True,
            'summary': 'awaiting install state',
            'error_code': None,
        }

def build_vendored_provider():
    return _Provider()
"""
    handoff_writes_activation = """
def run_activation_handoff(request):
    from pathlib import Path
    import json
    activation = Path(request.avp_home) / 'paid' / 'activation.json'
    activation.parent.mkdir(parents=True, exist_ok=True)
    activation.write_text(json.dumps({
        "status": "active",
        "provider_present": True,
        "license_id": "lic_new",
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": "2026-01-01T00:00:00+00:00",
        "public_fallback_available": True,
        "error_code": None,
    }))
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_dir = tmp_path / "rollback-base"
    base_dir.mkdir(parents=True, exist_ok=True)
    base_wheel_path = base_dir / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}.whl"
    with zipfile.ZipFile(base_wheel_path, "w") as archive:
        archive.writestr(f"{module}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(f"{module}/handoff_hook.py", handoff_writes_activation)
        archive.writestr(f"{module}/vendored_provider.py", postcommit_inactive_provider)
        archive.writestr(
            f"{module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/METADATA",
            f"Name: {COMPOSED_BASE_PACKAGE_NAME}\nVersion: {COMPOSED_BASE_PACKAGE_VERSION}\n",
        )
        archive.writestr(
            f"{module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt",
            (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {module}.vendored_provider:build_vendored_provider\n"
            ),
        )
        archive.writestr(
            f"{module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    rollback_base_bytes = base_wheel_path.read_bytes()
    rollback_base_hash = sha256_hex(rollback_base_bytes)

    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=rollback_base_hash,
                    base_size=len(rollback_base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
            _octet_response(200, rollback_base_bytes),
            _octet_response(200, thin_bytes),
        ]
    )
    payload = upgrade_free_builder_to_paired(home=home, apply=True, transport=transport)
    assert payload["result_code"] == "skipped_install_failed"
    assert len(transport.calls) == 3
    assert install_path.read_bytes() == prior_install_bytes
    if prior_activation_bytes is None:
        assert not activation_file.is_file()
    else:
        assert activation_file.read_bytes() == prior_activation_bytes
    assert legacy_marker.read_bytes() == prior_marker_bytes
    assert cache_path.read_bytes() == prior_cache_bytes
    assert not (
        vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}"
    ).exists()
    assert not (vendor_root(home) / f"{PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}").exists()
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []
    _assert_proxy_config_and_evidence_unchanged(
        home,
        config_sentinel=config_sentinel,
        evidence_sentinel=evidence_sentinel,
    )


@pytest.mark.parametrize(
    "install_safety_state",
    ["blocked", "malformed", "review_recommended", "unknown", None],  # claim-check: allow negative install_safety_state fixture labels for fail-closed safety-state test.
)
def test_upgrade_fail_closed_unverified_install_safety_skips_network(
    tmp_path, monkeypatch, install_safety_state,
):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    install_path = install_state_path(home)
    install_state = json.loads(install_path.read_text(encoding="utf-8"))
    install_state["install_safety_state"] = install_safety_state
    write_install_state(install_path, install_state)
    transport = BackendEchoTransport(
        responses=[_json_response(200, {"eligible": True})],
    )
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_ineligible_local_state"
    assert transport.calls == []


def test_upgrade_fail_closed_terminal_activation_skips_network(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    activation_file = activation_path(home)
    activation_file.parent.mkdir(parents=True, exist_ok=True)
    activation_file.write_text(
        json.dumps(
            {
                "status": STATUS_REVOKED,
                "provider_present": True,
                "license_id": "lic_prior",
                "customer_id": None,
                "expires_at": None,
                "last_checked_at": "2026-01-01T00:00:00+00:00",
                "public_fallback_available": True,
                "error_code": None,
            }
        ),
        encoding="utf-8",
    )
    transport = BackendEchoTransport(responses=[_json_response(200, {"eligible": True})])
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_paid_terminal_state"
    assert transport.calls == []


def test_upgrade_fail_closed_paid_license_activation_skips_network(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    activation_file = activation_path(home)
    activation_file.write_text(
        json.dumps(
            {
                "status": STATUS_WITHIN_GRACE,
                "provider_present": True,
                "license_id": "lic_paid",
                "customer_id": None,
                "expires_at": None,
                "last_checked_at": "2026-01-01T00:00:00+00:00",
                "public_fallback_available": True,
                "error_code": None,
            }
        ),
        encoding="utf-8",
    )
    transport = BackendEchoTransport(responses=[_json_response(200, {"eligible": True})])
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_paid_terminal_state"
    assert transport.calls == []


def test_upgrade_fail_closed_symlink_vendor_skips_network(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    real_dir = tmp_path / "real-vendor"
    real_dir.mkdir()
    for child in list(vendor_dir.iterdir()):
        if child.is_file():
            shutil.copy2(child, real_dir / child.name)
    shutil.rmtree(vendor_dir)
    vendor_dir.symlink_to(real_dir, target_is_directory=True)
    transport = BackendEchoTransport(responses=[_json_response(200, {"eligible": True})])
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_ineligible_local_state"
    assert transport.calls == []


def test_upgrade_fail_closed_symlink_install_json_skips_network(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    install_path = install_state_path(home)
    prior_install_bytes = install_path.read_bytes()
    real_install = tmp_path / "real-install.json"
    real_install.write_bytes(prior_install_bytes)
    install_path.unlink()
    install_path.symlink_to(real_install)
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash="a" * 64,
                    base_size=1,
                    thin_hash="b" * 64,
                    thin_size=1,
                ),
            ),
        ]
    )
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_ineligible_local_state"
    assert transport.calls == []
    assert real_install.read_bytes() == prior_install_bytes


def test_upgrade_fail_closed_symlink_activation_json_skips_network(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    activation_file = activation_path(home)
    activation_file.parent.mkdir(parents=True, exist_ok=True)
    activation_payload = {
        "status": STATUS_ACTIVE,
        "provider_present": True,
        "license_id": "lic_legacy_synthetic",
        "customer_id": None,
        "expires_at": None,
        "last_checked_at": "2026-01-01T00:00:00+00:00",
        "public_fallback_available": True,
        "error_code": None,
    }
    prior_activation_bytes = json.dumps(activation_payload, sort_keys=True).encode("utf-8")
    real_activation = tmp_path / "real-activation.json"
    real_activation.write_bytes(prior_activation_bytes)
    activation_file.symlink_to(real_activation)
    transport = BackendEchoTransport(responses=[_json_response(200, {"eligible": True})])
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_ineligible_local_state"
    assert transport.calls == []
    assert real_activation.read_bytes() == prior_activation_bytes


def test_upgrade_fail_closed_symlink_paid_parent_skips_network(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    paid_dir = home / "paid"
    real_paid = tmp_path / "real-paid"
    shutil.move(str(paid_dir), str(real_paid))
    paid_dir.symlink_to(real_paid, target_is_directory=True)
    transport = BackendEchoTransport(responses=[_json_response(200, {"eligible": True})])
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "rejected_ineligible_local_state"
    assert transport.calls == []


def test_upgrade_preview_allows_active_activation_with_license_id(tmp_path, monkeypatch):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    activation_file = activation_path(home)
    activation_file.write_text(
        json.dumps(
            {
                "status": STATUS_ACTIVE,
                "provider_present": True,
                "license_id": "lic_legacy_synthetic",
                "customer_id": None,
                "expires_at": None,
                "last_checked_at": "2026-01-01T00:00:00+00:00",
                "public_fallback_available": True,
                "error_code": None,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
        ]
    )
    payload = upgrade_free_builder_to_paired(home=home, apply=False, transport=transport)
    assert payload["result_code"] == "preview_ready"
    assert len(transport.calls) == 1


_UPGRADE_JSON_KEYS = frozenset(
    {
        "action",
        "apply",
        "current_package_name",
        "current_package_version",
        "result_code",
        "target_components",
        "target_install_composition_version",
        "upgrade_available",
    }
)


def test_upgrade_cli_emits_human_output_without_secrets(tmp_path, monkeypatch, capsys):
    from agentveil_mcp_proxy.paid_activation import assert_paid_human_output_no_overclaim

    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
        ]
    )
    code = run_paid_upgrade_free_builder_cli(
        home=home,
        apply=False,
        output_json=False,
        transport=transport,
    )
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith("Upgrade action:")
    assert "Result: preview_ready" in out
    assert not out.strip().startswith("{")
    assert_paid_human_output_no_overclaim(out)
    scan_paid_output_for_leaks(out, secrets=(TOKEN, SECRET))
    assert TOKEN not in out


def test_upgrade_cli_emits_bounded_json_without_secrets(tmp_path, monkeypatch, capsys):
    home = _seed_legacy_active_thin_install(tmp_path, monkeypatch)
    base_bytes, base_hash = _build_base_wheel(tmp_path / "base")
    thin_bytes, thin_hash = _build_thin_wheel(tmp_path / "thin")
    transport = BackendEchoTransport(
        responses=[
            _json_response(
                200,
                _v2_eligible_response(
                    base_hash=base_hash,
                    base_size=len(base_bytes),
                    thin_hash=thin_hash,
                    thin_size=len(thin_bytes),
                ),
            ),
        ]
    )
    code = run_paid_upgrade_free_builder_cli(
        home=home,
        apply=False,
        output_json=True,
        transport=transport,
    )
    assert code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert set(payload) <= _UPGRADE_JSON_KEYS
    scan_paid_output_for_leaks(out, secrets=(TOKEN, SECRET))
    assert TOKEN not in out
    assert "Bearer" not in out
