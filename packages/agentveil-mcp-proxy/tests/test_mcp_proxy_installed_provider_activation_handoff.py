"""Exact installed-wheel activation handoff contract and security tests."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import io
import json
import os
import sys
import types
from pathlib import Path
import traceback
import zipfile

import pytest

from agentveil_mcp_proxy.paid_activation import (
    BOUNDED_ACTIVATION_KEYS,
    PaidActivationError,
    STATUS_ACTIVE,
    activation_path,
    build_paid_activate_payload,
    build_paid_status_payload,
    load_activation_state,
    run_paid_activate_cli,
)
from agentveil_mcp_proxy.paid_install import (
    BOUNDED_INSTALL_KEYS,
    ERROR_HANDOFF_HOOK_EXCEPTION,
    ERROR_INSTALL_FAILED,
    INSTALL_FILENAME,
    ActivationValidateResult,
    EntitlementResult,
    InstallSafetyResult,
    PackageAuthorizeResult,
    PaidInstallError,
    activation_reference_from_credential,
    discover_exact_installed_activation_hook,
    install_state_path,
    invoke_installed_provider_activation_handoff,
    load_install_state,
    parse_vendored_entry_points,
    run_paid_activate_install_flow,
    set_paid_backend_client,
    sha256_hex,
    vendor_root,
    write_install_state,
)
from agentveil_mcp_proxy.paid_provider import (
    BOUNDED_HANDOFF_REQUEST_KEYS,
    BOUNDED_HANDOFF_RESPONSE_KEYS,
    ERROR_HANDOFF_HOOK_IMPORT_FAILED,
    ERROR_HANDOFF_HOOK_MALFORMED,
    ERROR_HANDOFF_HOOK_MISSING,
    ERROR_HANDOFF_HOOK_MULTIPLE,
    ERROR_HANDOFF_RESPONSE_INVALID,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_CONTRACT_VERSION,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
    INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
    InstalledProviderActivationHandoffRequest,
    MAX_HANDOFF_ACTIVATION_CREDENTIAL_LENGTH,
    MAX_HANDOFF_AVP_HOME_LENGTH,
    assert_handoff_request_fields_bounded,
    set_paid_provider_loader,
    validate_installed_provider_activation_handoff_response,
)
from agentveil_mcp_proxy.classification import ToolCallClassifier
from agentveil_mcp_proxy.cli import run_proxy
from agentveil_mcp_proxy.passthrough import DownstreamConfig, JSONRPC_APPROVAL_REQUIRED, McpPassthrough
from agentveil_mcp_proxy.policy import ProxyConfig

from test_mcp_proxy_approval_run_proxy_e2e import (
    _init_run_proxy_fixture,
    _pending_approval_count,
    _responses,
    _tool_call as _approval_tool_call,
)

from mcp_fake_downstream import seed_tool_schemas, tool_entry

PACKAGE_NAME = "agentveil-private-policy"
PACKAGE_VERSION = "0.1.0"
MODULE_NAME = PACKAGE_NAME.replace("-", "_")
RAW_LICENSE_KEY = "avp_live_handoff_secret_key_do_not_leak_xyz123"
ENTITLEMENT_TOKEN = "avp_ent_handoff.token.secret.do.not.leak"
_CONTRACT_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "paid_installed_provider_activation_handoff_contract.json"
)
FORBIDDEN_MARKERS = (
    RAW_LICENSE_KEY,
    ENTITLEMENT_TOKEN,
    "https://",
    "http://",
    "/Users/",
    "presigned",
    "entitlement_token",
    "workspace",
    "member_id",
    "team_",
)

SUCCESS_HOOK_SOURCE = """
import json
from pathlib import Path

def run_activation_handoff(request):
    record_path = Path(request.avp_home) / "paid" / ".handoff_trace.json"
    record_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "contract_version": request.contract_version,
        "credential_len": len(request.activation_credential),
        "activation_reference": request.activation_reference,
        "plan_family": request.plan_family,
        "package_name": request.package_name,
        "package_version": request.package_version,
        "provider_id": request.provider_id,
        "avp_home": request.avp_home,
        "repr": repr(request),
        "text": str(request),
    }
    records = []
    if record_path.is_file():
        records = json.loads(record_path.read_text(encoding="utf-8"))
    records.append(payload)
    record_path.write_text(json.dumps(records), encoding="utf-8")
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""

INACTIVE_HOOK_SOURCE = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "error",
        "public_fallback_available": True,
        "summary": "Hook declined activation.",
        "error_code": "hook_not_ready",
    }
"""

EXCEPTION_HOOK_SOURCE = """
def run_activation_handoff(request):
    raise RuntimeError("hook exploded with " + request.activation_credential)
"""

RELATIVE_HOOK_HELPER_SOURCE = "VALUE = 'helper-ok'\n"

RELATIVE_HOOK_SOURCE = """
from .handoff_helper import VALUE

def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": VALUE,
        "error_code": None,
    }
"""

AMBIENT_TRAP_HOOK_SOURCE = """
def run_activation_handoff(request):
    raise RuntimeError("ambient namespace hook executed")
"""


def _proxy_config() -> ProxyConfig:
    return ProxyConfig.from_dict(
        {
            "proxy_config_schema_version": 1,
            "avp": {
                "base_url": "https://agentveil.dev",
                "agent_name": "handoff-proxy",
                "trusted_signer_dids": ["did:key:zHandoffTest"],
            },
            "mode": "protect",
            "privacy": {
                "action": "redacted",
                "resource": "hash",
                "payload": "hash_only",
                "evidence_upload": False,
            },
            "approval": {},
            "policy": {
                "id": "handoff-test",
                "policy_schema_version": 1,
                "default_decision": "allow",
                "default_risk_class": "read",
                "rules": [],
            },
            "tool_surface": {"mode": "enforce", "allow": ["get_issue"]},
            "downstream": {},
        }
    )


class _RecordingPassthrough(McpPassthrough):
    def __init__(self, config: ProxyConfig) -> None:
        classifier = ToolCallClassifier(config, server_name="handoff-srv")
        super().__init__(
            DownstreamConfig(command=sys.executable, args=(), name="handoff-srv"),
            classifier=classifier,
        )
        self.forwarded: list[dict] = []
        seed_tool_schemas(
            self,
            [
                tool_entry("get_issue"),
                tool_entry("write_file"),
            ],
        )

    def _send_downstream(self, message: dict) -> None:
        self.forwarded.append(message)

    def _wait_downstream_response(self, expected_id) -> dict:
        if any(message.get("method") == "tools/list" for message in self.forwarded):
            return {
                "jsonrpc": "2.0",
                "id": expected_id,
                "result": {"tools": [{"name": "get_issue"}, {"name": "write_file"}]},
            }
        return {"jsonrpc": "2.0", "id": expected_id, "result": {"ok": True}}


def _tools_list_names(proxy: _RecordingPassthrough) -> list[str]:
    proxy.forwarded.clear()
    responses = proxy.handle_client_line(
        json.dumps({"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}})
    )
    assert responses and "result" in responses[0]
    tools = responses[0]["result"].get("tools", [])
    return sorted(tool.get("name", "") for tool in tools if isinstance(tool, dict))


def _handoff_contract() -> dict:
    return json.loads(_CONTRACT_PATH.read_text(encoding="utf-8"))


def _entry_points_text(*, target: str | None, extra_lines: str = "") -> str:
    lines = ["[" + INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP + "]"]
    if target is not None:
        lines.append(f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = {target}")
    if extra_lines:
        lines.append(extra_lines.rstrip())
    return "\n".join(lines) + "\n"


def _wheel_bytes(
    tmp_path: Path,
    *,
    hook_source: str | None = None,
    entry_points: str | None = None,
    metadata_extra: str = "",
    duplicate_dist_info: bool = False,
    include_hook_module: bool = True,
    include_package_init: bool = True,
    extra_files: dict[str, str] | None = None,
    duplicate_member: str | None = None,
) -> tuple[bytes, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    hook_source = hook_source or SUCCESS_HOOK_SOURCE
    entry_points = entry_points if entry_points is not None else _entry_points_text(
        target=f"{MODULE_NAME}.handoff_hook:run_activation_handoff",
    )
    with zipfile.ZipFile(wheel_path, "w") as archive:
        if include_package_init:
            archive.writestr(f"{MODULE_NAME}/__init__.py", "provider_id = 'private_v1'\n")
        if include_hook_module and hook_source is not None:
            archive.writestr(f"{MODULE_NAME}/handoff_hook.py", hook_source)
        for rel_path, content in (extra_files or {}).items():
            archive.writestr(rel_path, content)
        metadata = f"Name: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n{metadata_extra}"
        archive.writestr(f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info/METADATA", metadata)
        archive.writestr(f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info/entry_points.txt", entry_points)
        archive.writestr(
            f"{MODULE_NAME}-{PACKAGE_VERSION}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        if duplicate_dist_info:
            archive.writestr(
                f"{MODULE_NAME}_copy-{PACKAGE_VERSION}.dist-info/METADATA",
                metadata,
            )
    if duplicate_member is not None:
        with zipfile.ZipFile(wheel_path, "a") as archive:
            archive.writestr(duplicate_member, b"duplicate-bytes")
    data = wheel_path.read_bytes()
    return data, sha256_hex(data)


@dataclass
class _FakeBackend:
    wheel_bytes: bytes
    artifact_hash: str
    artifact_size: int
    provider_handoff_required: bool = False

    def validate_activation(self, license_key: str) -> ActivationValidateResult:
        assert license_key == RAW_LICENSE_KEY
        return ActivationValidateResult(
            valid=True,  # claim-check: allow activation-validation fixture field asserted by focused tests.
            customer_ref_fingerprint="cust_fp",
            plan="builder",
            license_status="active",
            subscription_status="active",
            period_end=None,
            public_fallback_available=True,
            error_code=None,
            provider_handoff_required=self.provider_handoff_required,
        )

    def issue_entitlement(self, license_key: str, validation: ActivationValidateResult) -> EntitlementResult:
        del license_key, validation
        return EntitlementResult(
            entitlement_token=ENTITLEMENT_TOKEN,
            entitlement_id="ent_handoff_001",
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
            download_authorization_id="dlauth_handoff_001",
            public_fallback_available=True,
            error_code=None,
        )

    def download_package(self, authorization: PackageAuthorizeResult) -> bytes:
        assert authorization.download_authorization_id == "dlauth_handoff_001"
        return self.wheel_bytes


@pytest.fixture(autouse=True)
def _reset_backend(monkeypatch):
    set_paid_backend_client(None)
    set_paid_provider_loader(None)
    monkeypatch.setenv("AVP_PAID_API_BASE_URL", "")
    yield
    set_paid_backend_client(None)
    set_paid_provider_loader(None)


def _assert_privacy(text: str) -> None:
    for marker in FORBIDDEN_MARKERS:
        assert marker not in text


def _handoff_request_kwargs(**overrides):
    base = {
        "contract_version": INSTALLED_PROVIDER_ACTIVATION_HANDOFF_CONTRACT_VERSION,
        "activation_credential": RAW_LICENSE_KEY,
        "activation_reference": activation_reference_from_credential(RAW_LICENSE_KEY),
        "plan_family": "builder",
        "package_name": PACKAGE_NAME,
        "package_version": PACKAGE_VERSION,
        "provider_id": "private_v1",
        "avp_home": "/tmp/avp-home",
    }
    base.update(overrides)
    return base


def test_handoff_contract_fixture_matches_public_constants():
    contract = _handoff_contract()
    assert contract["schema_version"] == "avp.paid_installed_provider_activation_handoff.v1"
    assert contract["contract_version"] == INSTALLED_PROVIDER_ACTIVATION_HANDOFF_CONTRACT_VERSION
    assert contract["entrypoint_group"] == INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP
    assert contract["entrypoint_name"] == INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME
    assert set(contract["request"]["allowed_keys"]) == set(BOUNDED_HANDOFF_REQUEST_KEYS)
    assert set(contract["response"]["allowed_keys"]) == set(BOUNDED_HANDOFF_RESPONSE_KEYS)


@pytest.mark.parametrize(
    "payload,expected_error",
    [
        ({"contract_version": "1", "status": "active"}, ERROR_HANDOFF_RESPONSE_INVALID),
        ({"contract_version": "1", "status": "pending", "public_fallback_available": True}, ERROR_HANDOFF_RESPONSE_INVALID),
        ({"contract_version": "999", "status": "active", "public_fallback_available": True}, "handoff_hook_incompatible"),
        (
            {
                "contract_version": "1",
                "status": "active",
                "public_fallback_available": True,
                "extra": True,
            },
            ERROR_HANDOFF_RESPONSE_INVALID,
        ),
    ],
)
def test_handoff_response_validation_rejects_invalid_payloads(payload, expected_error):
    with pytest.raises(ValueError, match=expected_error):
        validate_installed_provider_activation_handoff_response(payload)


def test_legacy_backend_without_handoff_flag_keeps_builder_path(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(wheel_bytes=wheel, artifact_hash=digest, artifact_size=len(wheel))
    )
    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE
    install = json.loads((home / "paid" / INSTALL_FILENAME).read_text(encoding="utf-8"))
    assert set(install) <= set(BOUNDED_INSTALL_KEYS)


def test_required_false_never_invokes_hook(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(
        tmp_path / "wheel",
        hook_source=EXCEPTION_HOOK_SOURCE,
    )
    set_paid_backend_client(
        _FakeBackend(wheel_bytes=wheel, artifact_hash=digest, artifact_size=len(wheel))
    )
    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE


def test_required_true_invokes_exact_vendored_hook_and_writes_active_state(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE
    install = load_install_state(install_state_path(home))
    activation = load_activation_state(activation_path(home))
    assert install is not None and activation is not None
    assert install["status"] == STATUS_ACTIVE
    assert activation["status"] == STATUS_ACTIVE
    assert set(install) <= set(BOUNDED_INSTALL_KEYS)
    assert set(activation) <= set(BOUNDED_ACTIVATION_KEYS)


def test_handoff_request_redacts_credential_in_repr_and_str():
    request = InstalledProviderActivationHandoffRequest(
        contract_version="1",
        activation_credential=RAW_LICENSE_KEY,
        activation_reference=activation_reference_from_credential(RAW_LICENSE_KEY),
        plan_family="builder",
        package_name=PACKAGE_NAME,
        package_version=PACKAGE_VERSION,
        provider_id="private_v1",
        avp_home="/tmp/avp-home",
    )
    text = repr(request) + str(request)
    assert RAW_LICENSE_KEY not in text
    assert "activation_credential='***'" in repr(request)
    assert "avp_home='***'" in repr(request)
    assert "/tmp/avp-home" not in repr(request)


def test_hook_receives_bounded_context_once_in_memory(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    module_path, attr_name = discover_exact_installed_activation_hook(
        vendor_dir,
        package_name=PACKAGE_NAME,
        package_version=PACKAGE_VERSION,
    )
    assert module_path == f"{MODULE_NAME}.handoff_hook"
    assert attr_name == "run_activation_handoff"
    trace = json.loads((home / "paid" / ".handoff_trace.json").read_text(encoding="utf-8"))
    assert len(trace) == 1
    call = trace[0]
    assert call["credential_len"] == len(RAW_LICENSE_KEY)
    assert call["activation_reference"] == activation_reference_from_credential(RAW_LICENSE_KEY)
    assert call["plan_family"] == "builder"
    assert call["package_name"] == PACKAGE_NAME
    assert call["package_version"] == PACKAGE_VERSION
    assert call["provider_id"] == "private_v1"
    _assert_privacy(call["repr"])
    _assert_privacy(call["text"])


def test_repeated_activation_is_retry_safe(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    backend = _FakeBackend(
        wheel_bytes=wheel,
        artifact_hash=digest,
        artifact_size=len(wheel),
        provider_handoff_required=True,
    )
    set_paid_backend_client(backend)
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    trace = json.loads((home / "paid" / ".handoff_trace.json").read_text(encoding="utf-8"))
    assert len(trace) == 2


@pytest.mark.parametrize(
    "entry_points,hook_source,expected_error",
    [
        ("", None, ERROR_HANDOFF_HOOK_MISSING),
        (
            _entry_points_text(target="bad-target"),
            None,
            ERROR_HANDOFF_HOOK_MALFORMED,
        ),
        (
            _entry_points_text(
                target=f"{MODULE_NAME}.handoff_hook:run_activation_handoff",
                extra_lines="v1 = other.module:run_activation_handoff",
            ),
            None,
            ERROR_HANDOFF_HOOK_MULTIPLE,
        ),
        (
            _entry_points_text(target="999.module:run_activation_handoff"),
            None,
            ERROR_HANDOFF_HOOK_MALFORMED,
        ),
        (
            _entry_points_text(target=f"{MODULE_NAME}.missing:run_activation_handoff"),
            None,
            "handoff_hook_import_failed",
        ),
        (
            _entry_points_text(target=f"{MODULE_NAME}.handoff_hook:run_activation_handoff"),
            INACTIVE_HOOK_SOURCE,
            "hook_not_ready",
        ),
        (
            _entry_points_text(target=f"{MODULE_NAME}.handoff_hook:run_activation_handoff"),
            EXCEPTION_HOOK_SOURCE,
            "handoff_hook_exception",
        ),
    ],
)
def test_handoff_failures_are_closed_without_new_active_state(
    tmp_path,
    entry_points,
    hook_source,
    expected_error,
):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(
        tmp_path / "wheel",
        entry_points=entry_points,
        hook_source=hook_source,
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(Exception) as exc_info:
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert expected_error in str(exc_info.value)
    assert load_install_state(install_state_path(home)) is None
    activation = load_activation_state(activation_path(home))
    assert activation is None or activation.get("status") != STATUS_ACTIVE


def test_failed_replacement_preserves_existing_active_state(tmp_path):
    home = tmp_path / "avp-home"
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
    wheel, digest = _wheel_bytes(tmp_path / "wheel", hook_source=INACTIVE_HOOK_SOURCE)
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(Exception):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    preserved = load_install_state(install_state_path(home))
    assert preserved is not None
    assert preserved["status"] == STATUS_ACTIVE
    assert preserved["last_installed_at"] == "2026-07-23T00:00:00+00:00"


def test_hook_not_imported_before_verification(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel", hook_source=EXCEPTION_HOOK_SOURCE)
    backend = _FakeBackend(
        wheel_bytes=wheel,
        artifact_hash=digest,
        artifact_size=len(wheel),
        provider_handoff_required=True,
    )
    set_paid_backend_client(backend)

    original_verify = __import__(
        "agentveil_mcp_proxy.paid_install",
        fromlist=["verify_wheel_artifact"],
    ).verify_wheel_artifact

    def _verify_then_fail(*args, **kwargs):
        original_verify(*args, **kwargs)
        raise PaidInstallError("artifact_hash_mismatch", exit_code=1)

    monkeypatch.setattr(
        "agentveil_mcp_proxy.paid_install.verify_wheel_artifact",
        _verify_then_fail,
    )
    with pytest.raises(PaidInstallError, match="artifact_hash_mismatch"):
        run_paid_activate_install_flow(
            license_key=RAW_LICENSE_KEY,
            home=home,
            client=backend,
        )
    assert load_install_state(install_state_path(home)) is None


def test_ambient_entry_point_is_not_used_for_exact_handoff(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel-no-hook", entry_points="")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )

    class _AmbientProvider:
        provider_id = "ambient_trap"
        provider_contract_version = "1"

        def activate(self, *, license_key: str):
            raise AssertionError("ambient provider must not run")

        def status(self):
            return {"provider_present": True, "provider_id": "ambient_trap", "provider_contract_version": "1", "status": "active", "private_provider_enabled": True, "public_fallback_available": True, "summary": "trap", "error_code": None}

        def deactivate(self):
            return self.status()

    from agentveil_mcp_proxy.paid_provider import set_paid_provider_loader as _set_loader

    _set_loader(lambda: _AmbientProvider())
    with pytest.raises(Exception, match=ERROR_HANDOFF_HOOK_MISSING):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)


def test_cli_handoff_activation_output_is_privacy_safe(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    out = io.StringIO()
    code = run_paid_activate_cli(
        license_key=RAW_LICENSE_KEY,
        home=home,
        out=out,
    )
    assert code == 0
    _assert_privacy(out.getvalue())


def test_parse_vendored_entry_points_rejects_malformed_ini():
    with pytest.raises(PaidInstallError, match="handoff_hook_malformed"):
        parse_vendored_entry_points("[broken")


def test_built_wheel_installed_path_handoff(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    backend = _FakeBackend(
        wheel_bytes=wheel,
        artifact_hash=digest,
        artifact_size=len(wheel),
        provider_handoff_required=True,
    )
    result = run_paid_activate_install_flow(
        license_key=RAW_LICENSE_KEY,
        home=home,
        client=backend,
    )
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    handoff = invoke_installed_provider_activation_handoff(
        license_key=RAW_LICENSE_KEY,
        validation=backend.validate_activation(RAW_LICENSE_KEY),
        home=home,
        package_name=PACKAGE_NAME,
        package_version=PACKAGE_VERSION,
        provider_id="private_v1",
        vendor_dir=vendor_dir,
    )
    assert handoff.status == STATUS_ACTIVE
    assert result.install_state["status"] == STATUS_ACTIVE


def test_handoff_contract_forbids_team_vocabulary_in_privacy_markers():
    contract = _handoff_contract()
    markers = " ".join(contract["privacy_forbidden_markers"]).lower()
    assert "workspace" in markers
    assert "member_id" in markers
    assert "team_" in markers


def test_tools_list_surface_unchanged_after_handoff_activation(tmp_path):
    proxy = _RecordingPassthrough(_proxy_config())
    before = _tools_list_names(proxy)

    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    after = _tools_list_names(proxy)
    assert before == after == ["get_issue", "write_file"]


def test_relative_import_hook_succeeds(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(
        tmp_path / "wheel",
        hook_source=RELATIVE_HOOK_SOURCE,
        extra_files={f"{MODULE_NAME}/handoff_helper.py": RELATIVE_HOOK_HELPER_SOURCE},
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE


def test_stale_hook_module_is_not_reused_when_new_wheel_omits_module(tmp_path):
    home = tmp_path / "avp-home"
    wheel_with_hook, digest1 = _wheel_bytes(tmp_path / "wheel-with-hook")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel_with_hook,
            artifact_hash=digest1,
            artifact_size=len(wheel_with_hook),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    wheel_without_module, digest2 = _wheel_bytes(
        tmp_path / "wheel-without-hook",
        include_hook_module=False,
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel_without_module,
            artifact_hash=digest2,
            artifact_size=len(wheel_without_module),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(Exception, match=ERROR_HANDOFF_HOOK_IMPORT_FAILED):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    preserved = load_install_state(install_state_path(home))
    assert preserved is not None and preserved["status"] == STATUS_ACTIVE


def test_hook_exception_does_not_leak_credential(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel", hook_source=EXCEPTION_HOOK_SOURCE)
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(PaidActivationError, match=ERROR_HANDOFF_HOOK_EXCEPTION) as exc_info:
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert exc_info.value.__cause__ is None
    rendered = "".join(
        traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
    )
    assert RAW_LICENSE_KEY not in rendered
    assert RAW_LICENSE_KEY not in str(exc_info.value)


def test_symlinked_vendor_target_rejected(tmp_path):
    home = tmp_path / "avp-home"
    outside = tmp_path / "outside-vendor"
    outside.mkdir()
    vendor_dir = vendor_root(home)
    vendor_dir.mkdir(parents=True)
    live = vendor_dir / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    live.symlink_to(outside, target_is_directory=True)
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(PaidActivationError, match=ERROR_INSTALL_FAILED):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)


def test_duplicate_zip_member_rejected(tmp_path):
    home = tmp_path / "avp-home"
    member = f"{MODULE_NAME}/__init__.py"
    wheel, digest = _wheel_bytes(tmp_path / "wheel", duplicate_member=member)
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(PaidActivationError, match=ERROR_INSTALL_FAILED):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)


def test_active_response_with_error_code_rejected():
    with pytest.raises(ValueError, match=ERROR_HANDOFF_RESPONSE_INVALID):
        validate_installed_provider_activation_handoff_response(
            {
                "contract_version": "1",
                "status": "active",
                "public_fallback_available": True,
                "summary": "ok",
                "error_code": "should_not_be_here",
            }
        )


def test_paid_status_and_local_approval_work_offline_after_handoff_activation(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    set_paid_backend_client(None)
    monkeypatch.setenv("AVP_PAID_API_BASE_URL", "")

    payload = build_paid_status_payload(home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE
    assert payload["paid_activation_available"] is True
    text = json.dumps(payload, sort_keys=True)
    assert RAW_LICENSE_KEY not in text
    assert ENTITLEMENT_TOKEN not in text
    assert str(home) not in text

    proxy_home, _config_path, log_path = _init_run_proxy_fixture(tmp_path)
    assert proxy_home == home
    monkeypatch.setattr("webbrowser.open", lambda url: False)

    client_out = io.StringIO()
    assert run_proxy(
        home=home,
        client_in=io.StringIO(_approval_tool_call("write_file", call_id="offline-handoff-1")),
        out=client_out,
        approval_ui_mode="browser",
    ) == 0
    response = _responses(client_out.getvalue())[0]
    assert response["error"]["code"] == JSONRPC_APPROVAL_REQUIRED
    assert response["error"]["data"]["status"] == "approval_required"
    assert response["error"]["data"]["approval_possible"] is True
    assert _pending_approval_count(home) == 1
    assert log_path.read_text(encoding="utf-8").splitlines() == ["tools/list"]


def test_late_wheel_cache_failure_preserves_prior_vendor_and_install_state(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel-first")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    prior_install = load_install_state(install_state_path(home))
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    marker = vendor_dir / "prior-vendor-marker.txt"
    marker.write_text("keep-me", encoding="utf-8")

    replacement_wheel, replacement_digest = _wheel_bytes(tmp_path / "wheel-second")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=replacement_wheel,
            artifact_hash=replacement_digest,
            artifact_size=len(replacement_wheel),
            provider_handoff_required=True,
        )
    )

    def _fail_wheel_cache(**_kwargs):
        raise OSError("simulated wheel cache commit failure")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.paid_install._commit_wheel_cache",
        _fail_wheel_cache,
    )
    with pytest.raises(OSError, match="simulated wheel cache commit failure"):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    assert load_install_state(install_state_path(home)) == prior_install
    assert marker.read_text(encoding="utf-8") == "keep-me"


def test_late_publish_failure_preserves_prior_vendor_and_install_state(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
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
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    vendor_dir.mkdir(parents=True)
    marker = vendor_dir / "prior-vendor-marker.txt"
    marker.write_text("keep-me", encoding="utf-8")

    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )

    def _fail_publish(**_kwargs):
        raise OSError("simulated vendor publish failure")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.paid_install._publish_staged_vendor",
        _fail_publish,
    )
    with pytest.raises(OSError, match="simulated vendor publish failure"):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    preserved = load_install_state(install_state_path(home))
    assert preserved is not None
    assert preserved["last_installed_at"] == "2026-07-23T00:00:00+00:00"
    assert marker.read_text(encoding="utf-8") == "keep-me"


def test_first_install_cache_failure_removes_published_vendor(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )

    def _fail_wheel_cache(**_kwargs):
        raise OSError("simulated wheel cache commit failure")

    monkeypatch.setattr(
        "agentveil_mcp_proxy.paid_install._commit_wheel_cache",
        _fail_wheel_cache,
    )
    with pytest.raises(OSError, match="simulated wheel cache commit failure"):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    assert load_install_state(install_state_path(home)) is None
    live_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    assert not live_vendor.exists()


def test_first_install_cache_chmod_failure_removes_committed_wheel(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    real_chmod = os.chmod

    def _chmod_fail_on_cache(path, mode):
        if str(path).endswith(".whl") and "/cache/" in str(path):
            raise OSError("simulated chmod failure")
        real_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", _chmod_fail_on_cache)
    with pytest.raises(OSError, match="simulated chmod failure"):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    cache_path = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    assert not cache_path.exists()
    assert load_install_state(install_state_path(home)) is None
    assert not (vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}").exists()


def test_replacement_cache_backup_cleanup_failure_restores_prior_wheel(
    tmp_path,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    wheel_old, digest_old = _wheel_bytes(
        tmp_path / "wheel-old",
        metadata_extra="Wheel-Marker: old\n",
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel_old,
            artifact_hash=digest_old,
            artifact_size=len(wheel_old),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    prior_install = load_install_state(install_state_path(home))
    cache_path = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    old_cache_bytes = cache_path.read_bytes()
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    vendor_marker = vendor_dir / "prior-vendor-marker.txt"
    vendor_marker.write_text("keep-me", encoding="utf-8")

    wheel_new, digest_new = _wheel_bytes(
        tmp_path / "wheel-new",
        metadata_extra="Wheel-Marker: new\n",
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel_new,
            artifact_hash=digest_new,
            artifact_size=len(wheel_new),
            provider_handoff_required=True,
        )
    )

    real_unlink = Path.unlink

    def _unlink_fail_backup(self, missing_ok=False):
        if self.name.endswith(".whl.backup"):
            raise OSError("simulated backup cleanup failure")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _unlink_fail_backup)
    with pytest.raises(OSError, match="simulated backup cleanup failure"):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    assert cache_path.read_bytes() == old_cache_bytes
    assert not cache_path.with_name(f"{cache_path.name}.backup").exists()
    assert load_install_state(install_state_path(home)) == prior_install
    assert vendor_marker.read_text(encoding="utf-8") == "keep-me"


def test_preloaded_ambient_modules_rejected_by_origin_check(tmp_path, monkeypatch):
    ambient_root = tmp_path / "ambient-site"
    ambient_package = ambient_root / MODULE_NAME
    ambient_package.mkdir(parents=True)
    (ambient_package / "__init__.py").write_text("provider_id = 'ambient_trap'\n", encoding="utf-8")
    (ambient_package / "handoff_hook.py").write_text(AMBIENT_TRAP_HOOK_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(ambient_root))
    importlib.import_module(MODULE_NAME)

    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(
        tmp_path / "wheel",
        include_package_init=False,
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(PaidActivationError, match=ERROR_HANDOFF_HOOK_IMPORT_FAILED):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert load_install_state(install_state_path(home)) is None


def test_namespace_wheel_without_ambient_package_succeeds(tmp_path):
    home = tmp_path / "avp-home"
    wheel, digest = _wheel_bytes(
        tmp_path / "wheel",
        include_package_init=False,
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["activation"]["status"] == STATUS_ACTIVE


def test_namespace_wheel_rejects_ambient_package_hook(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    ambient_root = tmp_path / "ambient-site"
    ambient_package = ambient_root / MODULE_NAME
    ambient_package.mkdir(parents=True)
    (ambient_package / "handoff_hook.py").write_text(
        AMBIENT_TRAP_HOOK_SOURCE,
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(ambient_root))

    wheel, digest = _wheel_bytes(
        tmp_path / "wheel",
        include_package_init=False,
    )
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(PaidActivationError, match=ERROR_HANDOFF_HOOK_IMPORT_FAILED):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert load_install_state(install_state_path(home)) is None


def test_preexisting_sys_modules_restored_after_hook_load(tmp_path):
    home = tmp_path / "avp-home"
    sentinel = types.ModuleType(MODULE_NAME)
    sentinel.PREEXISTING = "keep-me"
    sys.modules[MODULE_NAME] = sentinel

    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)

    assert sys.modules[MODULE_NAME] is sentinel
    assert sys.modules[MODULE_NAME].PREEXISTING == "keep-me"


def test_symlinked_paid_parent_rejected(tmp_path):
    home = tmp_path / "avp-home"
    home.mkdir()
    outside = tmp_path / "outside-paid"
    outside.mkdir()
    (home / "paid").symlink_to(outside, target_is_directory=True)

    wheel, digest = _wheel_bytes(tmp_path / "wheel")
    set_paid_backend_client(
        _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
    )
    with pytest.raises(PaidActivationError, match=ERROR_INSTALL_FAILED):
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize(
    "field,value_factory",
    [
        (
            "activation_credential",
            lambda: "x" * (MAX_HANDOFF_ACTIVATION_CREDENTIAL_LENGTH + 1),
        ),
        (
            "avp_home",
            lambda: "/" + ("a" * MAX_HANDOFF_AVP_HOME_LENGTH),
        ),
    ],
)
def test_handoff_request_rejects_oversized_bounded_fields(field, value_factory):
    kwargs = _handoff_request_kwargs(**{field: value_factory()})
    with pytest.raises(ValueError, match=ERROR_HANDOFF_RESPONSE_INVALID):
        assert_handoff_request_fields_bounded(**kwargs)
