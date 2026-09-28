"""Paid package install flow tests with bounded local backend contract."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import types
import zipfile

import pytest

from agentveil_mcp_proxy.cli import main
from agentveil_mcp_proxy.paid_activation import ACTIVATION_FILENAME, STATUS_ACTIVE
from agentveil_mcp_proxy.paid_install import (
    COMPOSED_BASE_ARTIFACT_ID,
    COMPOSED_BASE_PACKAGE_NAME,
    COMPOSED_BASE_PACKAGE_VERSION,
    COMPOSED_INSTALL_COMPOSITION_VERSION,
    COMPOSED_THIN_ARTIFACT_ID,
    COMPOSED_THIN_PACKAGE_VERSION,
    COMPONENT_ROLE_BASE,
    COMPONENT_ROLE_THIN,
    DEFAULT_ARTIFACT_ID,
    ERROR_INSTALL_FAILED,
    ERROR_HASH_MISMATCH,
    ERROR_DOWNLOAD_DENIED,
    ERROR_PACKAGE_NAME_MISMATCH,
    ERROR_VERSION_MISMATCH,
    INSTALL_FILENAME,
    INSTALL_SAFETY_ALLOWED_REQUEST_KEYS,
    INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD,
    INSTALL_SAFETY_STATE_BLOCKED,
    INSTALL_SAFETY_STATE_MALFORMED,
    INSTALL_SAFETY_STATE_REVIEW_RECOMMENDED,
    INSTALL_SAFETY_STATE_VERIFIED,
    FreeBuilderInstallError,
    FreeBuilderWheelExpectations,
    HttpPaidBackendClient,
    PaidInstallError,
    build_install_safety_check_request,
    evaluate_install_safety,
    install_wheel_to_vendor,
    parse_install_safety_result,
    parse_wheel_metadata,
    scan_paid_output_for_leaks,
    set_paid_backend_client,
    sha256_hex,
    validate_bounded_package_name,
    validate_bounded_package_version,
    ERROR_HANDOFF_HOOK_IMPORT_FAILED,
    ERROR_HANDOFF_HOOK_MULTIPLE,
    ERROR_VENDORED_PROVIDER_MALFORMED,
    ERROR_VENDORED_PROVIDER_MISSING,
    discover_exact_vendored_controlled_alternative_provider_entry,
    install_state_path,
    load_install_state,
    resolve_vendored_controlled_alternative_provider,
    resolve_vendored_paid_provider,
    resolve_vendored_controlled_alternative_authority,
    vendor_root,
    verify_free_builder_wheel_artifact,
    verify_wheel_artifact,
    write_install_state,
    run_free_builder_paired_install_flow,
)
from agentveil_mcp_proxy.controlled_alternatives import (
    CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP,
)


PACKAGE_NAME = "agentveil-private-policy"
PACKAGE_VERSION = "0.1.0"
THIN_PACKAGE_NAME = "agentveil-private-policy-thin"
ARTIFACT_ID = "art_pkg_private_policy_001"
RAW_LICENSE_KEY = "avp_live_test_secret_key_do_not_leak_123456789"
ENTITLEMENT_TOKEN = "avp_ent_v1.test.entitlement.token.secret.value.do.not.leak"
PRESIGNED_URL = (
    "https://agentveil-paid-artifacts-staging.s3.amazonaws.com/private/pkg.whl"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=secret"
)
CUSTOMER_REF = "cust_demo0001"

_VENDORED_PROVIDER_DEFAULT_HOME_SOURCE = """
from agentveil_mcp_proxy.paid_activation import default_home

class _Provider:
    provider_id = 'private_v1'
    provider_contract_version = '1'

    def status(self):
        install_path = default_home() / 'paid' / 'install.json'
        if install_path.is_file():
            return {
                'provider_present': True,
                'provider_id': 'private_v1',
                'provider_contract_version': '1',
                'status': 'active',
                'private_provider_enabled': True,
                'public_fallback_available': True,
                'summary': 'ok',
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

_VENDORED_PROVIDER_REQUIRES_ACTIVATION_JSON = """
from agentveil_mcp_proxy.paid_activation import default_home

class _Provider:
    provider_id = 'private_v1'
    provider_contract_version = '1'

    def status(self):
        activation_path = default_home() / 'paid' / 'activation.json'
        if activation_path.is_file():
            return {
                'provider_present': True,
                'provider_id': 'private_v1',
                'provider_contract_version': '1',
                'status': 'active',
                'private_provider_enabled': True,
                'public_fallback_available': True,
                'summary': 'ok',
                'error_code': None,
            }
        return {
            'provider_present': True,
            'provider_id': 'private_v1',
            'provider_contract_version': '1',
            'status': 'missing',
            'private_provider_enabled': False,
            'public_fallback_available': True,
            'summary': 'awaiting activation state',
            'error_code': None,
        }

def build_vendored_provider():
    return _Provider()
"""


@dataclass
class _MockBackendState:
    base_wheel_bytes: bytes
    base_artifact_hash: str
    base_artifact_size: int
    thin_wheel_bytes: bytes
    thin_artifact_hash: str
    thin_artifact_size: int
    last_authorize_artifact_id: str | None = None
    authorize_artifact_ids: list[str] | None = None
    safety_decision: str = "allow"
    safety_reason_code: str | None = None
    post_paths: list[str] | None = None
    authorize_call_count: int = 0
    download_call_count: int = 0
    entitlement_call_count: int = 0
    safety_call_count: int = 0


class _MockPaidBackendHandler(BaseHTTPRequestHandler):
    state: _MockBackendState

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, payload: dict, *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_packages_authorize(self, payload: dict) -> None:
        self.state.authorize_call_count += 1
        artifact_id = payload.get("artifact_id")
        self.state.last_authorize_artifact_id = artifact_id
        self.state.authorize_artifact_ids = self.state.authorize_artifact_ids or []
        self.state.authorize_artifact_ids.append(str(artifact_id))
        if payload.get("entitlement_token") != ENTITLEMENT_TOKEN:
            self._send_json(
                {
                    "download_authorized": False,
                    "error_code": "download_entitlement_invalid",
                    "public_fallback_available": True,
                }
            )
            return
        if artifact_id == COMPOSED_BASE_ARTIFACT_ID:
            package_name = COMPOSED_BASE_PACKAGE_NAME
            package_version = COMPOSED_BASE_PACKAGE_VERSION
            artifact_hash = self.state.base_artifact_hash
            artifact_size = self.state.base_artifact_size
            download_authorization_id = "dlauth_test_base_001"
        elif artifact_id == COMPOSED_THIN_ARTIFACT_ID:
            package_name = THIN_PACKAGE_NAME
            package_version = COMPOSED_THIN_PACKAGE_VERSION
            artifact_hash = self.state.thin_artifact_hash
            artifact_size = self.state.thin_artifact_size
            download_authorization_id = "dlauth_test_thin_001"
        else:
            self._send_json(
                {
                    "download_authorized": False,
                    "error_code": "download_denied",
                    "public_fallback_available": True,
                }
            )
            return
        self._send_json(
            {
                "download_authorized": True,
                "artifact_id": artifact_id,
                "package_name": package_name,
                "package_version": package_version,
                "platform": payload.get("platform", "linux"),
                "python_version": payload.get("python_version", "3.14"),
                "artifact_hash": artifact_hash,
                "artifact_size_bytes": artifact_size,
                "entitlement_id": "ent_test_001",
                "license_key_fingerprint": hashlib.sha256(RAW_LICENSE_KEY.encode()).hexdigest()[:16],
                "customer_ref_fingerprint": hashlib.sha256(CUSTOMER_REF.encode()).hexdigest()[:16],
                "download_authorization_id": download_authorization_id,
                "download_authorization_ref": "abcd1234ef567890",
                "expires_at": "2026-07-08T12:05:00+00:00",
                "public_fallback_available": True,
                "error_code": None,
            }
        )

    def _handle_packages_download(self, payload: dict) -> None:
        self.state.download_call_count += 1
        auth_id = payload.get("download_authorization_id")
        if auth_id == "dlauth_test_base_001":
            body = self.state.base_wheel_bytes
        elif auth_id == "dlauth_test_thin_001":
            body = self.state.thin_wheel_bytes
        else:
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.state.post_paths = self.state.post_paths or []
        self.state.post_paths.append(self.path)
        if self.path == "/v1/paid/activate/validate":
            payload = self._read_json()
            if payload.get("license_key") != RAW_LICENSE_KEY:
                self._send_json({"valid": False, "error_code": "invalid_key", "public_fallback_available": True})
                return
            self._send_json(
                {
                    "valid": True,
                    "customer_ref_fingerprint": hashlib.sha256(CUSTOMER_REF.encode()).hexdigest()[:16],
                    "plan": "pro",
                    "license_status": "active",
                    "subscription_status": "active",
                    "period_end": "2026-08-07T12:00:00+00:00",
                    "device_limit": 2,
                    "error_code": None,
                    "public_fallback_available": True,
                    "activation_rate_limit_per_minute": 30,
                }
            )
            return
        if self.path == "/v1/paid/activate/entitlement":
            self.state.entitlement_call_count += 1
            payload = self._read_json()
            if payload.get("license_key") != RAW_LICENSE_KEY:
                self._send_json({"error_code": "invalid_key"}, status=400)
                return
            self._send_json(
                {
                    "entitlement_token": ENTITLEMENT_TOKEN,
                    "entitlement_id": "ent_test_001",
                    "expires_at": "2026-08-07T12:00:00+00:00",
                }
            )
            return
        # claim-check: allow "safety" is the advisory endpoint label under test.
        if self.path == "/v1/paid/install/safety-check":
            self.state.safety_call_count += 1
            payload = self._read_json()
            extra = set(payload) - INSTALL_SAFETY_ALLOWED_REQUEST_KEYS
            if extra:
                self._send_json({"detail": "request_invalid"}, status=422)
                return
            expected = build_install_safety_check_request(ENTITLEMENT_TOKEN)
            for key, value in expected.items():
                if payload.get(key) != value:
                    self._send_json({"detail": "request_invalid"}, status=422)
                    return
            if payload.get("entitlement_token") != ENTITLEMENT_TOKEN:
                self._send_json({"detail": "request_invalid"}, status=422)
                return
            decision = self.state.safety_decision
            # claim-check: allow "blocked" is mock backend response state.
            if decision == "blocked":
                self._send_json(
                    {
                        "ok": False,
                        "decision": "block",
                        "reason_code": self.state.safety_reason_code or "hash_unverified",
                        "redirect_ref": None,
                        "install_safety_state": INSTALL_SAFETY_STATE_BLOCKED,
                        "live_enforcement": INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD,
                        "source_truth": {"resource_hash": None},
                    },
                    status=403,
                )
                return
            if decision == "malformed":
                self._send_json(
                    {
                        "ok": False,
                        "decision": "malformed",
                        "reason_code": "malformed_response",
                        "redirect_ref": None,
                        "install_safety_state": INSTALL_SAFETY_STATE_MALFORMED,
                        "live_enforcement": INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD,
                        "source_truth": {},
                    },
                    status=422,
                )
                return
            if decision == "redirect":
                reason = self.state.safety_reason_code or "model_suggested_source"
                self._send_json(
                    {
                        "ok": False,
                        "decision": "redirect",
                        "reason_code": reason,
                        "redirect_ref": "src_model_pkg_001",
                        "install_safety_state": INSTALL_SAFETY_STATE_REVIEW_RECOMMENDED,
                        "live_enforcement": INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD,
                        "source_truth": {"decision": "redirect"},
                    }
                )
                return
            self._send_json(
                {
                    "ok": True,
                    "decision": "allow",
                    "reason_code": "workspace_registry_trusted",
                    "redirect_ref": None,
                    "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
                    "live_enforcement": INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD,
                    "source_truth": {"decision": "allow"},
                }
            )
            return
        if self.path == "/v1/paid/packages/authorize":
            payload = self._read_json()
            self._handle_packages_authorize(payload)
            return
        if self.path == "/v1/paid/packages/download":
            payload = self._read_json()
            self._handle_packages_download(payload)
            return
        self.send_response(404)
        self.end_headers()


def _build_test_wheel(
    tmp_path: Path,
    *,
    package_name: str = PACKAGE_NAME,
    package_version: str = PACKAGE_VERSION,
    metadata_name: str | None = None,
    extra_entries: dict[str, str] | None = None,
) -> tuple[Path, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    wheel_path = tmp_path / f"{package_name.replace('-', '_')}-{package_version}-py3-none-any.whl"
    module_name = package_name.replace("-", "_")
    dist_name = (metadata_name or package_name).replace("-", "_").replace("/", "_").replace(".", "_")
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr(f"{module_name}/__init__.py", "provider_id = 'private_v1'\n")
        archive.writestr(
            f"{dist_name}-{package_version}.dist-info/METADATA",
            f"Name: {metadata_name or package_name}\nVersion: {package_version}\n",
        )
        archive.writestr(
            f"{module_name}-{package_version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        for entry_name, entry_body in (extra_entries or {}).items():
            archive.writestr(entry_name, entry_body)
    wheel_bytes = wheel_path.read_bytes()
    return wheel_path, sha256_hex(wheel_bytes)


def _build_composed_base_wheel(
    tmp_path: Path,
    *,
    package_version: str = COMPOSED_BASE_PACKAGE_VERSION,
    extra_entries: dict[str, str] | None = None,
) -> tuple[Path, str]:
    from agentveil_mcp_proxy.paid_provider import PAID_PROVIDER_ENTRYPOINT_GROUP

    module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    extra = {
        f"{module}/vendored_provider.py": (
            "import os\n"
            "from pathlib import Path\n"
            "class _Provider:\n"
            "    provider_id = 'private_v1'\n"
            "    provider_contract_version = '1'\n"
            "    def _install_path(self):\n"
            "        home = os.environ.get('AVP_HOME')\n"
            "        if not home:\n"
            "            return None\n"
            "        return Path(home) / 'paid' / 'install.json'\n"
            "    def status(self):\n"
            "        install_path = self._install_path()\n"
            "        if install_path is None or not install_path.is_file():\n"
            "            return {'provider_present': True, 'provider_id': 'private_v1', "
            "'provider_contract_version': '1', 'status': 'missing', "
            "'private_provider_enabled': False, 'public_fallback_available': True, "
            "'summary': 'awaiting install state', 'error_code': None}\n"
            "        return {'provider_present': True, 'provider_id': 'private_v1', "
            "'provider_contract_version': '1', 'status': 'active', "
            "'private_provider_enabled': True, 'public_fallback_available': True, "
            "'summary': 'ok', 'error_code': None}\n"
            "def build_vendored_provider():\n"
            "    return _Provider()\n"
        ),
        f"{module}-{package_version}.dist-info/entry_points.txt": (
            f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
            f"private_v1 = {module}.vendored_provider:build_vendored_provider\n"
        ),
    }
    extra.update(extra_entries or {})
    return _build_test_wheel(
        tmp_path,
        package_name=COMPOSED_BASE_PACKAGE_NAME,
        package_version=package_version,
        extra_entries=extra,
    )


def _build_composed_thin_wheel(
    tmp_path: Path,
    *,
    extra_entries: dict[str, str] | None = None,
) -> tuple[Path, str]:
    module = THIN_PACKAGE_NAME.replace("-", "_")
    thin_provider_source = (
        "class _Provider:\n"
        "    calls = []\n"
        "    def descriptor(self):\n"
        "        self.calls.append('descriptor')\n"
        "        return {'provider_id': 'private_v1'}\n"
        "def build_provider():\n"
        "    return _Provider()\n"
    )
    extra = {
        f"{module}/controlled_provider.py": thin_provider_source,
        f"{module}-{COMPOSED_THIN_PACKAGE_VERSION}.dist-info/entry_points.txt": (
            f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
            f"private_v1 = {module}.controlled_provider:build_provider\n"
            "[agentveil_mcp_proxy.controlled_alternative_authorities]\n"
            f"ca_route_v1 = {module}.controlled_provider:build_provider\n"
        ),
    }
    extra.update(extra_entries or {})
    return _build_test_wheel(
        tmp_path,
        package_name=THIN_PACKAGE_NAME,
        package_version=COMPOSED_THIN_PACKAGE_VERSION,
        extra_entries=extra,
    )


def _start_mock_paid_backend(
    tmp_path: Path,
    *,
    base_extra_entries: dict[str, str] | None = None,
) -> tuple[str, ThreadingHTTPServer, threading.Thread]:
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries=base_extra_entries,
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    state = _MockBackendState(
        base_wheel_bytes=base_wheel_path.read_bytes(),
        base_artifact_hash=base_hash,
        base_artifact_size=len(base_wheel_path.read_bytes()),
        thin_wheel_bytes=thin_wheel_path.read_bytes(),
        thin_artifact_hash=thin_hash,
        thin_artifact_size=len(thin_wheel_path.read_bytes()),
        post_paths=[],
        authorize_artifact_ids=[],
    )
    _MockPaidBackendHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockPaidBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    return base_url, server, thread


@pytest.fixture
def mock_paid_backend(tmp_path):
    base_wheel_path, base_hash = _build_composed_base_wheel(tmp_path / "wheel-base")
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    state = _MockBackendState(
        base_wheel_bytes=base_wheel_path.read_bytes(),
        base_artifact_hash=base_hash,
        base_artifact_size=len(base_wheel_path.read_bytes()),
        thin_wheel_bytes=thin_wheel_path.read_bytes(),
        thin_artifact_hash=thin_hash,
        thin_artifact_size=len(thin_wheel_path.read_bytes()),
        post_paths=[],
        authorize_artifact_ids=[],
    )
    _MockPaidBackendHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockPaidBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base_url
    finally:
        server.shutdown()
        thread.join(timeout=5)
        set_paid_backend_client(None)


@pytest.fixture(autouse=True)
def _reset_backend_client():
    set_paid_backend_client(None)
    yield
    set_paid_backend_client(None)


def _run_main_with_backend(
    argv: list[str],
    *,
    home: Path,
    base_url: str,
    stdin_text: str | None = None,
) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_home = os.environ.get("AVP_HOME")
    previous_base = os.environ.get("AVP_PAID_API_BASE_URL")
    os.environ["AVP_HOME"] = str(home)
    os.environ["AVP_PAID_API_BASE_URL"] = base_url
    set_paid_backend_client(HttpPaidBackendClient(base_url=base_url))
    previous_stdout = sys.stdout
    previous_stderr = sys.stderr
    previous_stdin = sys.stdin
    sys.stdout = stdout
    sys.stderr = stderr
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        code = main(argv)
    finally:
        sys.stdout = previous_stdout
        sys.stderr = previous_stderr
        sys.stdin = previous_stdin
        if previous_home is None:
            os.environ.pop("AVP_HOME", None)
        else:
            os.environ["AVP_HOME"] = previous_home
        if previous_base is None:
            os.environ["AVP_PAID_API_BASE_URL"] = ""
        else:
            os.environ["AVP_PAID_API_BASE_URL"] = previous_base
        set_paid_backend_client(None)
    return code, stdout.getvalue(), stderr.getvalue()


def _run_main_with_backend_preserve_ambient_avp_home(
    argv: list[str],
    *,
    base_url: str,
    stdin_text: str | None = None,
) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_base = os.environ.get("AVP_PAID_API_BASE_URL")
    os.environ["AVP_PAID_API_BASE_URL"] = base_url
    set_paid_backend_client(HttpPaidBackendClient(base_url=base_url))
    previous_stdout = sys.stdout
    previous_stderr = sys.stderr
    previous_stdin = sys.stdin
    sys.stdout = stdout
    sys.stderr = stderr
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        code = main(argv)
    finally:
        sys.stdout = previous_stdout
        sys.stderr = previous_stderr
        sys.stdin = previous_stdin
        if previous_base is None:
            os.environ["AVP_PAID_API_BASE_URL"] = ""
        else:
            os.environ["AVP_PAID_API_BASE_URL"] = previous_base
        set_paid_backend_client(None)
    return code, stdout.getvalue(), stderr.getvalue()


def _assert_no_paid_leaks(text: str, *, file_text: str = "") -> None:
    combined = text + file_text
    scan_paid_output_for_leaks(
        combined,
        secrets=(
            RAW_LICENSE_KEY,
            ENTITLEMENT_TOKEN,
            PRESIGNED_URL,
            CUSTOMER_REF,
        ),
    )
    assert PRESIGNED_URL not in combined
    assert "/Users/" not in combined


def test_paid_activate_install_local_flow(tmp_path, mock_paid_backend):
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 0, err
    assert "Status: active" in out
    assert "Provider: private_v1" in out
    assert f"Installed package: {COMPOSED_BASE_PACKAGE_NAME}" in out
    assert f"Installed version: {COMPOSED_BASE_PACKAGE_VERSION}" in out
    assert "Public fallback: available" in out
    _assert_no_paid_leaks(out + err)

    activation_file = home / "paid" / ACTIVATION_FILENAME
    install_file = home / "paid" / INSTALL_FILENAME
    assert activation_file.is_file()
    assert install_file.is_file()
    _assert_no_paid_leaks("", file_text=activation_file.read_text(encoding="utf-8"))
    _assert_no_paid_leaks("", file_text=install_file.read_text(encoding="utf-8"))
    assert json.loads(install_file.read_text(encoding="utf-8"))["status"] == STATUS_ACTIVE
    assert _MockPaidBackendHandler.state.post_paths is not None
    # claim-check: allow "safety" is the advisory endpoint label under test.
    safety_index = _MockPaidBackendHandler.state.post_paths.index("/v1/paid/install/safety-check")
    authorize_index = _MockPaidBackendHandler.state.post_paths.index("/v1/paid/packages/authorize")
    download_index = _MockPaidBackendHandler.state.post_paths.index("/v1/paid/packages/download")
    assert safety_index < authorize_index < download_index

    code, out, err = _run_main_with_backend(
        ["paid", "status", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
    )
    assert code == 0, err
    assert "Status: active" in out
    assert f"Installed package: {COMPOSED_BASE_PACKAGE_NAME}" in out
    _assert_no_paid_leaks(out + err)


def test_paid_activate_invalid_license_reports_failure(tmp_path, mock_paid_backend):
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "avp_live_invalid_key_only_000000000000", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
    )
    assert code == 1
    assert "invalid_key" in err.lower() or "ERROR:" in err
    _assert_no_paid_leaks(out + err)


def test_paid_activate_without_backend_keeps_provider_absent_path(tmp_path):
    home = tmp_path / "avp-home"
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_home = os.environ.get("AVP_HOME")
    previous_base = os.environ.get("AVP_PAID_API_BASE_URL")
    previous_base_present = "AVP_PAID_API_BASE_URL" in os.environ
    os.environ["AVP_HOME"] = str(home)
    os.environ["AVP_PAID_API_BASE_URL"] = ""
    previous_stdout = sys.stdout
    previous_stderr = sys.stderr
    sys.stdout = stdout
    sys.stderr = stderr
    try:
        code = main(["paid", "activate", RAW_LICENSE_KEY, "--home", str(home)])
    finally:
        sys.stdout = previous_stdout
        sys.stderr = previous_stderr
        if previous_home is None:
            os.environ.pop("AVP_HOME", None)
        else:
            os.environ["AVP_HOME"] = previous_home
        if not previous_base_present:
            os.environ.pop("AVP_PAID_API_BASE_URL", None)
        else:
            os.environ["AVP_PAID_API_BASE_URL"] = previous_base or ""
    assert code == 1
    out = stdout.getvalue()
    assert "Paid provider: absent" in out
    assert "Paid activation: unavailable" in out
    _assert_no_paid_leaks(out + stderr.getvalue())


def test_default_artifact_id_targets_private_policy_wheel():
    assert DEFAULT_ARTIFACT_ID == "art_pkg_private_policy_001"


def test_verify_wheel_rejects_metadata_version_mismatch(tmp_path):
    wheel_path, artifact_hash = _build_test_wheel(
        tmp_path / "wheel-build",
        package_version="9.9.9",
    )
    wheel_bytes = wheel_path.read_bytes()
    with pytest.raises(PaidInstallError) as exc:
        verify_wheel_artifact(
            wheel_bytes,
            expected_hash=artifact_hash,
            expected_size=len(wheel_bytes),
            expected_package_name=PACKAGE_NAME,
            expected_package_version=PACKAGE_VERSION,
        )
    assert exc.value.args[0] == ERROR_VERSION_MISMATCH


def test_parse_wheel_metadata_reads_dist_info(tmp_path):
    wheel_path, _artifact_hash = _build_test_wheel(tmp_path / "wheel-build")
    metadata = parse_wheel_metadata(wheel_path.read_bytes())
    assert metadata.package_name == PACKAGE_NAME
    assert metadata.package_version == PACKAGE_VERSION


def test_install_wheel_rejects_zip_slip_entry(tmp_path):
    wheel_path, _artifact_hash = _build_test_wheel(
        tmp_path / "wheel-build",
        extra_entries={"../escape.txt": "bad"},
    )
    target_dir = tmp_path / "vendor"
    with pytest.raises(PaidInstallError) as exc:
        install_wheel_to_vendor(
            home=tmp_path,
            wheel_path=wheel_path,
            target_dir=target_dir,
            expected_package_name=PACKAGE_NAME,
            expected_package_version=PACKAGE_VERSION,
        )
    assert exc.value.args[0] == ERROR_INSTALL_FAILED


def test_paid_activate_install_uses_composed_artifact_sequence(tmp_path, mock_paid_backend):
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 0, err
    assert _MockPaidBackendHandler.state.authorize_artifact_ids == [
        "art_pkg_private_guardrails_base_001",
        "art_pkg_ca_basic_006",
    ]
    assert COMPOSED_BASE_ARTIFACT_ID == "art_pkg_private_guardrails_base_001"
    assert COMPOSED_THIN_ARTIFACT_ID == "art_pkg_ca_basic_006"
    assert COMPOSED_THIN_PACKAGE_VERSION == "0.1.5"
    assert _MockPaidBackendHandler.state.entitlement_call_count == 1
    assert _MockPaidBackendHandler.state.safety_call_count == 1
    assert _MockPaidBackendHandler.state.authorize_call_count == 2
    assert _MockPaidBackendHandler.state.download_call_count == 2


def test_paid_activate_rejects_wheel_with_wrong_metadata_version(tmp_path, mock_paid_backend):
    wheel_path, artifact_hash = _build_composed_base_wheel(
        tmp_path / "bad-wheel",
        package_version="9.9.9",
    )
    _MockPaidBackendHandler.state.base_wheel_bytes = wheel_path.read_bytes()
    _MockPaidBackendHandler.state.base_artifact_hash = artifact_hash
    _MockPaidBackendHandler.state.base_artifact_size = len(_MockPaidBackendHandler.state.base_wheel_bytes)

    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 1
    assert ERROR_VERSION_MISMATCH in err or "package_version_mismatch" in err
    _assert_no_paid_leaks(out + err)


def test_validate_bounded_package_name_rejects_path_like_values():
    with pytest.raises(PaidInstallError) as exc:
        validate_bounded_package_name("../../escape")
    assert exc.value.args[0] == ERROR_PACKAGE_NAME_MISMATCH


def test_parse_wheel_metadata_rejects_unbounded_package_name(tmp_path):
    wheel_path, _artifact_hash = _build_test_wheel(
        tmp_path / "wheel-build",
        metadata_name="../../escape",
    )
    with pytest.raises(PaidInstallError) as exc:
        parse_wheel_metadata(wheel_path.read_bytes())
    assert exc.value.args[0] == ERROR_PACKAGE_NAME_MISMATCH


def test_validate_bounded_package_version_rejects_non_semver():
    with pytest.raises(PaidInstallError) as exc:
        validate_bounded_package_version("not-a-version")
    assert exc.value.args[0] == ERROR_VERSION_MISMATCH


def test_paid_activate_rejects_backend_controlled_package_name(tmp_path, mock_paid_backend):
    original_authorize = _MockPaidBackendHandler.do_POST

    def authorize_with_evil_name(self):  # noqa: ANN001
        if self.path == "/v1/paid/packages/authorize":
            payload = self._read_json()
            self.state.last_authorize_artifact_id = payload.get("artifact_id")
            if payload.get("entitlement_token") != ENTITLEMENT_TOKEN:
                self._send_json(
                    {
                        "download_authorized": False,
                        "error_code": "download_entitlement_invalid",
                        "public_fallback_available": True,
                    }
                )
                return
            if payload.get("artifact_id") != COMPOSED_BASE_ARTIFACT_ID:
                return original_authorize(self)
            self._send_json(
                {
                    "download_authorized": True,
                    "artifact_id": COMPOSED_BASE_ARTIFACT_ID,
                    "package_name": "../../escape",
                    "package_version": COMPOSED_BASE_PACKAGE_VERSION,
                    "platform": payload.get("platform", "linux"),
                    "python_version": payload.get("python_version", "3.14"),
                    "artifact_hash": self.state.base_artifact_hash,
                    "artifact_size_bytes": self.state.base_artifact_size,
                    "entitlement_id": "ent_test_001",
                    "license_key_fingerprint": hashlib.sha256(RAW_LICENSE_KEY.encode()).hexdigest()[:16],
                    "customer_ref_fingerprint": hashlib.sha256(CUSTOMER_REF.encode()).hexdigest()[:16],
                    "download_authorization_id": "dlauth_test_base_001",
                    "download_authorization_ref": "abcd1234ef567890",
                    "expires_at": "2026-07-08T12:05:00+00:00",
                    "public_fallback_available": True,
                    "error_code": None,
                }
            )
            return
        return original_authorize(self)

    _MockPaidBackendHandler.do_POST = authorize_with_evil_name
    try:
        home = tmp_path / "avp-home"
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        _MockPaidBackendHandler.do_POST = original_authorize

    assert code == 1
    assert ERROR_PACKAGE_NAME_MISMATCH in err or "package_name_mismatch" in err
    _assert_no_paid_leaks(out + err)


def test_paid_activate_install_safety_review_continues_with_warning(tmp_path, mock_paid_backend):
    _MockPaidBackendHandler.state.safety_decision = "redirect"
    _MockPaidBackendHandler.state.safety_reason_code = "model_suggested_source"
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 0, err
    assert "Install check: review recommended (model_suggested_source)" in out
    assert "Status: active" in out
    install_file = home / "paid" / INSTALL_FILENAME
    install_state = json.loads(install_file.read_text(encoding="utf-8"))
    assert install_state["install_safety_state"] == "review_recommended"
    assert install_state["install_safety_reason"] == "model_suggested_source"
    _assert_no_paid_leaks(out + err, file_text=install_file.read_text(encoding="utf-8"))


def test_paid_activate_install_safety_blocked_stops_before_download(tmp_path, mock_paid_backend):
    # claim-check: allow "blocked" is bounded test fixture state.
    _MockPaidBackendHandler.state.safety_decision = "blocked"
    _MockPaidBackendHandler.state.safety_reason_code = "hash_unverified"
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 1
    # claim-check: allow "blocked" is bounded CLI error text.
    assert "install check blocked (hash_unverified)" in err.lower()
    assert _MockPaidBackendHandler.state.authorize_call_count == 0
    assert _MockPaidBackendHandler.state.download_call_count == 0
    assert not (home / "paid" / INSTALL_FILENAME).exists()
    _assert_no_paid_leaks(out + err)


def test_paid_activate_install_safety_malformed_fails_closed(tmp_path, mock_paid_backend):
    _MockPaidBackendHandler.state.safety_decision = "malformed"
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 1
    # claim-check: allow "blocked" is bounded CLI error text.
    assert "install check blocked" in err.lower()
    assert _MockPaidBackendHandler.state.authorize_call_count == 0
    _assert_no_paid_leaks(out + err)


def test_paid_activate_install_safety_backend_unavailable_fails_closed(tmp_path, mock_paid_backend):
    original_post = _MockPaidBackendHandler.do_POST

    def safety_server_error(self):  # noqa: ANN001
        # claim-check: allow "safety" is the advisory endpoint label under test.
        if self.path == "/v1/paid/install/safety-check":
            self._send_json({"ok": False, "error_code": "unavailable"}, status=503)
            return
        return original_post(self)

    _MockPaidBackendHandler.do_POST = safety_server_error
    try:
        home = tmp_path / "avp-home"
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        _MockPaidBackendHandler.do_POST = original_post

    assert code == 1
    assert "paid_backend_unavailable" in err.lower() or "ERROR:" in err
    assert _MockPaidBackendHandler.state.authorize_call_count == 0
    _assert_no_paid_leaks(out + err)


def test_build_install_safety_check_request_matches_private_schema():
    payload = build_install_safety_check_request(ENTITLEMENT_TOKEN)
    assert set(payload) <= INSTALL_SAFETY_ALLOWED_REQUEST_KEYS
    assert "artifact_id" not in payload
    assert payload["user_pinned_source"] is False
    assert payload["intent_source"] == "user_direct"
    assert payload["target_source"] == "workspace_registry"
    assert payload["tool_source"] == "approved_registry"
    assert payload["metadata_influence"] == "none"


def test_evaluate_install_safety_accepts_redirect_advisory_continue():
    result = parse_install_safety_result(
        {
            "ok": False,
            "decision": "redirect",
            "reason_code": "model_suggested_source",
            "install_safety_state": INSTALL_SAFETY_STATE_REVIEW_RECOMMENDED,
            "live_enforcement": INSTALL_SAFETY_LIVE_ENFORCEMENT_HOLD,
        }
    )
    advisory, state, reason = evaluate_install_safety(result)
    assert advisory == "Install check: review recommended (model_suggested_source)"
    assert state == INSTALL_SAFETY_STATE_REVIEW_RECOMMENDED
    assert reason == "model_suggested_source"


def test_paid_activate_rejects_extra_safety_check_field(tmp_path, mock_paid_backend):
    original_post = _MockPaidBackendHandler.do_POST

    def reject_artifact_id(self):  # noqa: ANN001
        # claim-check: allow "safety" is the advisory endpoint label under test.
        if self.path == "/v1/paid/install/safety-check":
            payload = self._read_json()
            if "artifact_id" in payload:
                self._send_json({"detail": "request_invalid"}, status=422)
                return
        return original_post(self)

    _MockPaidBackendHandler.do_POST = reject_artifact_id
    import agentveil_mcp_proxy.paid_install as paid_install_module

    original_build = paid_install_module.build_install_safety_check_request
    try:

        def build_with_artifact(token: str) -> dict[str, object]:
            body = dict(original_build(token))
            body["artifact_id"] = ARTIFACT_ID
            return body

        paid_install_module.build_install_safety_check_request = build_with_artifact
        home = tmp_path / "avp-home"
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        _MockPaidBackendHandler.do_POST = original_post
        paid_install_module.build_install_safety_check_request = original_build

    assert code == 1
    assert _MockPaidBackendHandler.state.authorize_call_count == 0
    _assert_no_paid_leaks(out + err)


def test_verify_free_builder_wheel_artifact_accepts_bounded_metadata(tmp_path):
    thin_name = "agentveil-private-policy-thin"
    wheel_path, artifact_hash = _build_test_wheel(tmp_path / "wheel-build", package_name=thin_name)
    wheel_bytes = wheel_path.read_bytes()
    metadata = verify_free_builder_wheel_artifact(
        wheel_bytes,
        expectations=FreeBuilderWheelExpectations(
            artifact_hash=artifact_hash,
            artifact_size_bytes=len(wheel_bytes),
            package_name=thin_name,
            package_version=PACKAGE_VERSION,
        ),
    )
    assert metadata.package_name == thin_name
    assert metadata.package_version == PACKAGE_VERSION


def test_verify_free_builder_wheel_artifact_rejects_hash_mismatch(tmp_path):
    thin_name = "agentveil-private-policy-thin"
    wheel_path, artifact_hash = _build_test_wheel(tmp_path / "wheel-build", package_name=thin_name)
    wheel_bytes = wheel_path.read_bytes()
    with pytest.raises(FreeBuilderInstallError):
        verify_free_builder_wheel_artifact(
            wheel_bytes,
            expectations=FreeBuilderWheelExpectations(
                artifact_hash="0" * 64,
                artifact_size_bytes=len(wheel_bytes),
                package_name=thin_name,
                package_version=PACKAGE_VERSION,
            ),
        )


def test_run_free_builder_paired_install_flow_persists_split_state(tmp_path, monkeypatch):
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()
    result = run_free_builder_paired_install_flow(
        base_wheel_bytes=base_bytes,
        thin_wheel_bytes=thin_bytes,
        home=home,
        activation_credential=RAW_LICENSE_KEY,
        base_expectations=FreeBuilderWheelExpectations(
            artifact_hash=base_hash,
            artifact_size_bytes=len(base_bytes),
            package_name=COMPOSED_BASE_PACKAGE_NAME,
            package_version=COMPOSED_BASE_PACKAGE_VERSION,
        ),
        thin_expectations=FreeBuilderWheelExpectations(
            artifact_hash=thin_hash,
            artifact_size_bytes=len(thin_bytes),
            package_name=THIN_PACKAGE_NAME,
            package_version=COMPOSED_THIN_PACKAGE_VERSION,
        ),
    )
    assert result.install_state["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    roles = {entry["role"] for entry in result.install_state["install_components"]}
    assert roles == {COMPONENT_ROLE_BASE, COMPONENT_ROLE_THIN}
    assert resolve_vendored_paid_provider(home=home) is not None
    provider, error = resolve_vendored_controlled_alternative_provider(home=home)
    assert error is None and provider is not None


def test_run_free_builder_paired_install_honors_explicit_home_over_ambient_avp_home(
    tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

    explicit_home = tmp_path / "explicit-home"
    ambient_home = tmp_path / "ambient-home"
    monkeypatch.setenv("AVP_HOME", str(ambient_home))
    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/vendored_provider.py": _VENDORED_PROVIDER_DEFAULT_HOME_SOURCE,
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()
    result = run_free_builder_paired_install_flow(
        base_wheel_bytes=base_bytes,
        thin_wheel_bytes=thin_bytes,
        home=explicit_home,
        activation_credential=RAW_LICENSE_KEY,
        base_expectations=FreeBuilderWheelExpectations(
            artifact_hash=base_hash,
            artifact_size_bytes=len(base_bytes),
            package_name=COMPOSED_BASE_PACKAGE_NAME,
            package_version=COMPOSED_BASE_PACKAGE_VERSION,
        ),
        thin_expectations=FreeBuilderWheelExpectations(
            artifact_hash=thin_hash,
            artifact_size_bytes=len(thin_bytes),
            package_name=THIN_PACKAGE_NAME,
            package_version=COMPOSED_THIN_PACKAGE_VERSION,
        ),
    )
    assert result.install_state["status"] == STATUS_ACTIVE
    assert install_state_path(explicit_home).is_file()
    assert not install_state_path(ambient_home).exists()
    _assert_no_paid_leaks(json.dumps(result.install_state))


def test_run_free_builder_paired_rollback_preserves_prior_state_with_ambient_home_mismatch(
    tmp_path, monkeypatch,
):
    import agentveil_mcp_proxy.paid_install as paid_install_module
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

    explicit_home = tmp_path / "explicit-home"
    ambient_home = tmp_path / "ambient-home"
    monkeypatch.setenv("AVP_HOME", str(ambient_home))
    install_path = install_state_path(explicit_home)
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
                "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
                "install_safety_reason": None,
            }
        ),
        encoding="utf-8",
    )
    prior_install_bytes = install_path.read_bytes()

    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/vendored_provider.py": _VENDORED_PROVIDER_DEFAULT_HOME_SOURCE,
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()

    original_install = paid_install_module.install_wheel_to_vendor
    install_calls = {"count": 0}

    def fail_on_second_install(**kwargs):  # noqa: ANN003
        install_calls["count"] += 1
        if install_calls["count"] == 2:
            raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
        return original_install(**kwargs)

    monkeypatch.setattr(paid_install_module, "install_wheel_to_vendor", fail_on_second_install)
    with pytest.raises(FreeBuilderInstallError):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_bytes,
            thin_wheel_bytes=thin_bytes,
            home=explicit_home,
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_bytes),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_bytes),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert install_path.read_bytes() == prior_install_bytes
    assert not (vendor_root(explicit_home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").exists()


def test_paid_activate_explicit_home_with_ambient_avp_home_mismatch(tmp_path, monkeypatch):
    explicit_home = tmp_path / "explicit-home"
    ambient_home = tmp_path / "ambient-home"
    monkeypatch.setenv("AVP_HOME", str(ambient_home))
    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    base_url, server, thread = _start_mock_paid_backend(
        tmp_path / "backend",
        base_extra_entries={
            f"{base_module}/vendored_provider.py": _VENDORED_PROVIDER_DEFAULT_HOME_SOURCE,
        },
    )
    try:
        code, out, err = _run_main_with_backend_preserve_ambient_avp_home(
            ["paid", "activate", "--license-key-stdin", "--home", str(explicit_home)],
            base_url=base_url,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert code == 0, err
    assert install_state_path(explicit_home).is_file()
    assert not install_state_path(ambient_home).exists()
    _assert_no_paid_leaks(out + err)


def test_paid_activate_succeeds_when_provider_active_only_after_activation_json(
    tmp_path, monkeypatch,
):
    """Regression: paid install must not require live provider.active before activation.json."""

    from agentveil_mcp_proxy.paid_activation import build_paid_activate_payload

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    base_url, server, thread = _start_mock_paid_backend(
        tmp_path / "backend",
        base_extra_entries={
            f"{base_module}/vendored_provider.py": _VENDORED_PROVIDER_REQUIRES_ACTIVATION_JSON,
        },
    )
    try:
        set_paid_backend_client(HttpPaidBackendClient(base_url=base_url))
        payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert payload["activation"]["status"] == STATUS_ACTIVE
    install_file = home / "paid" / INSTALL_FILENAME
    activation_file = home / "paid" / ACTIVATION_FILENAME
    assert install_file.is_file()
    assert activation_file.is_file()
    saved_install = json.loads(install_file.read_text(encoding="utf-8"))
    assert saved_install["status"] == STATUS_ACTIVE
    assert saved_install["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    roles = {entry["role"] for entry in saved_install["install_components"]}
    assert roles == {COMPONENT_ROLE_BASE, COMPONENT_ROLE_THIN}
    _assert_no_paid_leaks("", file_text=install_file.read_text(encoding="utf-8"))
    _assert_no_paid_leaks("", file_text=activation_file.read_text(encoding="utf-8"))


def test_run_free_builder_paired_install_proves_missing_preinstall_then_active_post_state(
    tmp_path, monkeypatch,
):
    """Fake base reports missing before durable install state, active after publish."""

    from agentveil_mcp_proxy.console_project_status_client import (
        resolve_private_guardrails_status,
    )
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
        normalize_provider_response,
    )

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()
    preinstall_provider = resolve_vendored_paid_provider(home=home)
    assert preinstall_provider is None
    result = run_free_builder_paired_install_flow(
        base_wheel_bytes=base_bytes,
        thin_wheel_bytes=thin_bytes,
        home=home,
        activation_credential=RAW_LICENSE_KEY,
        base_expectations=FreeBuilderWheelExpectations(
            artifact_hash=base_hash,
            artifact_size_bytes=len(base_bytes),
            package_name=COMPOSED_BASE_PACKAGE_NAME,
            package_version=COMPOSED_BASE_PACKAGE_VERSION,
        ),
        thin_expectations=FreeBuilderWheelExpectations(
            artifact_hash=thin_hash,
            artifact_size_bytes=len(thin_bytes),
            package_name=THIN_PACKAGE_NAME,
            package_version=COMPOSED_THIN_PACKAGE_VERSION,
        ),
    )
    live_provider = resolve_vendored_paid_provider(home=home)
    assert live_provider is not None
    snapshot = normalize_provider_response(live_provider.status())
    assert resolve_private_guardrails_status(snapshot) == "active"
    assert result.install_state["status"] == STATUS_ACTIVE


CA_MODULE_NAME = PACKAGE_NAME.replace("-", "_")
CA_PROVIDER_SOURCE = """
class _Provider:
    calls = []

    def descriptor(self):
        self.calls.append("descriptor")
        return {"provider_id": "private_v1"}

    def propose(self, request):
        self.calls.append("propose")
        raise RuntimeError("CA1B_PHASE_CANARY")

    def execute(self, request):
        self.calls.append("execute")
        raise RuntimeError("CA1B_PHASE_CANARY")

    def verify(self, request):
        self.calls.append("verify")
        raise RuntimeError("CA1B_PHASE_CANARY")

def build_provider():
    return _Provider()
"""


def _build_controlled_alternative_test_wheel(
    tmp_path: Path,
    *,
    source: str = CA_PROVIDER_SOURCE,
    entry_points: str | None = None,
) -> tuple[Path, str]:
    extra = {
        f"{CA_MODULE_NAME}/controlled_provider.py": source,
        f"{CA_MODULE_NAME}-{PACKAGE_VERSION}.dist-info/entry_points.txt": (
            entry_points
            if entry_points is not None
            else (
                f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {CA_MODULE_NAME}.controlled_provider:build_provider\n"
            )
        ),
    }
    return _build_test_wheel(tmp_path, extra_entries=extra)


def _install_active_controlled_alternative(home: Path, *, wheel_path: Path) -> Path:
    vendor_dir = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
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
    return vendor_dir


def test_vendored_controlled_alternative_provider_loads_without_phases(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_path, _digest = _build_controlled_alternative_test_wheel(tmp_path / "wheel")
    vendor_dir = _install_active_controlled_alternative(home, wheel_path=wheel_path)
    before_path = list(sys.path)
    before_modules = {
        key
        for key in sys.modules
        if key == CA_MODULE_NAME or key.startswith(f"{CA_MODULE_NAME}.")
    }
    provider, error = resolve_vendored_controlled_alternative_provider(home=home)
    assert error is None
    assert provider is not None
    assert getattr(provider, "calls", None) == []
    assert not hasattr(provider, "descriptor") or provider.calls == []
    assert sys.path == before_path
    after_modules = {
        key
        for key in sys.modules
        if key == CA_MODULE_NAME or key.startswith(f"{CA_MODULE_NAME}.")
    }
    assert after_modules == before_modules
    assert str(vendor_dir.resolve()) not in sys.path
    assert error is None
    assert str(home) not in str(error)


def test_vendored_controlled_alternative_provider_missing_without_entry(tmp_path):
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    dist_info = vendor_dir / f"{CA_MODULE_NAME}-{PACKAGE_VERSION}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Name: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        "[agentveil_mcp_proxy.paid_providers]\nprivate_v1 = agentveil_private_policy.p:build\n",
        encoding="utf-8",
    )
    with pytest.raises(PaidInstallError, match=ERROR_VENDORED_PROVIDER_MISSING):
        discover_exact_vendored_controlled_alternative_provider_entry(
            vendor_dir,
            package_name=PACKAGE_NAME,
            package_version=PACKAGE_VERSION,
        )


def test_vendored_controlled_alternative_provider_duplicate_entry(tmp_path):
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    dist_info = vendor_dir / f"{CA_MODULE_NAME}-{PACKAGE_VERSION}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Name: {PACKAGE_NAME}\nVersion: {PACKAGE_VERSION}\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
        f"private_v1 = {CA_MODULE_NAME}.controlled_provider:build_provider\n"
        f"private_v1 = {CA_MODULE_NAME}.other:build_provider\n",
        encoding="utf-8",
    )
    with pytest.raises(PaidInstallError, match=ERROR_HANDOFF_HOOK_MULTIPLE):
        discover_exact_vendored_controlled_alternative_provider_entry(
            vendor_dir,
            package_name=PACKAGE_NAME,
            package_version=PACKAGE_VERSION,
        )


def test_vendored_controlled_alternative_factory_and_malformed_are_bounded(tmp_path, monkeypatch):
    canary = "CA1B_FACTORY_CANARY"
    home = tmp_path / "factory-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_path, _digest = _build_controlled_alternative_test_wheel(
        tmp_path / "factory",
        source=f"def build_provider():\n    raise RuntimeError({canary!r})\n",
    )
    _install_active_controlled_alternative(home, wheel_path=wheel_path)
    provider, error = resolve_vendored_controlled_alternative_provider(home=home)
    assert provider is None
    assert error == ERROR_HANDOFF_HOOK_IMPORT_FAILED
    assert canary not in str(error)

    malformed_home = tmp_path / "malformed-home"
    monkeypatch.setenv("AVP_HOME", str(malformed_home))
    malformed_wheel, _digest = _build_controlled_alternative_test_wheel(
        tmp_path / "malformed",
        entry_points=(
            f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
            "private_v1 = not a valid target\n"
        ),
    )
    _install_active_controlled_alternative(malformed_home, wheel_path=malformed_wheel)
    provider, error = resolve_vendored_controlled_alternative_provider(home=malformed_home)
    assert provider is None
    assert error == ERROR_VENDORED_PROVIDER_MALFORMED
    assert "not a valid target" not in str(error)


def _private_module_snapshot() -> dict[str, object]:
    return {
        key: sys.modules[key]
        for key in list(sys.modules)
        if key == CA_MODULE_NAME or key.startswith(f"{CA_MODULE_NAME}.")
    }


def _assert_bounded_controlled_resolver_failure(
    provider,
    error,
    *,
    before_path: list[str],
    before_modules: dict[str, object],
    canaries: tuple[str, ...] = (),
) -> None:
    assert provider is None
    assert error in {
        ERROR_VENDORED_PROVIDER_MISSING,
        ERROR_VENDORED_PROVIDER_MALFORMED,
        ERROR_HANDOFF_HOOK_IMPORT_FAILED,
        ERROR_HANDOFF_HOOK_MULTIPLE,
    }
    assert sys.path == before_path
    for key, module in before_modules.items():
        assert sys.modules.get(key) is module
    rendered = f"{error!r}{error}"
    for canary in canaries:
        assert canary not in rendered
    assert "/" not in str(error)
    assert "\\" not in str(error)


def test_resolve_vendored_controlled_alternative_provider_hostile_custody(tmp_path, monkeypatch):
    sentinel = types.ModuleType(CA_MODULE_NAME)
    monkeypatch.setitem(sys.modules, CA_MODULE_NAME, sentinel)

    def _run(home: Path):
        before_path = list(sys.path)
        before_modules = _private_module_snapshot()
        provider, error = resolve_vendored_controlled_alternative_provider(home=home)
        return provider, error, before_path, before_modules

    home = tmp_path / "wrong-name"
    monkeypatch.setenv("AVP_HOME", str(home))
    wheel_path, _digest = _build_controlled_alternative_test_wheel(tmp_path / "wheel-name")
    _install_active_controlled_alternative(home, wheel_path=wheel_path)
    write_install_state(
        install_state_path(home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "private_v1",
            "package_name": "wrong-package-name",
            "package_version": PACKAGE_VERSION,
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )
    provider, error, before_path, before_modules = _run(home)
    _assert_bounded_controlled_resolver_failure(
        provider,
        error,
        before_path=before_path,
        before_modules=before_modules,
        canaries=("wrong-package-name", str(home)),
    )

    version_home = tmp_path / "wrong-version"
    monkeypatch.setenv("AVP_HOME", str(version_home))
    version_wheel, _digest = _build_controlled_alternative_test_wheel(tmp_path / "wheel-version")
    _install_active_controlled_alternative(version_home, wheel_path=version_wheel)
    write_install_state(
        install_state_path(version_home),
        {
            "status": STATUS_ACTIVE,
            "provider_id": "private_v1",
            "package_name": PACKAGE_NAME,
            "package_version": "9.9.9",
            "public_fallback_available": True,
            "error_code": None,
            "last_installed_at": "2026-08-08T12:00:00+00:00",
            "install_safety_state": "verified",
            "install_safety_reason": None,
        },
    )
    provider, error, before_path, before_modules = _run(version_home)
    _assert_bounded_controlled_resolver_failure(
        provider,
        error,
        before_path=before_path,
        before_modules=before_modules,
        canaries=("9.9.9", str(version_home)),
    )

    symlink_home = tmp_path / "symlink-home"
    monkeypatch.setenv("AVP_HOME", str(symlink_home))
    symlink_wheel, _digest = _build_controlled_alternative_test_wheel(tmp_path / "wheel-symlink")
    vendor_dir = _install_active_controlled_alternative(symlink_home, wheel_path=symlink_wheel)
    outside = tmp_path / "outside-vendor"
    vendor_dir.rename(outside)
    vendor_dir.symlink_to(outside)
    provider, error, before_path, before_modules = _run(symlink_home)
    _assert_bounded_controlled_resolver_failure(
        provider,
        error,
        before_path=before_path,
        before_modules=before_modules,
        canaries=(str(outside), str(symlink_home)),
    )

    origin_home = tmp_path / "origin-home"
    monkeypatch.setenv("AVP_HOME", str(origin_home))
    origin_wheel, _digest = _build_controlled_alternative_test_wheel(
        tmp_path / "wheel-origin",
        entry_points=(
            f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
            "private_v1 = json:dumps\n"
        ),
    )
    _install_active_controlled_alternative(origin_home, wheel_path=origin_wheel)
    provider, error, before_path, before_modules = _run(origin_home)
    _assert_bounded_controlled_resolver_failure(
        provider,
        error,
        before_path=before_path,
        before_modules=before_modules,
        canaries=("json", "dumps", str(origin_home)),
    )

    none_home = tmp_path / "none-home"
    monkeypatch.setenv("AVP_HOME", str(none_home))
    none_wheel, _digest = _build_controlled_alternative_test_wheel(
        tmp_path / "wheel-none",
        source="def build_provider():\n    return None\n",
    )
    _install_active_controlled_alternative(none_home, wheel_path=none_wheel)
    provider, error, before_path, before_modules = _run(none_home)
    _assert_bounded_controlled_resolver_failure(
        provider,
        error,
        before_path=before_path,
        before_modules=before_modules,
        canaries=("None", str(none_home)),
    )
    assert sys.modules.get(CA_MODULE_NAME) is sentinel


def test_vendored_controlled_alternative_provider_restores_module_identity(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    sentinel = types.ModuleType(CA_MODULE_NAME)
    child = types.ModuleType(f"{CA_MODULE_NAME}.preexisting")
    monkeypatch.setitem(sys.modules, CA_MODULE_NAME, sentinel)
    monkeypatch.setitem(sys.modules, f"{CA_MODULE_NAME}.preexisting", child)
    wheel_path, _digest = _build_controlled_alternative_test_wheel(tmp_path / "wheel")
    _install_active_controlled_alternative(home, wheel_path=wheel_path)
    before_path = list(sys.path)
    provider, error = resolve_vendored_controlled_alternative_provider(home=home)
    assert error is None
    assert provider is not None
    assert getattr(provider, "calls", None) == []
    assert sys.path == before_path
    assert sys.modules.get(CA_MODULE_NAME) is sentinel
    assert sys.modules.get(f"{CA_MODULE_NAME}.preexisting") is child


def test_composed_activation_persists_split_state_and_vendors(tmp_path, mock_paid_backend, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 0, err
    install_state = json.loads((home / "paid" / INSTALL_FILENAME).read_text(encoding="utf-8"))
    assert install_state["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    roles = {entry["role"] for entry in install_state["install_components"]}
    assert roles == {COMPONENT_ROLE_BASE, COMPONENT_ROLE_THIN}
    assert (vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").is_dir()
    assert (vendor_root(home) / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}").is_dir()
    assert (home / "paid" / "cache" / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}.whl").is_file()
    assert (home / "paid" / "cache" / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}.whl").is_file()
    assert resolve_vendored_paid_provider(home=home) is not None
    provider, error = resolve_vendored_controlled_alternative_provider(home=home)
    assert error is None and provider is not None
    authority, authority_error = resolve_vendored_controlled_alternative_authority(home=home)
    assert authority_error is None and authority is not None
    _assert_no_paid_leaks(out + err, file_text=json.dumps(install_state))


def test_composed_activation_rejects_legacy_artifact_env(tmp_path, mock_paid_backend, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_PAID_ARTIFACT_ID", ARTIFACT_ID)
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 1
    assert ERROR_DOWNLOAD_DENIED in err or "download_denied" in err
    assert not (home / "paid" / INSTALL_FILENAME).exists()
    _assert_no_paid_leaks(out + err)


def test_composed_activation_rejects_mismatched_authorization_before_download(
    tmp_path,
    mock_paid_backend,
):
    original_authorize = _MockPaidBackendHandler.do_POST

    def authorize_wrong_hash(self):  # noqa: ANN001
        if self.path != "/v1/paid/packages/authorize":
            return original_authorize(self)
        payload = self._read_json()
        if payload.get("artifact_id") == COMPOSED_THIN_ARTIFACT_ID:
            self._send_json(
                {
                    "download_authorized": True,
                    "artifact_id": COMPOSED_THIN_ARTIFACT_ID,
                    "package_name": THIN_PACKAGE_NAME,
                    "package_version": COMPOSED_THIN_PACKAGE_VERSION,
                    "artifact_hash": "0" * 64,
                    "artifact_size_bytes": self.state.thin_artifact_size,
                    "download_authorization_id": "dlauth_test_thin_001",
                    "public_fallback_available": True,
                    "error_code": None,
                }
            )
            return
        self._handle_packages_authorize(payload)

    _MockPaidBackendHandler.do_POST = authorize_wrong_hash
    try:
        home = tmp_path / "avp-home"
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        _MockPaidBackendHandler.do_POST = original_authorize

    assert code == 1
    assert ERROR_HASH_MISMATCH in err or "artifact_hash_mismatch" in err
    assert _MockPaidBackendHandler.state.download_call_count == 2
    assert not (home / "paid" / INSTALL_FILENAME).exists()


def test_composed_activation_rejects_authorization_artifact_id_binding_before_download(
    tmp_path,
    mock_paid_backend,
):
    original_authorize = _MockPaidBackendHandler.do_POST

    def authorize_wrong_artifact_id(self):  # noqa: ANN001
        if self.path != "/v1/paid/packages/authorize":
            return original_authorize(self)
        payload = self._read_json()
        if payload.get("artifact_id") == COMPOSED_THIN_ARTIFACT_ID:
            self._send_json(
                {
                    "download_authorized": True,
                    "artifact_id": "art_pkg_unexpected_other_001",
                    "package_name": THIN_PACKAGE_NAME,
                    "package_version": COMPOSED_THIN_PACKAGE_VERSION,
                    "artifact_hash": _MockPaidBackendHandler.state.thin_artifact_hash,
                    "artifact_size_bytes": _MockPaidBackendHandler.state.thin_artifact_size,
                    "download_authorization_id": "dlauth_test_thin_001",
                    "public_fallback_available": True,
                    "error_code": None,
                }
            )
            return
        self._handle_packages_authorize(payload)

    _MockPaidBackendHandler.do_POST = authorize_wrong_artifact_id
    try:
        home = tmp_path / "avp-home"
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        _MockPaidBackendHandler.do_POST = original_authorize

    assert code == 1
    assert ERROR_DOWNLOAD_DENIED in err or "download_denied" in err
    assert _MockPaidBackendHandler.state.download_call_count == 1
    assert not (home / "paid" / INSTALL_FILENAME).exists()


def test_composed_second_component_failure_preserves_legacy_install(
    tmp_path,
    mock_paid_backend,
):
    home = tmp_path / "avp-home"
    legacy_wheel, _legacy_hash = _build_test_wheel(tmp_path / "legacy-wheel")
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel,
        target_dir=legacy_vendor,
        expected_package_name=PACKAGE_NAME,
        expected_package_version=PACKAGE_VERSION,
        require_empty_target=True,
    )
    legacy_cache = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    legacy_cache.parent.mkdir(parents=True, exist_ok=True)
    legacy_cache.write_bytes(legacy_wheel.read_bytes())
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
    prior_install_bytes = install_state_path(home).read_bytes()
    prior_vendor_marker = legacy_vendor / "legacy-marker.txt"
    prior_vendor_marker.write_text("keep-me", encoding="utf-8")

    original_download = _MockPaidBackendHandler.do_POST

    def fail_thin_download(self):  # noqa: ANN001
        if self.path != "/v1/paid/packages/download":
            return original_download(self)
        payload = self._read_json()
        if payload.get("download_authorization_id") == "dlauth_test_thin_001":
            self.send_response(403)
            self.end_headers()
            return
        self._handle_packages_download(payload)

    _MockPaidBackendHandler.do_POST = fail_thin_download
    try:
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
    finally:
        _MockPaidBackendHandler.do_POST = original_download

    assert code == 1
    assert install_state_path(home).read_bytes() == prior_install_bytes
    assert prior_vendor_marker.read_text(encoding="utf-8") == "keep-me"
    assert legacy_cache.is_file()
    assert not (vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").exists()
    _assert_no_paid_leaks(out + err)


def test_composed_publish_failure_rolls_back_first_component_and_preserves_legacy(
    tmp_path,
    mock_paid_backend,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    legacy_wheel, _legacy_hash = _build_test_wheel(tmp_path / "legacy-wheel")
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel,
        target_dir=legacy_vendor,
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
    prior_install_bytes = install_state_path(home).read_bytes()
    marker = legacy_vendor / "legacy-marker.txt"
    marker.write_text("keep-me", encoding="utf-8")
    legacy_cache = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    legacy_cache.parent.mkdir(parents=True, exist_ok=True)
    legacy_cache.write_bytes(legacy_wheel.read_bytes())
    prior_legacy_cache_bytes = legacy_cache.read_bytes()
    base_cache = home / "paid" / "cache" / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}.whl"
    base_cache.parent.mkdir(parents=True, exist_ok=True)
    prior_base_cache_bytes = b"prior-base-cache-bytes"
    base_cache.write_bytes(prior_base_cache_bytes)

    import agentveil_mcp_proxy.paid_install as paid_install_module

    original_publish = paid_install_module._publish_staged_vendor
    publish_calls = {"count": 0}

    def fail_on_second_publish(**kwargs):  # noqa: ANN003
        publish_calls["count"] += 1
        if publish_calls["count"] == 2:
            raise OSError("simulated composed publish failure")
        return original_publish(**kwargs)

    monkeypatch.setattr(paid_install_module, "_publish_staged_vendor", fail_on_second_publish)
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 1
    assert ERROR_INSTALL_FAILED in err or "install_failed" in err
    assert install_state_path(home).read_bytes() == prior_install_bytes
    assert marker.read_text(encoding="utf-8") == "keep-me"
    assert legacy_cache.read_bytes() == prior_legacy_cache_bytes
    assert base_cache.read_bytes() == prior_base_cache_bytes
    assert not (vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").exists()
    assert not (vendor_root(home) / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}").exists()
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob("*.backup")) == []
    _assert_no_paid_leaks(out + err)


def test_composed_state_write_failure_after_publish_rolls_back_and_preserves_legacy(
    tmp_path,
    mock_paid_backend,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    legacy_wheel, _legacy_hash = _build_test_wheel(tmp_path / "legacy-wheel")
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel,
        target_dir=legacy_vendor,
        expected_package_name=PACKAGE_NAME,
        expected_package_version=PACKAGE_VERSION,
        require_empty_target=True,
    )
    legacy_cache = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    legacy_cache.parent.mkdir(parents=True, exist_ok=True)
    legacy_cache.write_bytes(legacy_wheel.read_bytes())
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
    prior_install_bytes = install_state_path(home).read_bytes()
    prior_legacy_cache_bytes = legacy_cache.read_bytes()
    marker = legacy_vendor / "legacy-marker.txt"
    marker.write_text("keep-me", encoding="utf-8")

    base_cache = home / "paid" / "cache" / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}.whl"
    thin_cache = home / "paid" / "cache" / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}.whl"
    prior_base_cache_bytes = b"prior-base-cache-bytes"
    prior_thin_cache_bytes = b"prior-thin-cache-bytes"
    base_cache.write_bytes(prior_base_cache_bytes)
    thin_cache.write_bytes(prior_thin_cache_bytes)
    base_vendor = vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}"
    thin_vendor = vendor_root(home) / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}"
    base_vendor.mkdir(parents=True)
    thin_vendor.mkdir(parents=True)
    (base_vendor / "prior-base-vendor.txt").write_text("base-bytes", encoding="utf-8")
    (thin_vendor / "prior-thin-vendor.txt").write_text("thin-bytes", encoding="utf-8")

    import agentveil_mcp_proxy.paid_install as paid_install_module

    def fail_state_write(path, data):  # noqa: ANN001
        raise OSError("simulated composed install state write failure")

    monkeypatch.setattr(paid_install_module, "write_install_state", fail_state_write)
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    combined = out + err
    assert code == 1
    assert ERROR_INSTALL_FAILED in err or "install_failed" in err
    assert "Traceback" not in combined
    assert install_state_path(home).read_bytes() == prior_install_bytes
    loaded = load_install_state(install_state_path(home))
    assert loaded is not None
    assert loaded.get("install_composition_version") is None
    assert marker.read_text(encoding="utf-8") == "keep-me"
    assert legacy_cache.read_bytes() == prior_legacy_cache_bytes
    assert base_cache.read_bytes() == prior_base_cache_bytes
    assert thin_cache.read_bytes() == prior_thin_cache_bytes
    assert (base_vendor / "prior-base-vendor.txt").read_text(encoding="utf-8") == "base-bytes"
    assert (thin_vendor / "prior-thin-vendor.txt").read_text(encoding="utf-8") == "thin-bytes"
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []
    assert list(vendor_root(home).glob("*.backup")) == []
    assert list((home / "paid" / "cache").glob("*.backup")) == []
    _assert_no_paid_leaks(combined)


def test_composed_activation_preserves_legacy_vendor_and_cache_on_success(
    tmp_path,
    mock_paid_backend,
    monkeypatch,
):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    legacy_wheel, _legacy_hash = _build_test_wheel(tmp_path / "legacy-wheel")
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel,
        target_dir=legacy_vendor,
        expected_package_name=PACKAGE_NAME,
        expected_package_version=PACKAGE_VERSION,
        require_empty_target=True,
    )
    legacy_cache = home / "paid" / "cache" / f"{PACKAGE_NAME}-{PACKAGE_VERSION}.whl"
    legacy_cache.parent.mkdir(parents=True, exist_ok=True)
    legacy_cache.write_bytes(legacy_wheel.read_bytes())
    marker = legacy_vendor / "legacy-marker.txt"
    marker.write_text("keep-me", encoding="utf-8")

    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 0, err
    assert marker.read_text(encoding="utf-8") == "keep-me"
    assert legacy_cache.is_file()
    install_state = json.loads((home / "paid" / INSTALL_FILENAME).read_text(encoding="utf-8"))
    assert install_state["install_composition_version"] == COMPOSED_INSTALL_COMPOSITION_VERSION
    _assert_no_paid_leaks(out + err)


def test_malformed_split_install_state_fails_closed_without_fallback(tmp_path, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    install_path = install_state_path(home)
    install_path.parent.mkdir(parents=True, exist_ok=True)
    install_path.write_text(
        json.dumps(
            {
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
                    }
                ],
                "public_fallback_available": True,
                "error_code": None,
                "last_installed_at": "2026-08-08T12:00:00+00:00",
                "install_safety_state": "verified",
                "install_safety_reason": None,
            }
        ),
        encoding="utf-8",
    )
    assert load_install_state(install_state_path(home)) is None
    provider, error = resolve_vendored_controlled_alternative_provider(home=home)
    assert provider is None and error is not None


def test_repeated_composed_install_leaves_no_staging_residue(tmp_path, mock_paid_backend, monkeypatch):
    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    for _ in range(2):
        code, out, err = _run_main_with_backend(
            ["paid", "activate", "--license-key-stdin", "--home", str(home)],
            home=home,
            base_url=mock_paid_backend,
            stdin_text=f"{RAW_LICENSE_KEY}\n",
        )
        assert code == 0, err
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []
    assert list(vendor_root(home).glob("*.backup")) == []
    assert list((home / "paid" / "cache").glob("*.backup")) == []
    _assert_no_paid_leaks(out + err)


def test_run_free_builder_paired_rejects_expectation_metadata_mismatch(tmp_path):
    base_wheel_path, base_hash = _build_composed_base_wheel(tmp_path / "wheel-base")
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()
    with pytest.raises(FreeBuilderInstallError, match=ERROR_PACKAGE_NAME_MISMATCH):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_bytes,
            thin_wheel_bytes=thin_bytes,
            home=tmp_path / "avp-home",
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_bytes),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_bytes),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )


def test_run_free_builder_paired_fails_before_commit_when_paid_provider_missing(
    tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
    )

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    handoff_only_entry_points = (
        f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
        f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
        f"{base_module}.handoff_hook:run_activation_handoff\n"
    )
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                handoff_only_entry_points
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()
    with pytest.raises(FreeBuilderInstallError, match=ERROR_VENDORED_PROVIDER_MISSING):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_bytes,
            thin_wheel_bytes=thin_bytes,
            home=home,
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_bytes),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_bytes),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert not install_state_path(home).exists()
    assert RAW_LICENSE_KEY not in (home / "paid").as_posix()
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []


def test_run_free_builder_paired_rejects_inactive_base_provider_before_commit(
    tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

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
                "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
                "install_safety_reason": None,
            }
        ),
        encoding="utf-8",
    )
    prior_install_bytes = install_path.read_bytes()
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    legacy_wheel, _ = _build_test_wheel(tmp_path / "legacy-wheel")
    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel,
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

    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    inactive_provider_source = """
class _Provider:
    provider_id = 'private_v1'
    provider_contract_version = '1'
    def status(self):
        return {
            'provider_present': True,
            'provider_id': 'private_v1',
            'provider_contract_version': '1',
            'status': 'revoked',
            'private_provider_enabled': False,
            'public_fallback_available': True,
            'summary': 'inactive',
            'error_code': None,
        }
def build_vendored_provider():
    return _Provider()
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}/vendored_provider.py": inactive_provider_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    with pytest.raises(FreeBuilderInstallError, match=ERROR_VENDORED_PROVIDER_MALFORMED):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_wheel_path.read_bytes(),
            thin_wheel_bytes=thin_wheel_path.read_bytes(),
            home=home,
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_wheel_path.read_bytes()),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_wheel_path.read_bytes()),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert install_path.read_bytes() == prior_install_bytes
    assert legacy_marker.read_bytes() == prior_vendor_bytes
    assert cache_path.read_bytes() == prior_cache_bytes
    assert not (vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").exists()
    assert not (vendor_root(home) / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}").exists()
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []


def test_run_free_builder_paired_rejects_thin_authority_missing_before_commit(
    tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

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
                "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
                "install_safety_reason": None,
            }
        ),
        encoding="utf-8",
    )
    prior_install_bytes = install_path.read_bytes()

    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    thin_module = THIN_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(
        tmp_path / "wheel-thin",
        extra_entries={
            f"{thin_module}-{COMPOSED_THIN_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {thin_module}.controlled_provider:build_provider\n"
            ),
        },
    )
    with pytest.raises(FreeBuilderInstallError, match=ERROR_VENDORED_PROVIDER_MISSING):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_wheel_path.read_bytes(),
            thin_wheel_bytes=thin_wheel_path.read_bytes(),
            home=home,
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_wheel_path.read_bytes()),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_wheel_path.read_bytes()),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert install_path.read_bytes() == prior_install_bytes
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []


def test_run_free_builder_paired_rejects_malformed_thin_authority_before_commit(
    tmp_path, monkeypatch,
):
    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

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
                "install_safety_state": INSTALL_SAFETY_STATE_VERIFIED,
                "install_safety_reason": None,
            }
        ),
        encoding="utf-8",
    )
    prior_install_bytes = install_path.read_bytes()

    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    thin_module = THIN_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(
        tmp_path / "wheel-thin",
        extra_entries={
            f"{thin_module}-{COMPOSED_THIN_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {thin_module}.controlled_provider:build_provider\n"
                "[agentveil_mcp_proxy.controlled_alternative_authorities]\n"
                "ca_route_v1 = missing_authority_module:build_authority\n"
            ),
        },
    )
    with pytest.raises(FreeBuilderInstallError, match=ERROR_HANDOFF_HOOK_IMPORT_FAILED):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_wheel_path.read_bytes(),
            thin_wheel_bytes=thin_wheel_path.read_bytes(),
            home=home,
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_wheel_path.read_bytes()),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_wheel_path.read_bytes()),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert install_path.read_bytes() == prior_install_bytes
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []


def test_run_free_builder_paired_second_component_stage_failure_cleans_and_preserves_prior(
    tmp_path, monkeypatch,
):
    import agentveil_mcp_proxy.paid_install as paid_install_module

    home = tmp_path / "avp-home"
    monkeypatch.setenv("AVP_HOME", str(home))
    legacy_wheel, _legacy_hash = _build_test_wheel(tmp_path / "legacy-wheel")
    legacy_vendor = vendor_root(home) / f"{PACKAGE_NAME}-{PACKAGE_VERSION}"
    install_wheel_to_vendor(
        home=home,
        wheel_path=legacy_wheel,
        target_dir=legacy_vendor,
        expected_package_name=PACKAGE_NAME,
        expected_package_version=PACKAGE_VERSION,
        require_empty_target=True,
    )
    marker = legacy_vendor / "legacy-marker.txt"
    marker.write_text("keep-me", encoding="utf-8")
    prior_vendor_bytes = marker.read_bytes()

    from agentveil_mcp_proxy.paid_provider import (
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP,
        INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME,
        PAID_PROVIDER_ENTRYPOINT_GROUP,
    )

    base_module = COMPOSED_BASE_PACKAGE_NAME.replace("-", "_")
    handoff_source = """
def run_activation_handoff(request):
    return {
        "contract_version": "1",
        "status": "active",
        "public_fallback_available": True,
        "summary": "Installed hook completed.",
        "error_code": None,
    }
"""
    base_wheel_path, base_hash = _build_composed_base_wheel(
        tmp_path / "wheel-base",
        extra_entries={
            f"{base_module}/handoff_hook.py": handoff_source,
            f"{base_module}-{COMPOSED_BASE_PACKAGE_VERSION}.dist-info/entry_points.txt": (
                f"[{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_GROUP}]\n"
                f"{INSTALLED_PROVIDER_ACTIVATION_HANDOFF_ENTRYPOINT_NAME} = "
                f"{base_module}.handoff_hook:run_activation_handoff\n\n"
                f"[{PAID_PROVIDER_ENTRYPOINT_GROUP}]\n"
                f"private_v1 = {base_module}.vendored_provider:build_vendored_provider\n"
            ),
        },
    )
    thin_wheel_path, thin_hash = _build_composed_thin_wheel(tmp_path / "wheel-thin")
    base_bytes = base_wheel_path.read_bytes()
    thin_bytes = thin_wheel_path.read_bytes()

    original_install = paid_install_module.install_wheel_to_vendor
    install_calls = {"count": 0}

    def fail_on_second_install(**kwargs):  # noqa: ANN003
        install_calls["count"] += 1
        if install_calls["count"] == 2:
            raise PaidInstallError(ERROR_INSTALL_FAILED, exit_code=1)
        return original_install(**kwargs)

    monkeypatch.setattr(paid_install_module, "install_wheel_to_vendor", fail_on_second_install)
    with pytest.raises(FreeBuilderInstallError):
        run_free_builder_paired_install_flow(
            base_wheel_bytes=base_bytes,
            thin_wheel_bytes=thin_bytes,
            home=home,
            activation_credential=RAW_LICENSE_KEY,
            base_expectations=FreeBuilderWheelExpectations(
                artifact_hash=base_hash,
                artifact_size_bytes=len(base_bytes),
                package_name=COMPOSED_BASE_PACKAGE_NAME,
                package_version=COMPOSED_BASE_PACKAGE_VERSION,
            ),
            thin_expectations=FreeBuilderWheelExpectations(
                artifact_hash=thin_hash,
                artifact_size_bytes=len(thin_bytes),
                package_name=THIN_PACKAGE_NAME,
                package_version=COMPOSED_THIN_PACKAGE_VERSION,
            ),
        )
    assert marker.read_bytes() == prior_vendor_bytes
    assert not install_state_path(home).exists()
    assert not (vendor_root(home) / f"{COMPOSED_BASE_PACKAGE_NAME}-{COMPOSED_BASE_PACKAGE_VERSION}").exists()
    assert not (vendor_root(home) / f"{THIN_PACKAGE_NAME}-{COMPOSED_THIN_PACKAGE_VERSION}").exists()
    assert list(vendor_root(home).glob(".staging-*")) == []
    assert list((home / "paid" / "cache").glob(".staging-*")) == []
    _assert_no_paid_leaks(marker.read_text(encoding="utf-8"))
