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
    DEFAULT_ARTIFACT_ID,
    ERROR_INSTALL_FAILED,
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
    resolve_vendored_controlled_alternative_provider,
    vendor_root,
    verify_free_builder_wheel_artifact,
    verify_wheel_artifact,
    write_install_state,
)
from agentveil_mcp_proxy.controlled_alternatives import (
    CONTROLLED_ALTERNATIVE_PROVIDER_ENTRYPOINT_GROUP,
)


PACKAGE_NAME = "agentveil-private-policy"
PACKAGE_VERSION = "0.1.0"
ARTIFACT_ID = "art_pkg_private_policy_001"
RAW_LICENSE_KEY = "avp_live_test_secret_key_do_not_leak_123456789"
ENTITLEMENT_TOKEN = "avp_ent_v1.test.entitlement.token.secret.value.do.not.leak"
PRESIGNED_URL = (
    "https://agentveil-paid-artifacts-staging.s3.amazonaws.com/private/pkg.whl"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=secret"
)
CUSTOMER_REF = "cust_demo0001"


@dataclass
class _MockBackendState:
    wheel_bytes: bytes
    artifact_hash: str
    artifact_size: int
    last_authorize_artifact_id: str | None = None
    safety_decision: str = "allow"
    safety_reason_code: str | None = None
    post_paths: list[str] | None = None
    authorize_call_count: int = 0
    download_call_count: int = 0


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
            self.state.authorize_call_count += 1
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
            self._send_json(
                {
                    "download_authorized": True,
                    "artifact_id": ARTIFACT_ID,
                    "package_name": PACKAGE_NAME,
                    "package_version": PACKAGE_VERSION,
                    "platform": payload.get("platform", "linux"),
                    "python_version": payload.get("python_version", "3.14"),
                    "artifact_hash": self.state.artifact_hash,
                    "artifact_size_bytes": self.state.artifact_size,
                    "entitlement_id": "ent_test_001",
                    "license_key_fingerprint": hashlib.sha256(RAW_LICENSE_KEY.encode()).hexdigest()[:16],
                    "customer_ref_fingerprint": hashlib.sha256(CUSTOMER_REF.encode()).hexdigest()[:16],
                    "download_authorization_id": "dlauth_test_001",
                    "download_authorization_ref": "abcd1234ef567890",
                    "expires_at": "2026-07-08T12:05:00+00:00",
                    "public_fallback_available": True,
                    "error_code": None,
                }
            )
            return
        if self.path == "/v1/paid/packages/download":
            self.state.download_call_count += 1
            payload = self._read_json()
            if payload.get("download_authorization_id") != "dlauth_test_001":
                self.send_response(403)
                self.end_headers()
                return
            body = self.state.wheel_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
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


@pytest.fixture
def mock_paid_backend(tmp_path):
    wheel_path, artifact_hash = _build_test_wheel(tmp_path / "wheel-build")
    wheel_bytes = wheel_path.read_bytes()
    state = _MockBackendState(
        wheel_bytes=wheel_bytes,
        artifact_hash=artifact_hash,
        artifact_size=len(wheel_bytes),
        post_paths=[],
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
    assert f"Installed package: {PACKAGE_NAME}" in out
    assert f"Installed version: {PACKAGE_VERSION}" in out
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
    assert f"Installed package: {PACKAGE_NAME}" in out
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


def test_paid_activate_install_uses_private_policy_artifact_id(tmp_path, mock_paid_backend):
    home = tmp_path / "avp-home"
    code, out, err = _run_main_with_backend(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        base_url=mock_paid_backend,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 0, err
    assert _MockPaidBackendHandler.state.last_authorize_artifact_id == ARTIFACT_ID


def test_paid_activate_rejects_wheel_with_wrong_metadata_version(tmp_path, mock_paid_backend):
    wheel_path, artifact_hash = _build_test_wheel(
        tmp_path / "bad-wheel",
        package_version="9.9.9",
    )
    _MockPaidBackendHandler.state.wheel_bytes = wheel_path.read_bytes()
    _MockPaidBackendHandler.state.artifact_hash = artifact_hash
    _MockPaidBackendHandler.state.artifact_size = len(_MockPaidBackendHandler.state.wheel_bytes)

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
            self._send_json(
                {
                    "download_authorized": True,
                    "artifact_id": ARTIFACT_ID,
                    "package_name": "../../escape",
                    "package_version": PACKAGE_VERSION,
                    "platform": payload.get("platform", "linux"),
                    "python_version": payload.get("python_version", "3.14"),
                    "artifact_hash": self.state.artifact_hash,
                    "artifact_size_bytes": self.state.artifact_size,
                    "entitlement_id": "ent_test_001",
                    "license_key_fingerprint": hashlib.sha256(RAW_LICENSE_KEY.encode()).hexdigest()[:16],
                    "customer_ref_fingerprint": hashlib.sha256(CUSTOMER_REF.encode()).hexdigest()[:16],
                    "download_authorization_id": "dlauth_test_001",
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
    wheel_path, artifact_hash = _build_test_wheel(tmp_path / "wheel-build")
    wheel_bytes = wheel_path.read_bytes()
    metadata = verify_free_builder_wheel_artifact(
        wheel_bytes,
        expectations=FreeBuilderWheelExpectations(
            artifact_hash=artifact_hash,
            artifact_size_bytes=len(wheel_bytes),
            package_name=PACKAGE_NAME,
            package_version=PACKAGE_VERSION,
        ),
    )
    assert metadata.package_name == PACKAGE_NAME
    assert metadata.package_version == PACKAGE_VERSION


def test_verify_free_builder_wheel_artifact_rejects_hash_mismatch(tmp_path):
    wheel_path, artifact_hash = _build_test_wheel(tmp_path / "wheel-build")
    wheel_bytes = wheel_path.read_bytes()
    with pytest.raises(FreeBuilderInstallError):
        verify_free_builder_wheel_artifact(
            wheel_bytes,
            expectations=FreeBuilderWheelExpectations(
                artifact_hash="0" * 64,
                artifact_size_bytes=len(wheel_bytes),
                package_name=PACKAGE_NAME,
                package_version=PACKAGE_VERSION,
            ),
        )


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
