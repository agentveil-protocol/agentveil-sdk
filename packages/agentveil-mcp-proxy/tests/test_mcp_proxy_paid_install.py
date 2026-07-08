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
    HttpPaidBackendClient,
    PaidInstallError,
    install_wheel_to_vendor,
    parse_wheel_metadata,
    scan_paid_output_for_leaks,
    set_paid_backend_client,
    sha256_hex,
    validate_bounded_package_name,
    validate_bounded_package_version,
    verify_wheel_artifact,
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
            os.environ.pop("AVP_PAID_API_BASE_URL", None)
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
    os.environ["AVP_HOME"] = str(home)
    os.environ.pop("AVP_PAID_API_BASE_URL", None)
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
    assert code == 0
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
