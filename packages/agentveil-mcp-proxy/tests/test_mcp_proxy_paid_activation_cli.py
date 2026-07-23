"""CLI contract and privacy tests for public paid activation."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agentveil_mcp_proxy.cli import main
from agentveil_mcp_proxy.paid_activation import (
    ACTIVATION_FILENAME,
    BOUNDED_ACTIVATION_KEYS,
    ERROR_PROVIDER_ABSENT,
    PaidActivationError,
    STATUS_MISSING,
    activation_path,
    assert_activation_metadata_bounded,
    assert_license_key_redacted,
    assert_paid_human_output_no_overclaim,
    build_paid_activate_payload,
    build_paid_deactivate_payload,
    build_paid_status_payload,
    format_paid_human_output,
    load_activation_state,
    resolve_paid_activate_license_key,
    synthetic_license_id,
)
from agentveil_mcp_proxy.paid_install import set_paid_backend_client
from agentveil_mcp_proxy.paid_provider import PaidProviderSnapshot, discover_paid_provider

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
RAW_LICENSE_KEY = "avp_live_test_secret_key_do_not_leak_123456789"


@pytest.fixture(autouse=True)
def _reset_paid_backend_client(monkeypatch):
    set_paid_backend_client(None)
    # Offline/public-fallback path: explicit empty disables zero-config default URL.
    monkeypatch.setenv("AVP_PAID_API_BASE_URL", "")
    yield
    set_paid_backend_client(None)


def _home_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["AVP_HOME"] = str(home)
    # Explicit empty disables paid backend (offline/public-fallback path).
    env["AVP_PAID_API_BASE_URL"] = ""
    return env


def _run_main(argv: list[str], *, home: Path, stdin_text: str | None = None) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_home = os.environ.get("AVP_HOME")
    previous_base = os.environ.get("AVP_PAID_API_BASE_URL")
    previous_base_present = "AVP_PAID_API_BASE_URL" in os.environ
    os.environ["AVP_HOME"] = str(home)
    os.environ["AVP_PAID_API_BASE_URL"] = ""
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
        if not previous_base_present:
            os.environ.pop("AVP_PAID_API_BASE_URL", None)
        else:
            os.environ["AVP_PAID_API_BASE_URL"] = previous_base or ""
    return code, stdout.getvalue(), stderr.getvalue()


def test_discover_paid_provider_absent_by_default():
    discovery = discover_paid_provider()
    assert discovery == PaidProviderSnapshot(
        provider_present=False,
        status=STATUS_MISSING,
        public_fallback_available=True,
    )


def test_paid_activate_status_deactivate_cli_contract(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(
        ["paid", "activate", RAW_LICENSE_KEY, "--home", str(home)],
        home=home,
    )
    assert code == 0
    assert "Paid provider: absent" in out
    assert "Public fallback: active" in out
    assert "Paid activation: unavailable" in out
    assert f"Status: {STATUS_MISSING}" in out
    assert RAW_LICENSE_KEY not in out
    assert RAW_LICENSE_KEY not in err

    activation_file = home / "paid" / ACTIVATION_FILENAME
    assert activation_file.is_file()
    saved = json.loads(activation_file.read_text(encoding="utf-8"))
    assert_activation_metadata_bounded(saved)
    assert saved["status"] == STATUS_MISSING
    assert saved["provider_present"] is False
    assert saved["public_fallback_available"] is True
    assert saved["error_code"] == ERROR_PROVIDER_ABSENT
    assert saved["license_id"] == synthetic_license_id(RAW_LICENSE_KEY)
    assert RAW_LICENSE_KEY not in activation_file.read_text(encoding="utf-8")

    code, out, err = _run_main(["paid", "status", "--home", str(home)], home=home)
    assert code == 0
    assert "Paid provider: absent" in out
    assert f"Status: {STATUS_MISSING}" in out
    assert RAW_LICENSE_KEY not in out
    assert RAW_LICENSE_KEY not in err

    code, out, err = _run_main(["paid", "deactivate", "--home", str(home)], home=home)
    assert code == 0
    assert f"Status: {STATUS_MISSING}" in out
    assert RAW_LICENSE_KEY not in out
    assert RAW_LICENSE_KEY not in err

    saved = json.loads(activation_file.read_text(encoding="utf-8"))
    assert saved["status"] == STATUS_MISSING
    assert saved["license_id"] is None
    assert saved["error_code"] is None


def test_provider_absent_fallback_persists_public_fallback(tmp_path):
    home = tmp_path / "avp-home"
    payload = build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    assert payload["paid_provider_present"] is False
    assert payload["paid_activation_available"] is False
    assert payload["public_fallback_active"] is True
    assert payload["activation"]["status"] == STATUS_MISSING


def test_license_key_redacted_from_stdout_stderr_and_status_file(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(
        ["paid", "activate", RAW_LICENSE_KEY, "--home", str(home)],
        home=home,
    )
    assert code == 0
    combined = out + err
    assert_license_key_redacted(text=combined, license_key=RAW_LICENSE_KEY)
    file_text = activation_path(home).read_text(encoding="utf-8")
    assert_license_key_redacted(text=file_text, license_key=RAW_LICENSE_KEY)


def test_bounded_persisted_metadata_keys_only(tmp_path):
    home = tmp_path / "avp-home"
    build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home)
    saved = load_activation_state(activation_path(home))
    assert saved is not None
    assert set(saved) <= BOUNDED_ACTIVATION_KEYS


def test_no_overclaim_human_output(tmp_path):
    home = tmp_path / "avp-home"
    payloads = [
        build_paid_activate_payload(license_key=RAW_LICENSE_KEY, home=home),
        build_paid_status_payload(home=home),
        build_paid_deactivate_payload(home=home),
    ]
    for payload in payloads:
        text = format_paid_human_output(payload)
        assert_paid_human_output_no_overclaim(text)


def test_paid_status_without_prior_activation_reports_inactive(tmp_path):
    home = tmp_path / "avp-home"
    payload = build_paid_status_payload(home=home)
    assert payload["activation"]["status"] == STATUS_MISSING
    assert payload["public_fallback_active"] is True


def test_paid_json_output_is_privacy_safe(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(
        ["paid", "activate", RAW_LICENSE_KEY, "--home", str(home), "--json"],
        home=home,
    )
    assert code == 0
    payload = json.loads(out)
    assert payload["paid_provider_present"] is False
    assert payload["paid_activation_available"] is False
    assert RAW_LICENSE_KEY not in json.dumps(payload)
    assert RAW_LICENSE_KEY not in err


def test_paid_subprocess_entrypoint_contract(tmp_path):
    home = tmp_path / "avp-home"
    repo_root = PACKAGE_ROOT.parents[1]
    env = _home_env(home)
    env["PYTHONPATH"] = os.pathsep.join((str(repo_root), str(PACKAGE_ROOT)))
    commands = (
        [sys.executable, "-m", "agentveil_mcp_proxy.cli", "paid", "activate", RAW_LICENSE_KEY, "--home", str(home)],
        [sys.executable, "-m", "agentveil_mcp_proxy.cli", "paid", "status", "--home", str(home)],
        [sys.executable, "-m", "agentveil_mcp_proxy.cli", "paid", "deactivate", "--home", str(home)],
    )
    for cmd in commands:
        result = subprocess.run(
            cmd,
            cwd=PACKAGE_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert RAW_LICENSE_KEY not in result.stdout
        assert RAW_LICENSE_KEY not in result.stderr


def test_empty_license_key_is_rejected(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(["paid", "activate", "   ", "--home", str(home)], home=home)
    assert code == 2
    assert "license key" in err.lower()


def test_stdin_activation_works(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        stdin_text=f"  {RAW_LICENSE_KEY}  \n",
    )
    assert code == 0
    assert "Paid provider: absent" in out
    assert RAW_LICENSE_KEY not in out
    assert RAW_LICENSE_KEY not in err


def test_positional_and_stdin_conflict_is_rejected(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(
        ["paid", "activate", RAW_LICENSE_KEY, "--license-key-stdin", "--home", str(home)],
        home=home,
        stdin_text=f"{RAW_LICENSE_KEY}\n",
    )
    assert code == 2
    assert "not both" in err.lower()


def test_empty_stdin_is_rejected(tmp_path):
    home = tmp_path / "avp-home"
    code, out, err = _run_main(
        ["paid", "activate", "--license-key-stdin", "--home", str(home)],
        home=home,
        stdin_text="   \n",
    )
    assert code == 2
    assert "stdin" in err.lower()


def test_resolve_paid_activate_license_key_unit():
    assert resolve_paid_activate_license_key(
        license_key="abc",
        license_key_stdin=False,
    ) == "abc"
    assert resolve_paid_activate_license_key(
        license_key=None,
        license_key_stdin=True,
        stdin=io.StringIO(" stdin-key \n"),
    ) == "stdin-key"
    with pytest.raises(PaidActivationError, match="not both"):
        resolve_paid_activate_license_key(
            license_key="abc",
            license_key_stdin=True,
            stdin=io.StringIO("stdin-key\n"),
        )
