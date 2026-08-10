"""Clean-environment wheel install and installed-provider dependency closure proof."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import uuid
import zipfile
from pathlib import Path

import pytest
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[3]
MCP_PROXY_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_CONTRACT_PATH = (
    MCP_PROXY_ROOT
    / "agentveil_mcp_proxy"
    / "contracts"
    / "installed_provider_activation_handoff_v1.json"
)
SDK_VERSION = "0.7.23"
PROXY_VERSION = "0.7.40"
PACKAGE_NAME = "agentveil-private-policy"
PACKAGE_VERSION = "0.1.0"
MODULE_NAME = PACKAGE_NAME.replace("-", "_")
RAW_LICENSE_KEY = "avp_live_closure_secret_key_do_not_leak_xyz789"
CANONICAL_WHEEL_CONTRACT_MEMBER = (
    "agentveil_mcp_proxy/contracts/installed_provider_activation_handoff_v1.json"
)

CRYPTO_HOOK_SOURCE = textwrap.dedent(
    """
    from nacl.signing import SigningKey
    from cryptography.hazmat.primitives import hashes

    def run_activation_handoff(request):
        SigningKey.generate()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(b"closure-proof")
        digest.finalize()
        return {
            "contract_version": "1",
            "status": "active",
            "public_fallback_available": True,
            "summary": "crypto-deps-ok",
            "error_code": None,
        }
    """
)


def _expected_contract() -> dict:
    return json.loads(CANONICAL_CONTRACT_PATH.read_text(encoding="utf-8"))


def _outside_repo_root(label: str) -> Path:
    root = Path("/tmp") / "avp-rb-closure" / label
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    return root


def _resolve_python312() -> str | None:
    for candidate in ("python3.12", "/opt/homebrew/bin/python3.12", "/usr/local/bin/python3.12"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _docker_python312_available() -> bool:
    if shutil.which("docker") is None:
        return False
    if subprocess.run(["docker", "image", "inspect", "python:3.12-slim"], capture_output=True).returncode == 0:
        return True
    return subprocess.run(["docker", "pull", "python:3.12-slim"], capture_output=True).returncode == 0


def _build_public_wheels(out_dir: Path) -> tuple[Path, Path]:
    sdk_wheel_dir = out_dir / "sdk-build"
    proxy_wheel_dir = out_dir / "proxy-build"
    sdk_wheel_dir.mkdir(parents=True, exist_ok=True)
    proxy_wheel_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(sdk_wheel_dir), str(REPO_ROOT)],
        check=True,
        cwd=REPO_ROOT,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--outdir",
            str(proxy_wheel_dir),
            str(MCP_PROXY_ROOT),
        ],
        check=True,
        cwd=MCP_PROXY_ROOT,
    )

    sdk_wheels = sorted(sdk_wheel_dir.glob("agentveil-*.whl"))
    proxy_wheels = sorted(proxy_wheel_dir.glob("agentveil_mcp_proxy-*.whl"))
    assert len(sdk_wheels) == 1, sdk_wheels
    assert len(proxy_wheels) == 1, proxy_wheels
    return sdk_wheels[0], proxy_wheels[0]


def _assert_proxy_wheel_contains_single_canonical_contract(proxy_wheel: Path) -> None:
    with zipfile.ZipFile(proxy_wheel) as archive:
        contract_members = [
            name
            for name in archive.namelist()
            if name.startswith("agentveil_mcp_proxy/contracts/") and name.endswith(".json")
        ]
    assert contract_members == [CANONICAL_WHEEL_CONTRACT_MEMBER]
    with zipfile.ZipFile(proxy_wheel) as archive:
        wheel_contract = json.loads(archive.read(CANONICAL_WHEEL_CONTRACT_MEMBER))
    assert wheel_contract == _expected_contract()


def _write_expected_contract(scripts_dir: Path) -> Path:
    path = scripts_dir / "expected_contract.json"
    path.write_text(json.dumps(_expected_contract(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_activation_script(scripts_dir: Path) -> Path:
    script = textwrap.dedent(
        f"""
        import hashlib
        import io
        import json
        import sys
        import zipfile
        from dataclasses import dataclass
        from pathlib import Path

        from agentveil_mcp_proxy.paid_activation import STATUS_ACTIVE
        from agentveil_mcp_proxy.paid_install import (
            ActivationValidateResult,
            EntitlementResult,
            InstallSafetyResult,
            PackageAuthorizeResult,
            set_paid_backend_client,
            run_paid_activate_install_flow,
        )

        RAW_LICENSE_KEY = {RAW_LICENSE_KEY!r}
        ENTITLEMENT_TOKEN = "ent.closure.test.token"
        PACKAGE_NAME = {PACKAGE_NAME!r}
        PACKAGE_VERSION = {PACKAGE_VERSION!r}
        MODULE_NAME = {MODULE_NAME!r}
        HOOK_SOURCE = {CRYPTO_HOOK_SOURCE!r}

        @dataclass
        class _FakeBackend:
            wheel_bytes: bytes
            artifact_hash: str
            artifact_size: int
            provider_handoff_required: bool = True

            def validate_activation(self, license_key: str) -> ActivationValidateResult:
                assert license_key == RAW_LICENSE_KEY
                return ActivationValidateResult(
                    valid=True,  # claim-check: allow clean-install fake-backend fixture.
                    customer_ref_fingerprint="cust_fp",
                    plan="builder",
                    license_status="active",
                    subscription_status="active",
                    period_end=None,
                    public_fallback_available=True,
                    error_code=None,
                    provider_handoff_required=self.provider_handoff_required,
                )

            def issue_entitlement(
                self,
                license_key: str,
                validation: ActivationValidateResult,
            ) -> EntitlementResult:
                del license_key, validation
                return EntitlementResult(
                    entitlement_token=ENTITLEMENT_TOKEN,
                    entitlement_id="ent_closure_001",
                    expires_at=None,
                )

            def check_install_safety(self, entitlement_token: str) -> InstallSafetyResult:
                assert entitlement_token == ENTITLEMENT_TOKEN
                return InstallSafetyResult(
                    ok=True,
                    decision="allow",
                    reason_code="registry_trusted",
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
                    download_authorization_id="dlauth_closure_001",
                    public_fallback_available=True,
                    error_code=None,
                )

            def download_package(self, authorization: PackageAuthorizeResult) -> bytes:
                assert authorization.download_authorization_id == "dlauth_closure_001"
                return self.wheel_bytes

        def _wheel_bytes() -> tuple[bytes, str]:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(f"{{MODULE_NAME}}/__init__.py", "provider_id = 'neutral_v1'\\n")
                archive.writestr(f"{{MODULE_NAME}}/handoff_hook.py", HOOK_SOURCE)
                metadata = f"Name: {{PACKAGE_NAME}}\\nVersion: {{PACKAGE_VERSION}}\\n"
                archive.writestr(
                    f"{{MODULE_NAME}}-{{PACKAGE_VERSION}}.dist-info/METADATA",
                    metadata,
                )
                archive.writestr(
                    f"{{MODULE_NAME}}-{{PACKAGE_VERSION}}.dist-info/entry_points.txt",
                    "[agentveil_mcp_proxy.installed_provider_activation_handoffs]\\n"
                    f"v1 = {{MODULE_NAME}}.handoff_hook:run_activation_handoff\\n",
                )
                archive.writestr(
                    f"{{MODULE_NAME}}-{{PACKAGE_VERSION}}.dist-info/WHEEL",
                    "Wheel-Version: 1.0\\nGenerator: closure-test\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
                )
            data = buffer.getvalue()
            return data, hashlib.sha256(data).hexdigest()

        home = Path(sys.argv[1])
        wheel, digest = _wheel_bytes()
        backend = _FakeBackend(
            wheel_bytes=wheel,
            artifact_hash=digest,
            artifact_size=len(wheel),
            provider_handoff_required=True,
        )
        set_paid_backend_client(backend)
        try:
            result = run_paid_activate_install_flow(
                license_key=RAW_LICENSE_KEY,
                home=home,
                client=backend,
            )
        except Exception as exc:
            print(json.dumps({{"error": type(exc).__name__, "message": str(exc)}}))
            raise SystemExit(1) from exc
        payload = {{
            "activation_status": result.activation_status,
            "install_status": result.install_state.get("status"),
            "provider_status": result.provider.status,
        }}
        print(json.dumps(payload))
        if payload["activation_status"] != STATUS_ACTIVE:
            raise SystemExit(1)
        if payload["install_status"] != STATUS_ACTIVE:
            raise SystemExit(1)
        if payload["provider_status"] != STATUS_ACTIVE:
            raise SystemExit(1)
        """
    )
    path = scripts_dir / "run_closure_activation.py"
    path.write_text(textwrap.dedent(script), encoding="utf-8")
    return path


def _write_metadata_script(scripts_dir: Path, *, expect_crypto: bool) -> Path:
    script = textwrap.dedent(
        f"""
        import importlib.metadata as md
        import importlib.resources
        import importlib.util
        import json
        import sys
        from pathlib import Path
        from packaging.version import Version

        venv_root = Path(sys.prefix).resolve()
        repo_root = Path({str(REPO_ROOT)!r}).resolve()
        worktree_proxy_root = Path({str(MCP_PROXY_ROOT)!r}).resolve()
        expect_crypto = {expect_crypto!r}

        import agentveil
        import agentveil_mcp_proxy

        agentveil_origin = Path(agentveil.__file__).resolve()
        proxy_origin = Path(agentveil_mcp_proxy.__file__).resolve()
        assert str(agentveil_origin).startswith(str(venv_root)), agentveil_origin
        assert str(proxy_origin).startswith(str(venv_root)), proxy_origin
        assert repo_root not in agentveil_origin.parents
        assert worktree_proxy_root not in proxy_origin.parents

        if expect_crypto:
            import cryptography
            crypto_origin = Path(cryptography.__file__).resolve()
            assert str(crypto_origin).startswith(str(venv_root)), crypto_origin
            crypto_version = md.version("cryptography")
            assert Version(crypto_version) >= Version("42.0.0")
        else:
            assert importlib.util.find_spec("cryptography") is None
            crypto_version = None

        import nacl
        pynacl_origin = Path(nacl.__file__).resolve()
        assert str(pynacl_origin).startswith(str(venv_root)), pynacl_origin
        assert Version(md.version("agentveil")) == Version("{SDK_VERSION}")
        assert Version(md.version("agentveil-mcp-proxy")) == Version("{PROXY_VERSION}")
        assert Version(md.version("pynacl")) >= Version("1.5.0")

        contract_resource = importlib.resources.files("agentveil_mcp_proxy").joinpath(
            "contracts/installed_provider_activation_handoff_v1.json"
        )
        assert contract_resource.is_file(), contract_resource
        installed_contract = json.loads(contract_resource.read_bytes().decode("utf-8"))
        expected_contract = json.loads(
            Path(__file__).resolve().parent.joinpath("expected_contract.json").read_text(encoding="utf-8")
        )
        assert installed_contract == expected_contract
        assert installed_contract["privacy"]["deny_only_metadata"] is True
        assert {RAW_LICENSE_KEY!r} not in json.dumps(installed_contract)

        print(json.dumps({{
            "agentveil": md.version("agentveil"),
            "agentveil_mcp_proxy": md.version("agentveil-mcp-proxy"),
            "pynacl": md.version("pynacl"),
            "cryptography": crypto_version,
            "contract_owner": contract_resource.as_posix(),
            "contract_exact_match": True,
            "agentveil_origin": str(agentveil_origin),
            "proxy_origin": str(proxy_origin),
        }}))
        """
    )
    path = scripts_dir / "verify_metadata.py"
    path.write_text(textwrap.dedent(script), encoding="utf-8")
    return path


def _run_native_probe(
    *,
    work_root: Path,
    sdk_wheel: Path,
    proxy_wheel: Path,
    python312: str,
    install_mode: str,
) -> subprocess.CompletedProcess[str]:
    wheels_dir = work_root / "wheels"
    scripts_dir = work_root / "scripts"
    venv_dir = work_root / "venv"
    home_dir = work_root / "avp-home"
    wheels_dir.mkdir()
    scripts_dir.mkdir()
    home_dir.mkdir()
    shutil.copy2(sdk_wheel, wheels_dir / sdk_wheel.name)
    shutil.copy2(proxy_wheel, wheels_dir / proxy_wheel.name)
    _write_expected_contract(scripts_dir)
    activation_script = _write_activation_script(scripts_dir)
    metadata_script = _write_metadata_script(scripts_dir, expect_crypto=install_mode == "full")

    subprocess.run([python312, "-m", "venv", str(venv_dir)], check=True)
    pip = venv_dir / "bin" / "pip"
    py = venv_dir / "bin" / "python"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}

    subprocess.run([str(pip), "install", "--upgrade", "pip", "packaging"], check=True, env=env)
    subprocess.run([str(pip), "install", "--no-cache-dir", str(sdk_wheel)], check=True, env=env)
    if install_mode == "full":
        subprocess.run([str(pip), "install", "--no-cache-dir", str(proxy_wheel)], check=True, env=env)
    else:
        subprocess.run(
            [str(pip), "install", "--no-cache-dir", "--no-deps", str(proxy_wheel)],
            check=True,
            env=env,
        )

    meta = subprocess.run([str(py), str(metadata_script)], capture_output=True, text=True, env=env)
    if meta.returncode != 0:
        return meta
    activation = subprocess.run(
        [str(py), str(activation_script), str(home_dir)],
        capture_output=True,
        text=True,
        env=env,
    )
    activation.stdout = meta.stdout + activation.stdout
    return activation


def _run_docker_probe(
    *,
    work_root: Path,
    sdk_wheel: Path,
    proxy_wheel: Path,
    install_mode: str,
) -> subprocess.CompletedProcess[str]:
    wheels_dir = work_root / "wheels"
    scripts_dir = work_root / "scripts"
    home_dir = work_root / "avp-home"
    wheels_dir.mkdir()
    scripts_dir.mkdir()
    home_dir.mkdir()
    shutil.copy2(sdk_wheel, wheels_dir / sdk_wheel.name)
    shutil.copy2(proxy_wheel, wheels_dir / proxy_wheel.name)
    _write_expected_contract(scripts_dir)
    _write_activation_script(scripts_dir)
    _write_metadata_script(scripts_dir, expect_crypto=install_mode == "full")

    inner = textwrap.dedent(
        """
        set -euo pipefail
        python3.12 -m venv /work/venv
        /work/venv/bin/pip install --upgrade pip packaging
        """
    )
    if install_mode == "full":
        inner += textwrap.dedent(
            f"""
            /work/venv/bin/pip install --no-cache-dir /work/wheels/{sdk_wheel.name}
            /work/venv/bin/pip install --no-cache-dir /work/wheels/{proxy_wheel.name}
            """
        )
    else:
        inner += textwrap.dedent(
            f"""
            /work/venv/bin/pip install --no-cache-dir /work/wheels/{sdk_wheel.name}
            /work/venv/bin/pip install --no-cache-dir --no-deps /work/wheels/{proxy_wheel.name}
            """
        )
    inner += textwrap.dedent(
        """
        /work/venv/bin/python /work/scripts/verify_metadata.py
        /work/venv/bin/python /work/scripts/run_closure_activation.py /work/avp-home
        """
    )
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{work_root}:/work",
            "python:3.12-slim",
            "bash",
            "-lc",
            inner,
        ],
        capture_output=True,
        text=True,
    )


def _run_clean_install_probe(
    *,
    work_root: Path,
    sdk_wheel: Path,
    proxy_wheel: Path,
    install_mode: str,
) -> subprocess.CompletedProcess[str]:
    python312 = _resolve_python312()
    if python312 is not None:
        return _run_native_probe(
            work_root=work_root,
            sdk_wheel=sdk_wheel,
            proxy_wheel=proxy_wheel,
            python312=python312,
            install_mode=install_mode,
        )
    if not _docker_python312_available():
        pytest.fail("Python 3.12 not found locally and docker python:3.12-slim unavailable")
    return _run_docker_probe(
        work_root=work_root,
        sdk_wheel=sdk_wheel,
        proxy_wheel=proxy_wheel,
        install_mode=install_mode,
    )


@pytest.fixture(scope="module")
def built_public_wheels() -> tuple[Path, Path]:
    root = _outside_repo_root(f"wheel-build-{uuid.uuid4().hex[:8]}")
    sdk_wheel, proxy_wheel = _build_public_wheels(root)
    _assert_proxy_wheel_contains_single_canonical_contract(proxy_wheel)
    yield sdk_wheel, proxy_wheel
    shutil.rmtree(root, ignore_errors=True)


def test_clean_python312_install_resolves_crypto_dependencies_and_runs_handoff(
    built_public_wheels,
):
    sdk_wheel, proxy_wheel = built_public_wheels
    _assert_proxy_wheel_contains_single_canonical_contract(proxy_wheel)
    work_root = _outside_repo_root(f"full-{uuid.uuid4().hex[:8]}")
    try:
        proc = _run_clean_install_probe(
            work_root=work_root,
            sdk_wheel=sdk_wheel,
            proxy_wheel=proxy_wheel,
            install_mode="full",
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        json_lines = [line for line in proc.stdout.splitlines() if line.strip().startswith("{")]
        assert len(json_lines) >= 2, proc.stdout + proc.stderr
        metadata = json.loads(json_lines[0])
        payload = json.loads(json_lines[-1])
        assert metadata["agentveil"] == SDK_VERSION
        assert metadata["agentveil_mcp_proxy"] == PROXY_VERSION
        assert metadata["contract_exact_match"] is True
        assert metadata["contract_owner"].endswith(CANONICAL_WHEEL_CONTRACT_MEMBER)
        assert Version(metadata["pynacl"]) >= Version("1.5.0")
        assert Version(metadata["cryptography"]) >= Version("42.0.0")
        assert "/venv/" in metadata["agentveil_origin"].replace("\\", "/")
        assert "/venv/" in metadata["proxy_origin"].replace("\\", "/")
        assert payload["activation_status"] == "active"
        assert payload["install_status"] == "active"
        assert payload["provider_status"] == "active"
        assert RAW_LICENSE_KEY not in proc.stdout
        assert RAW_LICENSE_KEY not in proc.stderr
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def test_missing_cryptography_fails_closed_without_active_state(built_public_wheels):
    sdk_wheel, proxy_wheel = built_public_wheels
    work_root = _outside_repo_root(f"no-crypto-{uuid.uuid4().hex[:8]}")
    try:
        proc = _run_clean_install_probe(
            work_root=work_root,
            sdk_wheel=sdk_wheel,
            proxy_wheel=proxy_wheel,
            install_mode="no_proxy_deps",
        )
        assert proc.returncode != 0, proc.stdout + proc.stderr
        combined = proc.stdout + proc.stderr
        assert RAW_LICENSE_KEY not in combined
        install_path = work_root / "avp-home" / "paid" / "install.json"
        activation_path = work_root / "avp-home" / "paid" / "activation.json"
        if install_path.is_file():
            assert json.loads(install_path.read_text()).get("status") != "active"
        if activation_path.is_file():
            assert json.loads(activation_path.read_text()).get("status") != "active"
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
