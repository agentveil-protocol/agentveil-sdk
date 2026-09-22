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
PROXY_VERSION = "0.7.49"
BASE_PACKAGE_NAME = "agentveil-private-guardrails-base"
BASE_PACKAGE_VERSION = "0.1.0"
THIN_PACKAGE_NAME = "agentveil-private-policy-thin"
THIN_PACKAGE_VERSION = "0.1.3"
BASE_MODULE_NAME = BASE_PACKAGE_NAME.replace("-", "_")
THIN_MODULE_NAME = THIN_PACKAGE_NAME.replace("-", "_")
COMPOSED_BASE_ARTIFACT_ID = "art_pkg_private_guardrails_base_001"
COMPOSED_THIN_ARTIFACT_ID = "art_pkg_ca_basic_004"
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


_WHEEL_BUILD_COPY_IGNORE_NAMES = frozenset(
    {
        ".git",
        ".venv",
        ".worktrees",
        "build",
        "dist",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
    }
)

_SDK_SOURCE_RELATIVE_PARTS = (
    "agentveil",
    "agentveil_mcp",
    "agentveil_paperclip",
    "mcp_server",
    "pyproject.toml",
    "README_PYPI.md",
    "LICENSE",
    "MANIFEST.in",
    "CHANGELOG.md",
)

_PROXY_SOURCE_RELATIVE_PARTS = (
    "agentveil_mcp_proxy",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "MANIFEST.in",
)


def _wheel_build_copy_ignore(_directory: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        if name in _WHEEL_BUILD_COPY_IGNORE_NAMES or name.endswith(".egg-info"):
            ignored.add(name)
    return ignored


def _copy_public_source_tree(
    source_root: Path,
    dest_root: Path,
    *,
    relative_parts: tuple[str, ...],
) -> None:
    dest_root.mkdir(parents=True, exist_ok=True)
    for relative_part in relative_parts:
        source = source_root / relative_part
        if not source.exists():
            continue
        dest = dest_root / relative_part
        if source.is_dir():
            shutil.copytree(source, dest, ignore=_wheel_build_copy_ignore, dirs_exist_ok=False)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)


def _build_public_wheels(out_dir: Path) -> tuple[Path, Path]:
    sdk_source = out_dir / "sdk-source"
    proxy_source = out_dir / "proxy-source"
    _copy_public_source_tree(REPO_ROOT, sdk_source, relative_parts=_SDK_SOURCE_RELATIVE_PARTS)
    _copy_public_source_tree(MCP_PROXY_ROOT, proxy_source, relative_parts=_PROXY_SOURCE_RELATIVE_PARTS)

    sdk_wheel_dir = out_dir / "sdk-build"
    proxy_wheel_dir = out_dir / "proxy-build"
    sdk_wheel_dir.mkdir(parents=True, exist_ok=True)
    proxy_wheel_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(sdk_wheel_dir), str(sdk_source)],
        check=True,
        cwd=sdk_source,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--outdir",
            str(proxy_wheel_dir),
            str(proxy_source),
        ],
        check=True,
        cwd=proxy_source,
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
            COMPOSED_INSTALL_COMPOSITION_VERSION,
            EntitlementResult,
            InstallSafetyResult,
            PackageAuthorizeResult,
            set_paid_backend_client,
            run_paid_activate_install_flow,
        )

        RAW_LICENSE_KEY = {RAW_LICENSE_KEY!r}
        ENTITLEMENT_TOKEN = "ent.closure.test.token"
        BASE_PACKAGE_NAME = {BASE_PACKAGE_NAME!r}
        BASE_PACKAGE_VERSION = {BASE_PACKAGE_VERSION!r}
        THIN_PACKAGE_NAME = {THIN_PACKAGE_NAME!r}
        THIN_PACKAGE_VERSION = {THIN_PACKAGE_VERSION!r}
        BASE_MODULE_NAME = {BASE_MODULE_NAME!r}
        THIN_MODULE_NAME = {THIN_MODULE_NAME!r}
        COMPOSED_BASE_ARTIFACT_ID = {COMPOSED_BASE_ARTIFACT_ID!r}
        COMPOSED_THIN_ARTIFACT_ID = {COMPOSED_THIN_ARTIFACT_ID!r}
        HOOK_SOURCE = {CRYPTO_HOOK_SOURCE!r}

        @dataclass
        class _FakeBackend:
            base_wheel_bytes: bytes
            base_artifact_hash: str
            base_artifact_size: int
            thin_wheel_bytes: bytes
            thin_artifact_hash: str
            thin_artifact_size: int
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
                del platform_name, python_version
                assert entitlement_token == ENTITLEMENT_TOKEN
                if artifact_id == COMPOSED_BASE_ARTIFACT_ID:
                    return PackageAuthorizeResult(
                        download_authorized=True,
                        artifact_id=COMPOSED_BASE_ARTIFACT_ID,
                        package_name=BASE_PACKAGE_NAME,
                        package_version=BASE_PACKAGE_VERSION,
                        artifact_hash=self.base_artifact_hash,
                        artifact_size_bytes=self.base_artifact_size,
                        download_authorization_id="dlauth_closure_base_001",
                        public_fallback_available=True,
                        error_code=None,
                    )
                if artifact_id == COMPOSED_THIN_ARTIFACT_ID:
                    return PackageAuthorizeResult(
                        download_authorized=True,
                        artifact_id=COMPOSED_THIN_ARTIFACT_ID,
                        package_name=THIN_PACKAGE_NAME,
                        package_version=THIN_PACKAGE_VERSION,
                        artifact_hash=self.thin_artifact_hash,
                        artifact_size_bytes=self.thin_artifact_size,
                        download_authorization_id="dlauth_closure_thin_001",
                        public_fallback_available=True,
                        error_code=None,
                    )
                return PackageAuthorizeResult(
                    download_authorized=False,
                    artifact_id=artifact_id,
                    package_name=None,
                    package_version=None,
                    artifact_hash=None,
                    artifact_size_bytes=None,
                    download_authorization_id=None,
                    public_fallback_available=True,
                    error_code="download_denied",
                )

            def download_package(self, authorization: PackageAuthorizeResult) -> bytes:
                if authorization.download_authorization_id == "dlauth_closure_base_001":
                    return self.base_wheel_bytes
                if authorization.download_authorization_id == "dlauth_closure_thin_001":
                    return self.thin_wheel_bytes
                raise AssertionError("unexpected download authorization")

        def _base_wheel_bytes() -> tuple[bytes, str]:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(
                    f"{{BASE_MODULE_NAME}}/vendored_provider.py",
                    "class _Provider:\\n"
                    "    provider_id = 'private_v1'\\n"
                    "    provider_contract_version = '1'\\n"
                    "    def status(self):\\n"
                    "        return {{'provider_present': True, 'provider_id': 'private_v1', "
                    "'provider_contract_version': '1', 'status': 'active', "
                    "'private_provider_enabled': True, 'public_fallback_available': True, "
                    "'summary': 'ok', 'error_code': None}}\\n"
                    "def build_vendored_provider():\\n"
                    "    return _Provider()\\n",
                )
                archive.writestr(f"{{BASE_MODULE_NAME}}/handoff_hook.py", HOOK_SOURCE)
                metadata = f"Name: {{BASE_PACKAGE_NAME}}\\nVersion: {{BASE_PACKAGE_VERSION}}\\n"
                archive.writestr(
                    f"{{BASE_MODULE_NAME}}-{{BASE_PACKAGE_VERSION}}.dist-info/METADATA",
                    metadata,
                )
                archive.writestr(
                    f"{{BASE_MODULE_NAME}}-{{BASE_PACKAGE_VERSION}}.dist-info/entry_points.txt",
                    "[agentveil_mcp_proxy.installed_provider_activation_handoffs]\\n"
                    f"v1 = {{BASE_MODULE_NAME}}.handoff_hook:run_activation_handoff\\n"
                    "[agentveil_mcp_proxy.paid_providers]\\n"
                    f"private_v1 = {{BASE_MODULE_NAME}}.vendored_provider:build_vendored_provider\\n",
                )
                archive.writestr(
                    f"{{BASE_MODULE_NAME}}-{{BASE_PACKAGE_VERSION}}.dist-info/WHEEL",
                    "Wheel-Version: 1.0\\nGenerator: closure-test\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
                )
            data = buffer.getvalue()
            return data, hashlib.sha256(data).hexdigest()

        def _thin_wheel_bytes() -> tuple[bytes, str]:
            buffer = io.BytesIO()
            thin_provider = (
                "class _Provider:\\n"
                "    calls = []\\n"
                "    def descriptor(self):\\n"
                "        self.calls.append('descriptor')\\n"
                "        return {{'provider_id': 'private_v1'}}\\n"
                "def build_provider():\\n"
                "    return _Provider()\\n"
            )
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(f"{{THIN_MODULE_NAME}}/controlled_provider.py", thin_provider)
                metadata = f"Name: {{THIN_PACKAGE_NAME}}\\nVersion: {{THIN_PACKAGE_VERSION}}\\n"
                archive.writestr(
                    f"{{THIN_MODULE_NAME}}-{{THIN_PACKAGE_VERSION}}.dist-info/METADATA",
                    metadata,
                )
                archive.writestr(
                    f"{{THIN_MODULE_NAME}}-{{THIN_PACKAGE_VERSION}}.dist-info/entry_points.txt",
                    "[agentveil_mcp_proxy.controlled_alternative_providers]\\n"
                    f"private_v1 = {{THIN_MODULE_NAME}}.controlled_provider:build_provider\\n"
                    "[agentveil_mcp_proxy.controlled_alternative_authorities]\\n"
                    f"ca_route_v1 = {{THIN_MODULE_NAME}}.controlled_provider:build_provider\\n",
                )
                archive.writestr(
                    f"{{THIN_MODULE_NAME}}-{{THIN_PACKAGE_VERSION}}.dist-info/WHEEL",
                    "Wheel-Version: 1.0\\nGenerator: closure-test\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
                )
            data = buffer.getvalue()
            return data, hashlib.sha256(data).hexdigest()

        home = Path(sys.argv[1])
        base_wheel, base_digest = _base_wheel_bytes()
        thin_wheel, thin_digest = _thin_wheel_bytes()
        backend = _FakeBackend(
            base_wheel_bytes=base_wheel,
            base_artifact_hash=base_digest,
            base_artifact_size=len(base_wheel),
            thin_wheel_bytes=thin_wheel,
            thin_artifact_hash=thin_digest,
            thin_artifact_size=len(thin_wheel),
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
        install_state = result.install_state
        payload = {{
            "activation_status": result.activation_status,
            "install_status": install_state.get("status"),
            "provider_status": result.provider.status,
            "install_composition_version": install_state.get("install_composition_version"),
            "install_component_roles": [
                entry.get("role")
                for entry in (install_state.get("install_components") or [])
                if isinstance(entry, dict)
            ],
        }}
        print(json.dumps(payload))
        if payload["activation_status"] != STATUS_ACTIVE:
            raise SystemExit(1)
        if payload["install_status"] != STATUS_ACTIVE:
            raise SystemExit(1)
        if payload["provider_status"] != STATUS_ACTIVE:
            raise SystemExit(1)
        if payload["install_composition_version"] != COMPOSED_INSTALL_COMPOSITION_VERSION:
            raise SystemExit(1)
        if set(payload["install_component_roles"]) != {{
            "base_private_guardrails",
            "controlled_alternatives_basic",
        }}:
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
        assert payload["install_composition_version"] == "1"
        assert set(payload["install_component_roles"]) == {
            "base_private_guardrails",
            "controlled_alternatives_basic",
        }
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
