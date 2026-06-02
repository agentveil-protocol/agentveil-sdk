from __future__ import annotations

import importlib.util
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _release_acceptance_module():
    script = PACKAGE_ROOT / "scripts" / "mcp_proxy_release_acceptance.py"
    spec = importlib.util.spec_from_file_location("mcp_proxy_release_acceptance", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_proxy_package_console_script_entrypoint():
    with (PACKAGE_ROOT / "pyproject.toml").open("rb") as f:
        pyproject = tomllib.load(f)

    scripts = pyproject["project"].get("scripts", {})
    assert scripts.get("agentveil-mcp-proxy") == "agentveil_mcp_proxy.cli:main"


def test_proxy_package_uses_separate_license_file():
    with (PACKAGE_ROOT / "pyproject.toml").open("rb") as f:
        pyproject = tomllib.load(f)

    assert pyproject["project"]["license"] == "BUSL-1.1"
    assert pyproject["project"]["license-files"] == ["LICENSE"]
    license_text = (PACKAGE_ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Business Source License 1.1" in license_text
    assert "AgentVeil MCP Proxy" in license_text


def test_proxy_package_depends_on_public_sdk():
    with (PACKAGE_ROOT / "pyproject.toml").open("rb") as f:
        pyproject = tomllib.load(f)

    dependencies = pyproject["project"].get("dependencies", [])
    assert any(req.startswith("agentveil") for req in dependencies)


def test_release_acceptance_verifier_pins_proxy_and_backend_signers():
    acceptance = _release_acceptance_module()

    assert acceptance.verification_signer_dids(
        "did:key:zProxy",
        ["did:key:zBackend1", "did:key:zProxy", "did:key:zBackend2"],
    ) == ["did:key:zProxy", "did:key:zBackend1", "did:key:zBackend2"]
