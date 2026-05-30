from __future__ import annotations

from pathlib import Path
import tomllib


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


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
