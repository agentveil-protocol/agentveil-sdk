"""
MCP Slice 2 — packaging and import smoke tests.

These tests verify the local-first foundation laid in Slice 1:
- the canonical `agentveil_mcp` package is importable and wired correctly,
- the `mcp_server` deprecation shim still works and emits DeprecationWarning,
- pyproject.toml metadata matches the documented canonical paths,
- the README files agree on canonical vs deprecated terminology.

They do NOT start the MCP server, do NOT make network calls, and do NOT
install the package into the environment. If the `mcp` runtime is not
installed, tests that need to import the server module are skipped.
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import warnings

import pytest

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
CANONICAL_README = REPO_ROOT / "agentveil_mcp" / "README.md"
TOP_README = REPO_ROOT / "README.md"
MCP_DOCKERFILE = REPO_ROOT / "mcp_server" / "Dockerfile"
MCP_SERVER = REPO_ROOT / "agentveil_mcp" / "server.py"
AGENTS_DOC = REPO_ROOT / "AGENTS.md"
INTEGRATIONS_DOC = REPO_ROOT / "docs" / "INTEGRATIONS.md"
CLAUDE_MCP_EXAMPLE = REPO_ROOT / "examples" / "claude_mcp_example.py"
LEGACY_CLAUDE_MCP_MODULE = REPO_ROOT / "agentveil" / "tools" / "claude_mcp.py"


def _mcp_runtime_available() -> bool:
    """True iff the `mcp` runtime is importable."""
    try:
        import mcp.server.fastmcp  # noqa: F401
        return True
    except ImportError:
        return False


requires_mcp = pytest.mark.skipif(
    not _mcp_runtime_available(),
    reason="MCP runtime not installed; install with pip install 'agentveil[mcp]'",
)


# ------------------------------------------------------------------
# Group A — canonical imports
# ------------------------------------------------------------------

def _purge(modname: str) -> None:
    """Drop a module and its submodules from sys.modules so re-import fires __init__."""
    for key in [k for k in sys.modules if k == modname or k.startswith(modname + ".")]:
        del sys.modules[key]


@requires_mcp
def test_canonical_package_importable():
    import agentveil_mcp  # noqa: F401
    assert agentveil_mcp.__name__ == "agentveil_mcp"


@requires_mcp
def test_canonical_server_module_importable():
    import agentveil_mcp.server  # noqa: F401


@requires_mcp
def test_canonical_main_is_callable():
    from agentveil_mcp.server import main
    assert callable(main)


@requires_mcp
def test_canonical_mcp_instance_present():
    from mcp.server.fastmcp import FastMCP
    from agentveil_mcp.server import mcp
    assert isinstance(mcp, FastMCP)


@requires_mcp
def test_module_entry_importable_without_running():
    # Just verifying __main__.py parses and is loadable. Running it would
    # call mcp.run() and block; we don't want that. Import via spec instead.
    import importlib.util

    spec = importlib.util.find_spec("agentveil_mcp.__main__")
    assert spec is not None
    assert spec.origin and spec.origin.endswith("__main__.py")


@requires_mcp
def test_tool_count_sanity():
    """Guard against accidentally dropping a tool during future refactors."""
    import agentveil_mcp.server as s

    # FastMCP exposes an internal tool registry; names may differ across versions.
    # Count function objects in the module that were decorated by @mcp.tool().
    # The decorator registers them; they remain module attributes as plain functions.
    expected = {
        "check_reputation", "check_trust", "get_agent_info", "search_agents",
        "get_attestations_received", "get_protocol_stats", "verify_audit_chain",
        "get_audit_trail", "register_agent", "submit_attestation",
        "publish_agent_card", "get_my_agent_info", "runtime_evaluate_action",
        "controlled_action", "get_approval_request", "approve_action",
        "deny_action", "execute_after_approval", "get_decision_receipt",
        "get_execution_receipt",
    }
    present = {name for name in expected if callable(getattr(s, name, None))}
    assert present == expected, f"missing tool callables: {expected - present}"


# ------------------------------------------------------------------
# Group B — shim backward compat
# ------------------------------------------------------------------

@requires_mcp
def test_shim_import_emits_deprecation_warning():
    _purge("mcp_server")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import mcp_server  # noqa: F401
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert dep, "expected DeprecationWarning on `import mcp_server`"


@requires_mcp
def test_shim_server_import_emits_deprecation_warning():
    _purge("mcp_server")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import mcp_server.server  # noqa: F401
    dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert dep, "expected DeprecationWarning on `import mcp_server.server`"


@requires_mcp
def test_shim_main_is_same_object_as_canonical_main():
    _purge("mcp_server")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        from mcp_server.server import main as shim_main
    from agentveil_mcp.server import main as canonical_main
    assert shim_main is canonical_main, "shim should re-export the same callable, not a copy"


# ------------------------------------------------------------------
# Group C — packaging metadata (no mcp runtime needed, but we're past importorskip)
# ------------------------------------------------------------------

@pytest.fixture(scope="module")
def pyproject() -> dict:
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)


def test_console_script_entrypoint(pyproject):
    scripts = pyproject["project"].get("scripts", {})
    assert scripts.get("agentveil-mcp") == "agentveil_mcp.server:main", (
        "console_script 'agentveil-mcp' must point to agentveil_mcp.server:main"
    )


def test_mcp_runtime_dependency_present_for_console_script(pyproject):
    dependencies = pyproject["project"].get("dependencies", [])
    assert any(req.startswith("mcp") for req in dependencies), (
        "agentveil-mcp is installed by default, so the mcp runtime must be a base dependency"
    )


def test_mcp_optional_dependency_present(pyproject):
    extras = pyproject["project"].get("optional-dependencies", {})
    assert "mcp" in extras, "[project.optional-dependencies].mcp missing"
    assert any(req.startswith("mcp") for req in extras["mcp"]), (
        "the 'mcp' extra must require the mcp runtime package"
    )


def test_packages_find_includes_both_packages(pyproject):
    include = pyproject["tool"]["setuptools"]["packages"]["find"]["include"]
    assert "agentveil_mcp*" in include, "agentveil_mcp* must be in packages.find.include"
    assert "mcp_server*" in include, (
        "mcp_server* must remain in packages.find.include so the shim ships"
    )
    assert "agentveil*" in include


def test_project_name_unchanged(pyproject):
    assert pyproject["project"]["name"] == "agentveil", (
        "Slice 1 must not rename the agentveil distribution"
    )


# ------------------------------------------------------------------
# Group D — README canonical vs deprecated terminology
# ------------------------------------------------------------------

def test_canonical_readme_declares_agentveil_mcp_as_canonical():
    text = CANONICAL_README.read_text()
    assert "agentveil-mcp" in text
    assert "canonical" in text.lower(), (
        "agentveil_mcp/README.md must explicitly label the canonical path"
    )


def test_canonical_readme_marks_mcp_server_as_deprecated():
    text = CANONICAL_README.read_text().lower()
    assert "deprecated" in text, "README must mention deprecation of mcp_server"
    assert "mcp_server" in text, "README must reference old mcp_server path to migrate from"


def test_top_readme_uses_extras_install_form():
    text = TOP_README.read_text()
    # The Claude/Hermes rows should use the `'agentveil[mcp]'` extras form,
    # not the bare `pip install agentveil mcp` two-package form.
    assert "pip install 'agentveil[mcp]'" in text, (
        "top-level README should advertise the [mcp] extras install form"
    )
    # Guard against regression to the old two-package form in the integrations table rows
    # that mention MCP.
    for line in text.splitlines():
        low = line.lower()
        if "mcp" in low and "pip install" in low and "agentveil" in low:
            assert "pip install agentveil mcp" not in line, (
                f"regression: two-package install form in: {line.strip()}"
            )


def test_mcp_dockerfile_uses_extras_install_form():
    text = MCP_DOCKERFILE.read_text()
    assert "pip install --no-cache-dir 'agentveil[mcp]' httpx" in text
    assert "pip install --no-cache-dir agentveil mcp" not in text


def test_mcp_protocol_info_advertises_mcp_extra_install():
    text = MCP_SERVER.read_text()
    assert '"mcp": "pip install \'agentveil[mcp]\'"' in text


def test_public_mcp_docs_use_canonical_install_and_command_paths():
    docs = {
        "AGENTS.md": AGENTS_DOC.read_text(),
        "docs/INTEGRATIONS.md": INTEGRATIONS_DOC.read_text(),
        "examples/claude_mcp_example.py": CLAUDE_MCP_EXAMPLE.read_text(),
        "agentveil/tools/claude_mcp.py": LEGACY_CLAUDE_MCP_MODULE.read_text(),
    }

    for name, text in docs.items():
        assert "pip install agentveil mcp" not in text, (
            f"{name} must use the [mcp] extra, not a two-package install"
        )
        assert "mcp_server.avp" not in text, (
            f"{name} references a non-existent mcp_server.avp module"
        )
        assert "python -m agentveil.tools.claude_mcp" not in text, (
            f"{name} should advertise the canonical agentveil-mcp command"
        )
        assert '"args": ["-m", "agentveil.tools.claude_mcp"]' not in text, (
            f"{name} should not advertise the legacy Python module config"
        )
        assert '"args": ["-m", "mcp_server.server"]' not in text, (
            f"{name} should not advertise deprecated mcp_server.server config"
        )

    assert "pip install 'agentveil[mcp]'" in AGENTS_DOC.read_text()
    assert "pip install 'agentveil[mcp]'" in INTEGRATIONS_DOC.read_text()
    assert "pip install 'agentveil[mcp]'" in CLAUDE_MCP_EXAMPLE.read_text()
    assert "pip install 'agentveil[mcp]'" in LEGACY_CLAUDE_MCP_MODULE.read_text()
    assert "agentveil-mcp" in AGENTS_DOC.read_text()
    assert '"command": "agentveil-mcp"' in INTEGRATIONS_DOC.read_text()
    assert '"command": "agentveil-mcp"' in CLAUDE_MCP_EXAMPLE.read_text()
    assert '"command": "agentveil-mcp"' in LEGACY_CLAUDE_MCP_MODULE.read_text()
