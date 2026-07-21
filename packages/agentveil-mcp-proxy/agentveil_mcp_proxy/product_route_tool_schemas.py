"""Deterministic MCP tool schemas for the product route catalog."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentveil_mcp_proxy.product_route import (
    FILESYSTEM_PRODUCT_TOOLS,
    GITHUB_PRODUCT_TOOLS,
    GIT_PRODUCT_TOOLS,
    PACKAGE_PRODUCT_TOOLS,
    PRODUCT_ROUTE_TOOL_CATALOG,
)
from agentveil_mcp_proxy.quickstart_filesystem import _tools as quickstart_filesystem_tools

_GIT_REPO_PATH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "repo_path": {
            "type": "string",
            "description": (
                "Optional git repository path. Defaults to the configured "
                "product profile workspace when omitted."
            ),
        },
        "staged": {
            "type": "boolean",
            "description": (
                "For git_diff only. When true, summarize staged/index changes "
                "via git diff --cached --stat instead of unstaged working-tree diff."
            ),
        },
    },
    "required": [],
    "additionalProperties": True,
}

_PACKAGE_NAME_SCHEMA: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$",
    "description": (
        "Optional PyPI distribution name for package tools. Defaults to the "
        "configured offline product-route test package when omitted."
    ),
}

_PACKAGE_PROJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "project_path": {
            "type": "string",
            "description": (
                "Optional package project root. Defaults to the configured "
                "product profile package project when omitted."
            ),
        },
        "package_name": dict(_PACKAGE_NAME_SCHEMA),
    },
    "required": [],
    "additionalProperties": True,
}

_GITHUB_REPO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "owner": {
            "type": "string",
            "description": (
                "Optional repository owner. Defaults to the configured "
                "product profile GitHub target when omitted."
            ),
        },
        "repo": {
            "type": "string",
            "description": (
                "Optional repository name. Defaults to the configured "
                "product profile GitHub target when omitted."
            ),
        },
        "repo_root": {
            "type": "string",
            "description": (
                "Optional local content root. Defaults to the configured "
                "product profile GitHub content root when omitted."
            ),
        },
        "issue_number": {"type": "integer"},
        "pull_number": {"type": "integer"},
        "comment_body": {"type": "string"},
        "branch": {"type": "string"},
        "secret_name": {"type": "string"},
        "visibility": {"type": "string"},
        "tag_name": {"type": "string"},
        "workflow_run_id": {"type": "integer"},
    },
    "required": [],
    "additionalProperties": True,
}


def _filesystem_tool_entries() -> dict[str, dict[str, Any]]:
    return {entry["name"]: entry for entry in quickstart_filesystem_tools()}


def _git_tool_entry(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{name} (product route git pack)",
        "inputSchema": dict(_GIT_REPO_PATH_SCHEMA),
    }


def _package_tool_entry(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{name} (product route package pack)",
        "inputSchema": dict(_PACKAGE_PROJECT_SCHEMA),
    }


def _github_tool_entry(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"{name} (product route github/ci pack)",
        "inputSchema": dict(_GITHUB_REPO_SCHEMA),
    }


def build_product_route_tool_entries() -> list[dict[str, Any]]:
    """Return deterministic ``tools/list`` entries for ``PRODUCT_ROUTE_TOOL_CATALOG``."""

    filesystem_by_name = _filesystem_tool_entries()
    entries: list[dict[str, Any]] = []
    for name in PRODUCT_ROUTE_TOOL_CATALOG:
        if name in FILESYSTEM_PRODUCT_TOOLS:
            entries.append(dict(filesystem_by_name[name]))
        elif name in GIT_PRODUCT_TOOLS:
            entries.append(_git_tool_entry(name))
        elif name in PACKAGE_PRODUCT_TOOLS:
            entries.append(_package_tool_entry(name))
        elif name in GITHUB_PRODUCT_TOOLS:
            entries.append(_github_tool_entry(name))
        else:
            raise KeyError(f"missing schema mapping for catalog tool {name!r}")
    return entries


def product_route_tool_catalog_hash() -> str:
    """Return a stable hash over the product route tool catalog schemas."""

    payload = build_product_route_tool_entries()
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    ).hexdigest()


__all__ = [
    "build_product_route_tool_entries",
    "product_route_tool_catalog_hash",
]
