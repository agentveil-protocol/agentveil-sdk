# SPDX-FileCopyrightText: 2026 Oleg Boiko
# SPDX-License-Identifier: BUSL-1.1

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

# Compact shared GitHub property fragments (product profile supplies defaults).
# Omit verbose descriptions: tools/list size is dominated by repeating them.
_GH_OWNER: dict[str, Any] = {"type": "string"}
_GH_REPO: dict[str, Any] = {"type": "string"}
_GH_REPO_ROOT: dict[str, Any] = {"type": "string"}
_GH_ISSUE_NUMBER: dict[str, Any] = {"type": "integer"}
_GH_PULL_NUMBER: dict[str, Any] = {"type": "integer"}
_GH_COMMENT_BODY: dict[str, Any] = {"type": "string"}
_GH_BRANCH: dict[str, Any] = {"type": "string"}
_GH_SECRET_NAME: dict[str, Any] = {"type": "string"}
_GH_VISIBILITY: dict[str, Any] = {"type": "string"}
_GH_TAG_NAME: dict[str, Any] = {"type": "string"}
_GH_WORKFLOW_RUN_ID: dict[str, Any] = {"type": "integer"}

# Extra advertised properties beyond owner/repo/repo_root, keyed by tool.
# Keep additionalProperties=true and stay within the legacy shared field set.
_GITHUB_TOOL_EXTRA_PROPERTIES: dict[str, tuple[str, ...]] = {
    "get_issue": ("issue_number",),
    "get_pull_request": ("pull_number",),
    "list_comments": ("issue_number", "pull_number"),
    "create_comment": ("issue_number", "pull_number", "comment_body"),
    "update_issue": ("issue_number",),
    "add_labels": ("issue_number",),
    "remove_labels": ("issue_number",),
    "request_review": ("pull_number",),
    "merge_pull_request": ("pull_number",),
    "close_issue": ("issue_number",),
    "delete_branch": ("branch",),
    "create_release": ("tag_name",),
    "update_repository_settings": ("visibility",),
    "manage_secret": ("secret_name",),
    "rerun_workflow": ("workflow_run_id",),
    "cancel_workflow": ("workflow_run_id",),
    "dispatch_workflow": ("branch",),
    "get_secret": ("secret_name",),
    "get_env_secret": ("secret_name",),
}

_GITHUB_PROPERTY_DEFS: dict[str, dict[str, Any]] = {
    "owner": _GH_OWNER,
    "repo": _GH_REPO,
    "repo_root": _GH_REPO_ROOT,
    "issue_number": _GH_ISSUE_NUMBER,
    "pull_number": _GH_PULL_NUMBER,
    "comment_body": _GH_COMMENT_BODY,
    "branch": _GH_BRANCH,
    "secret_name": _GH_SECRET_NAME,
    "visibility": _GH_VISIBILITY,
    "tag_name": _GH_TAG_NAME,
    "workflow_run_id": _GH_WORKFLOW_RUN_ID,
}


def _github_object_schema(*property_names: str) -> dict[str, Any]:
    properties = {
        name: dict(_GITHUB_PROPERTY_DEFS[name])
        for name in property_names
    }
    return {
        "type": "object",
        "properties": properties,
        "required": [],
        "additionalProperties": True,
    }


def _github_tool_schema(name: str) -> dict[str, Any]:
    extras = _GITHUB_TOOL_EXTRA_PROPERTIES.get(name, ())
    return _github_object_schema("owner", "repo", "repo_root", *extras)


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
        "inputSchema": _github_tool_schema(name),
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


def measure_product_route_tools_list_size() -> dict[str, int]:
    """Return compact byte sizes for product-route ``tools/list`` advertising."""

    entries = build_product_route_tool_entries()
    tools_list = {"jsonrpc": "2.0", "id": 1, "result": {"tools": entries}}
    tools_list_bytes = len(json.dumps(tools_list, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    schema_bytes = sum(
        len(json.dumps(entry["inputSchema"], separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        for entry in entries
    )
    github_schema_bytes = sum(
        len(json.dumps(entry["inputSchema"], separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        for entry in entries
        if entry["name"] in GITHUB_PRODUCT_TOOLS
    )
    return {
        "tool_count": len(entries),
        "tools_list_bytes": tools_list_bytes,
        "schema_bytes": schema_bytes,
        "github_schema_bytes": github_schema_bytes,
    }


__all__ = [
    "build_product_route_tool_entries",
    "measure_product_route_tools_list_size",
    "product_route_tool_catalog_hash",
]
