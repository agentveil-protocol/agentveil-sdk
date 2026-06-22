"""Composite stdio MCP downstream for the product route catalog."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_DOWNSTREAM_NAME,
    PRODUCT_ROUTE_TOOL_CATALOG,
    product_route_tool_pack,
)
from agentveil_mcp_proxy.product_route_local_fixtures import (
    ProductRouteProfile,
    resolve_product_route_profile,
)
from agentveil_mcp_proxy.product_route_pack_handlers import (
    GitHubCiPackHandler,
    GitRepoPackHandler,
    PackageInstallPackHandler,
)
from agentveil_mcp_proxy.product_route_tool_schemas import build_product_route_tool_entries
from agentveil_mcp_proxy.quickstart_filesystem import _handle_tools_call

JSONRPC_VERSION = "2.0"
SERVER_NAME = "agentveil-product-route-downstream"
SERVER_VERSION = "1.0.0"


def _response(request_id: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": dict(result)}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


@dataclass
class ProductRouteRuntime:
    profile: ProductRouteProfile
    git: GitRepoPackHandler
    package: PackageInstallPackHandler
    github: GitHubCiPackHandler

    @classmethod
    def from_profile_root(cls, profile_root: Path) -> ProductRouteRuntime:
        profile = resolve_product_route_profile(profile_root)
        return cls(
            profile=profile,
            git=GitRepoPackHandler(
                repo_root=profile.git_repo,
                outcome_log=profile.git_outcome_log,
            ),
            package=PackageInstallPackHandler(
                project_root=profile.package_project,
                target_venv=profile.package_venv,
                local_dist=profile.package_dist,
                outcome_log=profile.package_outcome_log,
            ),
            github=GitHubCiPackHandler(
                state_dir=profile.github_state_dir,
                content_root=profile.github_content_root,
                outcome_log=profile.github_outcome_log,
            ),
        )


def handle_message(runtime: ProductRouteRuntime, message: Mapping[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        return _response(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        tools = build_product_route_tool_entries()
        names = [entry["name"] for entry in tools]
        if tuple(names) != PRODUCT_ROUTE_TOOL_CATALOG:
            raise RuntimeError("product route tools/list drifted from PRODUCT_ROUTE_TOOL_CATALOG")
        return _response(request_id, {"tools": tools})
    if method == "tools/call":
        params = message.get("params", {})
        if not isinstance(params, Mapping):
            return _error(request_id, -32602, "params must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name:
            return _error(request_id, -32602, "tool name required")
        if not isinstance(arguments, Mapping):
            return _error(request_id, -32602, "arguments must be an object")
        if name not in PRODUCT_ROUTE_TOOL_CATALOG:
            return _error(request_id, -32601, f"unknown catalog tool: {name}")
        pack = product_route_tool_pack(name)
        if pack is None:
            return _error(request_id, -32601, f"unknown catalog tool owner: {name}")
        try:
            if pack == "filesystem":
                return _handle_tools_call(runtime.profile.filesystem_sandbox, request_id, params)
            if pack == "git":
                return _response(request_id, runtime.git.handle(name, arguments))
            if pack == "package":
                return _response(request_id, runtime.package.handle(name, arguments))
            if pack == "github":
                return _response(request_id, runtime.github.handle(name, arguments))
            return _error(request_id, -32601, f"unsupported pack: {pack}")
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
    return _error(request_id, -32601, "method not found")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["-h"], ["--help"]):
        print(f"usage: python -m agentveil_mcp_proxy.product_route_downstream PROFILE_ROOT")
        return 0
    if len(argv) != 1:
        print(
            f"usage: python -m agentveil_mcp_proxy.product_route_downstream PROFILE_ROOT",
            file=sys.stderr,
        )
        return 2
    profile_root = Path(argv[0]).expanduser().resolve()
    if not profile_root.is_dir():
        print("profile root must exist", file=sys.stderr)
        return 2
    runtime = ProductRouteRuntime.from_profile_root(profile_root)
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        try:
            message = json.loads(raw_line)
        except json.JSONDecodeError:
            response = _error(None, -32700, "parse error")
        else:
            if not isinstance(message, Mapping):
                response = _error(None, -32600, "request must be an object")
            else:
                try:
                    response = handle_message(runtime, message)
                except RuntimeError as exc:
                    response = _error(message.get("id"), -32603, str(exc))
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
