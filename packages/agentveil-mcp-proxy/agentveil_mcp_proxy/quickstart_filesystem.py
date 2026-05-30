"""Tiny stdio MCP server for `agentveil-mcp-proxy --quickstart-filesystem`.

This server is intentionally small and sandbox-rooted. It exists so a fresh
install can exercise MCP initialize, tools/list, and simple filesystem tool
calls without installing an external Node-based MCP server first.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Mapping


JSONRPC_VERSION = "2.0"


def _response(request_id: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": dict(result)}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "list_workspace",
            "description": "List files under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        {
            "name": "write_file",
            "description": "Write a UTF-8 text file under the quickstart sandbox root.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
    ]


def _safe_child(root: Path, requested: str) -> Path:
    target = (root / requested).resolve()
    if target == root or root in target.parents:
        return target
    raise ValueError("path escapes quickstart sandbox")


def _handle_tools_call(root: Path, request_id: Any, params: Mapping[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, Mapping):
        return _error(request_id, -32602, "arguments must be an object")
    if name == "list_workspace":
        files = [
            item.relative_to(root).as_posix()
            for item in sorted(root.rglob("*"))
            if item.is_file()
        ]
        return _response(request_id, {"content": [{"type": "text", "text": "\n".join(files)}]})
    if name == "write_file":
        path = arguments.get("path")
        content = arguments.get("content")
        if not isinstance(path, str) or not path:
            return _error(request_id, -32602, "path must be a non-empty string")
        if not isinstance(content, str):
            return _error(request_id, -32602, "content must be a string")
        try:
            target = _safe_child(root, path)
        except ValueError as exc:
            return _error(request_id, -32602, str(exc))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return _response(
            request_id,
            {"content": [{"type": "text", "text": f"wrote {target.relative_to(root).as_posix()}"}]},
        )
    return _error(request_id, -32601, "unknown tool")


def handle_message(root: Path, message: Mapping[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        return _response(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentveil-quickstart-filesystem", "version": "0"},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _response(request_id, {"tools": _tools()})
    if method == "tools/call":
        params = message.get("params", {})
        if not isinstance(params, Mapping):
            return _error(request_id, -32602, "params must be an object")
        return _handle_tools_call(root, request_id, params)
    return _error(request_id, -32601, "method not found")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["-h"], ["--help"]):
        print("usage: python -m agentveil_mcp_proxy.quickstart_filesystem SANDBOX")
        return 0
    if len(argv) != 1:
        print("usage: python -m agentveil_mcp_proxy.quickstart_filesystem SANDBOX", file=sys.stderr)
        return 2
    root = Path(argv[0]).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
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
                response = handle_message(root, message)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
