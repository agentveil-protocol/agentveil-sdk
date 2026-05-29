"""Shared schema-aware fake MCP downstream for proxy tests.

A schema-aware MCP server answers ``tools/list`` with advertised
``inputSchema`` objects, so the proxy's pre-approval argument validation can
resolve a schema before policy / approval / downstream execution. Tests that
drive a ``tools/call`` through the proxy should use this downstream or seed the
schema cache unless they specifically exercise the ``tool_schema_unavailable``
path.

This module centralizes that protocol so individual tests stop hand-rolling
incomplete fake servers (which silently omit ``tools/list`` and therefore trip
the schema-unavailable boundary).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

# A permissive object schema: no required keys, additionalProperties defaults
# True, so any arguments validate. Use when a test needs the call to PROCEED
# past validation and exercise a different layer (policy / runtime gate / etc.).
PERMISSIVE_OBJECT_SCHEMA: dict[str, Any] = {"type": "object"}


def tool_entry(name: str, schema: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One ``tools/list`` entry advertising ``name`` with an inputSchema."""
    return {
        "name": name,
        "description": f"{name} (test fake)",
        "inputSchema": dict(schema) if schema is not None else dict(PERMISSIVE_OBJECT_SCHEMA),
    }


def downstream_script(
    *,
    tools: Sequence[Mapping[str, Any]],
    call_result_text: str = "forwarded",
    call_result: Mapping[str, Any] | None = None,
    advertise_schema: bool = True,
) -> str:
    """Return Python source for a stdio MCP downstream.

    The script answers ``initialize`` and, when ``advertise_schema`` is true,
    ``tools/list`` with ``tools``. Other id'd requests return ``call_result`` if
    given, else ``{"content": [{"type": "text", "text": call_result_text}]}``.
    When ``advertise_schema`` is false the server returns the call-result shape
    for ``tools/list`` too, modeling a downstream that trips the proxy's
    schema-unavailable path.

    If ``$DOWNSTREAM_LOG`` is set, each received method is appended to it.
    """
    if call_result is None:
        call_result = {"content": [{"type": "text", "text": call_result_text}]}
    header = (
        "import json\n"
        "import os\n"
        "import sys\n"
        f"TOOLS = json.loads({json.dumps(list(tools))!r})\n"
        f"CALL_RESULT = json.loads({json.dumps(dict(call_result))!r})\n"
        f"ADVERTISE_SCHEMA = {bool(advertise_schema)!r}\n"
    )
    body = r'''
log_path = os.environ.get("DOWNSTREAM_LOG")
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    if log_path:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(method + "\n")
    if "id" not in msg:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-downstream", "version": "1.0.0"},
        }
    elif method == "tools/list" and ADVERTISE_SCHEMA:
        result = {"tools": TOOLS}
    else:
        result = CALL_RESULT
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
'''
    return header + body


def write_downstream(
    tmp_path: Path,
    *,
    filename: str = "fake_downstream.py",
    tools: Sequence[Mapping[str, Any]] | None = None,
    call_result_text: str = "forwarded",
    call_result: Mapping[str, Any] | None = None,
    advertise_schema: bool = True,
) -> Path:
    """Write a fake downstream script to ``tmp_path`` and return its path."""
    if tools is None:
        tools = [tool_entry("create_issue")]
    script = tmp_path / filename
    script.write_text(
        downstream_script(
            tools=tools,
            call_result_text=call_result_text,
            call_result=call_result,
            advertise_schema=advertise_schema,
        ),
        encoding="utf-8",
    )
    return script


def seed_tool_schemas(passthrough: Any, tools: Sequence[Mapping[str, Any]]) -> None:
    """Seed a passthrough's schema cache as if ``tools/list`` had been seen.

    For in-memory passthrough tests (no real subprocess) whose subject is NOT
    schema discovery: this models the steady state where the tool's schema is
    already known, so the internal ``tools/list`` probe is a cache hit and does
    not interfere with what the test actually exercises.
    """
    passthrough._tool_schemas.update_from_response(
        {"jsonrpc": "2.0", "id": "seed", "result": {"tools": list(tools)}}
    )


__all__ = [
    "PERMISSIVE_OBJECT_SCHEMA",
    "downstream_script",
    "seed_tool_schemas",
    "tool_entry",
    "write_downstream",
]
