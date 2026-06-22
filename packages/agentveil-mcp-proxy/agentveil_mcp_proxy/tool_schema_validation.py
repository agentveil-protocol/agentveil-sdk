"""Pre-approval validation of MCP ``tools/call`` arguments against the
tool's advertised ``inputSchema``.

This is a deliberately small JSON-Schema *subset* sufficient for MCP tool
input schemas. It is NOT a general JSON Schema engine and adds no
dependency. The validator returns deterministic, privacy-safe detail
strings that name only argument keys and expected types — never argument
*values* — so results are safe to log in bounded evidence.

Supported subset:
  - ``type: object`` at the top level
  - ``properties``
  - ``required``
  - ``additionalProperties: false`` (unknown-argument rejection)
  - primitive ``type`` checks for string / number / integer / boolean /
    object / array on declared properties

Anything outside this subset (unknown keywords, nested schemas, unions,
formats) is intentionally not enforced. When a schema cannot be
meaningfully validated, the validator returns no errors (fail-open at the
schema level); the *caller* decides conservative behavior when NO schema
claim-check: allow "all" refers to advertised schema absence in this documented caller boundary.
is advertised at all.
"""
from __future__ import annotations

import threading
from typing import Any, Iterable, Mapping

from agentveil_mcp_proxy.classification import sha256_jcs


_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    # bool is a subclass of int in Python; exclude it from number/integer.
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
}


def validate_arguments(schema: Mapping[str, Any], arguments: Any) -> list[str]:
    """Validate ``arguments`` against the subset of ``schema``.

    Returns a deterministic, sorted-within-group list of human-readable
    detail strings (empty list = valid / not-validatable). Strings contain
    claim-check: allow "never" describes tested redaction of raw argument values.
    only argument names and expected type names — never values.
    """
    if not isinstance(schema, Mapping):
        return []
    # Only object schemas are validated; non-object schemas are out of subset.
    if schema.get("type") not in (None, "object"):
        return []

    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        # Schema describes an object but arguments are not a JSON object.
        return ["arguments must be of type object"]

    properties = schema.get("properties")
    properties = properties if isinstance(properties, Mapping) else {}
    required = schema.get("required")
    required = [r for r in required if isinstance(r, str)] if isinstance(required, list) else []
    additional_properties = schema.get("additionalProperties", True)

    details: list[str] = []

    # 1. Missing required arguments.
    for key in sorted(set(required)):
        if key not in arguments:
            details.append(f"missing required argument: {key}")

    # 2. Unknown arguments (only when additionalProperties is explicitly false).
    if additional_properties is False:
        for key in sorted(arguments.keys()):
            if key not in properties:
                details.append(f"unknown argument: {key}")

    # 3. Primitive type mismatches on declared properties that are present.
    for key in sorted(arguments.keys()):
        if key not in properties:
            continue
        prop = properties[key]
        if not isinstance(prop, Mapping):
            continue
        expected = prop.get("type")
        check = _TYPE_CHECKS.get(expected) if isinstance(expected, str) else None
        if check is not None and not check(arguments[key]):
            details.append(f"argument {key} must be of type {expected}")

    return details


def bounded_tool_schema_fingerprint(schema: Mapping[str, Any] | None) -> str | None:
    """Return a stable hash for one advertised tool ``inputSchema`` shape."""

    if schema is None:
        return None
    normalized = {
        "type": schema.get("type"),
        "required": sorted(
            key for key in schema.get("required", [])
            if isinstance(key, str)
        ) if isinstance(schema.get("required"), list) else [],
        "additionalProperties": schema.get("additionalProperties"),
        "properties": sorted(
            (
                key,
                {
                    "type": prop.get("type")
                    if isinstance(prop, Mapping) and isinstance(prop.get("type"), str)
                    else None
                },
            )
            for key, prop in sorted(
                (schema.get("properties") or {}).items()
                if isinstance(schema.get("properties"), Mapping)
                else []
            )
            if isinstance(key, str)
        ),
    }
    return sha256_jcs(normalized)


class ToolSchemaCache:
    """Thread-safe cache of advertised MCP tool ``inputSchema`` objects,
    claim-check: allow "safe" is part of the standard "thread-safe" term.
    keyed by tool name. Populated from downstream ``tools/list`` responses.

    Stores only schema structure (no request arguments / no raw values).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._schemas: dict[str, dict[str, Any]] = {}
        self._advertised_names: set[str] = set()
        self._quarantined_names: set[str] = set()

    def update_from_response(self, response: Any) -> int:
        """Cache ``inputSchema`` for each tool in a ``tools/list``-shaped
        downstream response. Returns the number of schemas cached.

        Detection is structural: a JSON-RPC result whose ``tools`` is a list
        of objects with a string ``name``. Each valid ``name`` is recorded in
        the advertised-name set so callers can distinguish a tool the
        downstream advertised but emitted without an ``inputSchema`` from a
        tool absent from that advertisement. Evidence: callers use this split
        for the unknown-tool regression tests. When the entry also has
        a dict ``inputSchema``, the schema itself is cached and counted.
        Other responses are ignored.
        """
        if not isinstance(response, Mapping):
            return 0
        result = response.get("result")
        if not isinstance(result, Mapping):
            return 0
        tools = result.get("tools")
        if not isinstance(tools, list):
            return 0
        cached = 0
        with self._lock:
            for tool in tools:
                if not isinstance(tool, Mapping):
                    continue
                name = tool.get("name")
                if not (isinstance(name, str) and name):
                    continue
                self._advertised_names.add(name)
                schema = tool.get("inputSchema")
                if isinstance(schema, Mapping):
                    self._schemas[name] = dict(schema)
                    cached += 1
        return cached

    def get(self, tool_name: str) -> dict[str, Any] | None:
        with self._lock:
            schema = self._schemas.get(tool_name)
            return dict(schema) if schema is not None else None

    def fingerprint(self, tool_name: str) -> str | None:
        """Return a bounded hash of the cached ``inputSchema`` for one tool."""

        return bounded_tool_schema_fingerprint(self.get(tool_name))

    def is_advertised(self, tool_name: str) -> bool:
        """Return True iff ``tool_name`` was seen in a prior ``tools/list``
        advertisement. Used by the proxy to deny ``tools/call`` for absent
        tool names before approval is requested.
        """
        with self._lock:
            return tool_name in self._advertised_names

    def observed_tool_names(self) -> frozenset[str]:
        """Return the sorted downstream-advertised tool names currently cached."""

        with self._lock:
            return frozenset(self._advertised_names)

    def is_quarantined(self, tool_name: str) -> bool:
        """Return True when a downstream-advertised tool is outside declared surface."""

        with self._lock:
            return tool_name in self._quarantined_names

    def set_quarantined(self, tool_names: Iterable[str]) -> tuple[str, ...]:
        """Replace the quarantined downstream tool set and return the sorted names."""

        with self._lock:
            self._quarantined_names = {name for name in tool_names if isinstance(name, str) and name}
            return tuple(sorted(self._quarantined_names))

    def clear_quarantine(self) -> None:
        """Clear quarantined downstream tools when action-gate checks are inactive."""

        with self._lock:
            self._quarantined_names.clear()


__all__ = [
    "ToolSchemaCache",
    "bounded_tool_schema_fingerprint",
    "validate_arguments",
]
