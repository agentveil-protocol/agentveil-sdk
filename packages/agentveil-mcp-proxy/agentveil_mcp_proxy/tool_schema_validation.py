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
from typing import Any, Mapping


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


class ToolSchemaCache:
    """Thread-safe cache of advertised MCP tool ``inputSchema`` objects,
    claim-check: allow "safe" is part of the standard "thread-safe" term.
    keyed by tool name. Populated from downstream ``tools/list`` responses.

    Stores only schema structure (no request arguments / no raw values).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._schemas: dict[str, dict[str, Any]] = {}

    def update_from_response(self, response: Any) -> int:
        """Cache ``inputSchema`` for each tool in a ``tools/list``-shaped
        downstream response. Returns the number of schemas cached.

        Detection is structural: a JSON-RPC result whose ``tools`` is a list
        of objects with a string ``name`` and a dict ``inputSchema``. This is
        the standard MCP ``tools/list`` result shape; other responses are
        ignored.
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
                schema = tool.get("inputSchema")
                if isinstance(name, str) and name and isinstance(schema, Mapping):
                    self._schemas[name] = dict(schema)
                    cached += 1
        return cached

    def get(self, tool_name: str) -> dict[str, Any] | None:
        with self._lock:
            schema = self._schemas.get(tool_name)
            return dict(schema) if schema is not None else None


__all__ = ["ToolSchemaCache", "validate_arguments"]
