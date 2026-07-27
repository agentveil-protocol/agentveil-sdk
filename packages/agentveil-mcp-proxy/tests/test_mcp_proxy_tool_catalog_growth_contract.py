"""Architecture guard for deliberate product-route MCP catalog growth."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from agentveil_mcp_proxy.product_route import (
    PRODUCT_ROUTE_TOOL_CATALOG,
    PRODUCT_ROUTE_TOOL_PACK,
)


CONTRACT_PATH = Path(__file__).with_name("fixtures") / "product_route_tool_catalog_contract.json"
CONTRACT_SCHEMA_VERSION = "avp.product_route.tool_catalog.v1"


def _load_contract() -> dict[str, object]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _tool_names_hash(names: list[str]) -> str:
    payload = json.dumps(names, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_product_route_catalog_growth_requires_explicit_contract_update() -> None:
    contract = _load_contract()
    expected_tools = contract["tools"]
    assert isinstance(expected_tools, list)

    expected_names = [row["name"] for row in expected_tools]
    expected_packs = {row["name"]: row["pack"] for row in expected_tools}
    actual_names = list(PRODUCT_ROUTE_TOOL_CATALOG)

    assert contract["schema_version"] == CONTRACT_SCHEMA_VERSION
    assert contract["catalog_count"] == len(expected_names)
    assert actual_names == expected_names
    assert {
        name: PRODUCT_ROUTE_TOOL_PACK[name]
        for name in actual_names
    } == expected_packs
    assert dict(Counter(expected_packs.values())) == contract["pack_counts"]
    assert _tool_names_hash(actual_names) == contract["tool_names_sha256"]
