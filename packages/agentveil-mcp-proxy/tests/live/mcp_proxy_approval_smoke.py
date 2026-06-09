#!/usr/bin/env python3
"""Compatibility smoke for the current Approval Center product path.

The old approval smoke constructed ApprovalServer and McpPassthrough directly.
The product path now runs through one-shot ``run`` with a stable Approval Center,
so this legacy entry point delegates to the P10A.9 live smoke.
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, TESTS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from mcp_proxy_persistent_approval_center_smoke import main as persistent_approval_main


if __name__ == "__main__":
    raise SystemExit(persistent_approval_main())
