#!/usr/bin/env python3
"""Workflow Guard T4 smoke entrypoint (metadata-only, no real shell by default)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from agentveil_mcp_proxy.workflow_guard_cli import smoke_workflow_guard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Workflow Guard smoke scenarios")
    parser.add_argument("--home", type=Path, default=None)
    parser.add_argument("--event-log", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    return smoke_workflow_guard(
        home=args.home,
        event_log=args.event_log,
        output_json=args.json,
    )


if __name__ == "__main__":
    raise SystemExit(main())
