"""Console entry point for `agentveil-paperclip`.

Subcommands today:

* ``doctor`` — read-only local readiness report for the AgentVeil MCP
  proxy + Paperclip-managed Claude/Codex integration.

The CLI is intentionally minimal. It does not write configuration, mutate
user files, generate identities, or call the AgentVeil backend.
"""

from __future__ import annotations

import argparse
import sys
from typing import TextIO

from .doctor import collect_doctor_report, render_doctor_report


def cmd_doctor(_args: argparse.Namespace, *, out: TextIO) -> int:
    """Render the read-only doctor report to `out`."""

    report = collect_doctor_report()
    out.write(render_doctor_report(report))
    return 0


def _add_doctor_subcommand(subparsers: argparse._SubParsersAction) -> None:
    doctor = subparsers.add_parser(
        "doctor",
        help=(
            "Report local readiness for the AgentVeil MCP proxy and "
            "Paperclip integration. Read-only."
        ),
    )
    doctor.set_defaults(handler=cmd_doctor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentveil-paperclip",
        description=(
            "Paperclip-side helpers for AgentVeil. Read-only diagnostics for "
            "the local AgentVeil MCP proxy plus Paperclip-managed Claude or "
            "Codex runtime integration."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True
    _add_doctor_subcommand(subparsers)

    return parser


def build_agentveil_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentveil",
        description="AgentVeil command helpers.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    paperclip = subparsers.add_parser(
        "paperclip",
        help="Paperclip integration helpers.",
    )
    paperclip_subparsers = paperclip.add_subparsers(dest="paperclip_command")
    paperclip_subparsers.required = True
    _add_doctor_subcommand(paperclip_subparsers)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args, out=sys.stdout)


def agentveil_main(argv: list[str] | None = None) -> int:
    parser = build_agentveil_parser()
    args = parser.parse_args(argv)
    return args.handler(args, out=sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
