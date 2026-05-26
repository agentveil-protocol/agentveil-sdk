"""Console entry point for `agentveil-paperclip`.

Subcommands today:

* ``doctor`` — read-only local readiness report for the AgentVeil MCP
  proxy + Paperclip-managed Claude/Codex integration.
* ``init --dry-run`` — read-only preview of the setup steps that
  would need to happen for each integration surface. Running ``init``
  without ``--dry-run`` is refused; no mutating init flow is
  implemented today.

The CLI is intentionally minimal. It does not write configuration, mutate
user files, generate identities, or call the AgentVeil backend.
"""

from __future__ import annotations

import argparse
import sys
from typing import TextIO

from .doctor import collect_doctor_report, render_doctor_report
from .init_plan import collect_init_plan, render_init_plan


_SHOW_PATHS_HELP = (
    "Include local filesystem paths in the output. Off by default for "
    "privacy. May reveal absolute paths from your home directory or system."
)


def cmd_doctor(args: argparse.Namespace, *, out: TextIO) -> int:
    """Render the read-only doctor report to `out`."""

    report = collect_doctor_report()
    out.write(render_doctor_report(report, show_paths=args.show_paths))
    return 0


def cmd_init(args: argparse.Namespace, *, out: TextIO) -> int:
    """Render the dry-run init plan. Refuses to run without ``--dry-run``."""

    if not args.dry_run:
        sys.stderr.write(
            "agentveil paperclip init currently supports --dry-run only.\n"
            "Re-run with `--dry-run` to preview the proposed setup plan.\n"
            "No mutating init implementation is available in this release.\n"
        )
        return 2

    plan = collect_init_plan(show_paths=args.show_paths)
    out.write(render_init_plan(plan, show_paths=args.show_paths))
    return 0


def _add_doctor_subcommand(subparsers: argparse._SubParsersAction) -> None:
    doctor = subparsers.add_parser(
        "doctor",
        help=(
            "Report local readiness for the AgentVeil MCP proxy and "
            "Paperclip integration. Read-only."
        ),
    )
    doctor.add_argument(
        "--show-paths",
        action="store_true",
        help=_SHOW_PATHS_HELP,
    )
    doctor.set_defaults(handler=cmd_doctor)


def _add_init_subcommand(subparsers: argparse._SubParsersAction) -> None:
    init = subparsers.add_parser(
        "init",
        help=(
            "Preview the AgentVeil Paperclip integration setup plan. "
            "Only the --dry-run preview is implemented; nothing is written."
        ),
    )
    init.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Print the proposed setup plan without writing any files or "
            "creating any proxy state. Required in this release."
        ),
    )
    init.add_argument(
        "--show-paths",
        action="store_true",
        help=_SHOW_PATHS_HELP,
    )
    init.set_defaults(handler=cmd_init)


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
    _add_init_subcommand(subparsers)

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
    _add_init_subcommand(paperclip_subparsers)

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
