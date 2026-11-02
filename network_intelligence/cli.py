"""Unified command-line interface for the suite."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from . import health, monitor, scanner


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nis", description="Authorized defensive network utilities")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("scan", help="discover hosts on an authorized private LAN")
    commands.add_parser("monitor", help="monitor outbound IPv4 metadata")
    commands.add_parser("health-check", help="check a local endpoint without credentials")
    args, remainder = parser.parse_known_args(argv)
    if args.command == "scan":
        return scanner.main(remainder)
    if args.command == "monitor":
        return monitor.main(remainder)
    return health.main(remainder)


if __name__ == "__main__":
    raise SystemExit(main())
