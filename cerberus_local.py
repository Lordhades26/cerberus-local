#!/usr/bin/env python3
"""CERBERUS-LOCAL CLI (M1)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cerberus.cli.commands import (
    cmd_start,
    cmd_status,
    cmd_stop,
    cmd_version,
    resolve_config,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cerberus_local.py", description="CERBERUS-LOCAL EDR (M1)")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("start", "status", "stop"):
        s = sub.add_parser(name)
        s.add_argument("--config", type=Path, default=None, help="Ruta a YAML de config")
        if name == "start":
            s.add_argument("--dry-run", action="store_true", help="Forzar modo dry_run")
    sub.add_parser("version")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "version":
        return cmd_version()
    cfg = resolve_config(args.config)
    if args.command == "start":
        return cmd_start(cfg)
    if args.command == "status":
        return cmd_status(cfg)
    if args.command == "stop":
        return cmd_stop(cfg)
    return 2


if __name__ == "__main__":
    sys.exit(main())
