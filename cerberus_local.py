#!/usr/bin/env python3
"""CERBERUS-LOCAL CLI (M1)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cerberus.cli.commands import (
    cmd_mode,
    cmd_rollback,
    cmd_start,
    cmd_status,
    cmd_stop,
    cmd_version,
    resolve_config,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cerberus_local.py", description="CERBERUS-LOCAL EDR")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("start", "status", "stop"):
        s = sub.add_parser(name)
        s.add_argument("--config", type=Path, default=None, help="Ruta a YAML de config")
        if name == "start":
            s.add_argument("--dry-run", action="store_true", help="Forzar modo dry_run")
    m = sub.add_parser("mode")
    m.add_argument("value")
    m.add_argument("--config", type=Path, default=None)
    rb = sub.add_parser("rollback")
    rb.add_argument("action_id")
    rb.add_argument("--config", type=Path, default=None)
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
    if args.command == "mode":
        return cmd_mode(cfg, args.value)
    if args.command == "rollback":
        return cmd_rollback(cfg, args.action_id)
    return 2


if __name__ == "__main__":
    sys.exit(main())
