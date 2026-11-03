"""Shared fail-closed command-line scope handling for the collector scripts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from kenya_recon.collectors import load_targets  # noqa: E402
from kenya_recon.safety import SafetyError, load_allowlist, require_authorised_target, stop_requested  # noqa: E402

ACKNOWLEDGEMENT = "YES"


def add_scope_arguments(parser: argparse.ArgumentParser, *, single_target: bool = False) -> None:
    parser.add_argument("--input", type=Path, default=ROOT / "data" / "targets_to_scan.csv", help="CSV containing explicit target authorisation")
    parser.add_argument("--allowlist", type=Path, default=ROOT / "config" / "allowlist.txt", help="separate approved-domain allowlist")
    parser.add_argument("--stop-file", type=Path, default=ROOT / "config" / "STOP", help="existing file immediately halts collection")
    parser.add_argument("--timeout-seconds", type=float, default=10.0, help="per network action timeout (1–20 seconds)")
    parser.add_argument("--i-own-or-have-written-permission", metavar="YES", required=True, help="must be exactly YES")
    if single_target:
        parser.add_argument("--target-id", required=True, help="one explicitly authorised target_id from the CSV")


def approved_targets(args: argparse.Namespace, *, target_id: str | None = None) -> list[dict[str, str]]:
    if args.i_own_or_have_written_permission != ACKNOWLEDGEMENT:
        raise SafetyError("explicit permission acknowledgement was not provided")
    if not 1 <= args.timeout_seconds <= 20:
        raise SafetyError("timeout-seconds must be between 1 and 20")
    if stop_requested(args.stop_file):
        raise SafetyError(f"STOP file exists: {args.stop_file}; no network action will be taken")
    allowlist = load_allowlist(args.allowlist)
    rows = load_targets(args.input)
    if target_id is not None:
        rows = [row for row in rows if row.get("target_id", "") == target_id]
        if len(rows) != 1:
            raise SafetyError("target-id must match exactly one non-blank CSV row")
    if not rows:
        raise SafetyError("input CSV has no target rows")
    approved: list[dict[str, str]] = []
    for row in rows:
        domain = require_authorised_target(
            row.get("domain", ""),
            scan_authorized=row.get("scan_authorized", ""),
            allowlist=allowlist,
            stop_file=args.stop_file,
        )
        approved.append({**row, "domain": domain})
    return approved


def guarded_main(main: Callable[[], None]) -> None:
    """Give every executable the same clear, non-stack-trace safety failure."""
    try:
        main()
    except SafetyError as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(2)
