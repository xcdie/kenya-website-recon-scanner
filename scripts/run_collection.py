#!/usr/bin/env python3
"""Run low-impact, rate-limited metadata collection for an approved CSV scope."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from scope import ROOT, add_scope_arguments, approved_targets, guarded_main

from kenya_recon.collectors import collect_site, utc_now, write_report
from kenya_recon.safety import SafetyError, stop_requested


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_scope_arguments(parser)
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "local" / "collection.json")
    parser.add_argument("--delay-seconds", type=float, default=5.0, help="wait between targets; minimum 5 seconds")
    parser.add_argument("--max-targets", type=int, default=12, help="maximum targets per run; 1–25")
    args = parser.parse_args()
    if args.delay_seconds < 5:
        raise SafetyError("delay-seconds must be at least 5")
    if not 1 <= args.max_targets <= 25:
        raise SafetyError("max-targets must be between 1 and 25")
    targets = approved_targets(args)
    if len(targets) > args.max_targets:
        raise SafetyError(f"CSV has {len(targets)} approved targets, exceeding max-targets")

    report: dict[str, object] = {
        "report_type": "authorised_low_impact_metadata_collection",
        "started_at_utc": utc_now(),
        "scope": {
            "target_count": len(targets),
            "minimum_delay_seconds": args.delay_seconds,
            "authorisation_acknowledgement": True,
            "controls": ["CSV approval", "allowlist", "STOP file", "public-address check"],
        },
        "results": [],
        "limitations": "Observations are not a risk score, vulnerability finding, or verdict about any operator.",
    }
    results: list[dict[str, object]] = report["results"]  # type: ignore[assignment]
    for index, target in enumerate(targets):
        if stop_requested(args.stop_file):
            report["stopped_at_utc"] = utc_now()
            report["stop_reason"] = "STOP file detected before next target"
            break
        print(f"Collecting approved target {index + 1}/{len(targets)}: {target['domain']}")
        try:
            results.append(collect_site(target["domain"], timeout=args.timeout_seconds, stop_file=args.stop_file))
        except SafetyError as error:
            results.append({"domain": target["domain"], "error": str(error), "collected_at_utc": utc_now()})
            report["stopped_at_utc"] = utc_now()
            report["stop_reason"] = "safety control triggered"
            break
        if index < len(targets) - 1:
            time.sleep(args.delay_seconds)
    report["finished_at_utc"] = utc_now()
    write_report(report, args.output)
    print(f"Wrote {args.output} and {args.output.with_suffix('.summary.csv')}")


if __name__ == "__main__":
    guarded_main(main)
