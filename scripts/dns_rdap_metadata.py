#!/usr/bin/env python3
"""Collect DNS and minimal public RDAP metadata for one pre-authorised target."""

from __future__ import annotations

import argparse
import json

from scope import add_scope_arguments, approved_targets, guarded_main

from kenya_recon.collectors import dns_metadata, rdap_metadata, utc_now


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_scope_arguments(parser, single_target=True)
    args = parser.parse_args()
    target = approved_targets(args, target_id=args.target_id)[0]
    result = {
        "domain": target["domain"],
        "collected_at_utc": utc_now(),
        "method": "DNS A/AAAA/MX/NS and one public RDAP lookup",
        "dns": dns_metadata(target["domain"], timeout=args.timeout_seconds, stop_file=args.stop_file),
        "rdap": rdap_metadata(target["domain"], timeout=args.timeout_seconds, stop_file=args.stop_file),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    guarded_main(main)
