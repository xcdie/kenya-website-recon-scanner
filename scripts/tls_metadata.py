#!/usr/bin/env python3
"""Collect TLS certificate metadata for exactly one pre-authorised target."""

from __future__ import annotations

import argparse
import json

from scope import add_scope_arguments, approved_targets, guarded_main

from kenya_recon.collectors import tls_certificate_metadata, utc_now
from kenya_recon.safety import public_addresses


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    add_scope_arguments(parser, single_target=True)
    args = parser.parse_args()
    target = approved_targets(args, target_id=args.target_id)[0]
    addresses = public_addresses(target["domain"])
    result = {
        "domain": target["domain"],
        "collected_at_utc": utc_now(),
        "method": "one certificate-validated TLS handshake; no HTTP request",
        "result": tls_certificate_metadata(target["domain"], addresses=addresses, timeout=args.timeout_seconds, stop_file=args.stop_file),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    guarded_main(main)
