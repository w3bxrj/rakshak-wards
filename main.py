#!/usr/bin/env python3
"""CLI entrypoint for Team Rakshak Secret Wards pipeline."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rakshak.pipeline import run_pipeline
from rakshak.security import SecretMissingError

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description="Team Rakshak Secret Wards privacy firewall")
    ap.add_argument("--input", required=True, help="Input directory")
    ap.add_argument("--output", required=True, help="Output directory")
    args = ap.parse_args()

    # Windows cmd.exe does not strip POSIX single quotes produced by shlex.quote()
    raw_in = args.input[1:-1] if len(args.input) >= 2 and args.input[0] == "'" and args.input[-1] == "'" else args.input
    raw_out = args.output[1:-1] if len(args.output) >= 2 and args.output[0] == "'" and args.output[-1] == "'" else args.output

    try:
        report = run_pipeline(
            inp=Path(raw_in),
            out=Path(raw_out),
            policy_path=HERE / "config" / "policy.yaml",
        )
    except SecretMissingError:
        sys.stderr.write("ERROR: RAKSHA_SECRET is required and must be non-empty.\n")
        return 2

    c = report["counts"]
    print(
        f"files {c['files_total']} sanitized {c['files_sanitized']} "
        f"quarantined {c['files_quarantined']} records {c['records_processed']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
