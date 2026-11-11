#!/usr/bin/env python3
"""Convert timestamped strongSwan log files to latency JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def parse(path: Path, max_ike_init_retries: int = 1) -> tuple[list[float], int, int, int]:
    starts: list[float] = []
    finishes: list[float] = []
    active = False
    decryption_retries = 0
    decryption_failures = 0
    udp_failures = 0
    current_retries = 0
    decryption_failure = False

    # Iterate over the file instead of loading it all at once. Some complete
    # experiment logs contain over 10,000 handshakes and exceed 60 MB.
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            fields = line.split()
            if not fields:
                continue
            try:
                timestamp = float(fields[0])
            except ValueError as error:
                raise ValueError(
                    f"{path}:{number}: missing millisecond timestamp"
                ) from error

            if "retrying IKE_SA_INIT" in line:
                current_retries += 1
                decryption_retries += 1
            elif "applying key exchange public value failed" in line:
                decryption_failure = True
            elif "CREATED => CONNECTING" in line and not current_retries:
                if active:
                    starts[-1] = timestamp
                    if decryption_failure or current_retries >= max_ike_init_retries > 0:
                        decryption_failures += 1
                    else:
                        udp_failures += 1
                    current_retries = 0
                    decryption_failure = False
                else:
                    starts.append(timestamp)
                active = True
            elif "CONNECTING => ESTABLISHED" in line:
                if not active:
                    raise ValueError(f"{path}:{number}: establishment without a start")
                finishes.append(timestamp)
                active = False
                current_retries = 0
                decryption_failure = False
            elif (
                "=> DESTROYING" in line
                and "CREATED => DESTROYING" not in line
                and active
            ):
                # An unrelated, unnamed IKE_SA may be created and immediately
                # destroyed while the measured IKE_SA is still connecting.
                starts.pop()
                if decryption_failure or current_retries >= max_ike_init_retries > 0:
                    decryption_failures += 1
                else:
                    udp_failures += 1
                active = False
                current_retries = 0
                decryption_failure = False

    if len(starts) != len(finishes):
        raise ValueError(f"unpaired events: {len(starts)} starts, {len(finishes)} finishes")
    values = sorted((end - start) * 1000 for start, end in zip(starts, finishes))
    return values, decryption_retries, decryption_failures, udp_failures


def convert(log: Path, output: Path, max_ike_init_retries: int) -> None:
    values, retries, decryption_failures, udp_failures = parse(
        log, max_ike_init_retries
    )
    handshake_failures = decryption_failures + udp_failures
    result = {
        "latencies_ms": values,
        "decryption_retries": retries,
        "decryption_failures": decryption_failures,
        "udp_failures": udp_failures,
        "handshake_failures": handshake_failures,
    }
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{log}:")
    print(f"  successful samples: {len(values)}")
    print(f"  decryption retries: {retries}")
    print(f"  decryption failures: {decryption_failures}")
    print(f"  UDP failures: {udp_failures}")
    print(f"  handshake failures: {handshake_failures}")
    print(f"  PASS: wrote {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input", type=Path, help="a .log file or a directory of .log files"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="output JSON file (file input) or output directory (directory input)",
    )
    parser.add_argument("--max-ike-init-retries", type=int, default=1)
    args = parser.parse_args()
    if args.max_ike_init_retries < 0:
        parser.error("--max-ike-init-retries must be non-negative")
    if args.input.is_dir():
        logs = sorted(args.input.glob("*.log"))
        output_dir = args.output or args.input
        if args.output is not None and not output_dir.is_dir():
            parser.error("--output must be an existing directory for directory input")
        if not logs:
            print(f"ERROR: no .log files found in {args.input}", file=sys.stderr)
            return 1
        failures = 0
        for log in logs:
            try:
                convert(
                    log,
                    output_dir / log.with_suffix(".json").name,
                    args.max_ike_init_retries,
                )
            except (OSError, ValueError) as error:
                print(f"ERROR: {error}", file=sys.stderr)
                failures += 1
        print(f"converted: {len(logs) - failures}, failed: {failures}")
        return 1 if failures else 0

    output = args.output or args.input.with_suffix(".json")
    try:
        convert(args.input, output, args.max_ike_init_retries)
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
