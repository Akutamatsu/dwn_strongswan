#!/usr/bin/env python3
"""Check Table 2 overhead totals and derive Table 1 packet-size margins."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "reference_results" / "packet_sizes.csv"
BREAKDOWN = ROOT / "reference_results" / "ike_overhead_breakdown.csv"
IPV6_UDP_HEADERS = 48
INITIATOR_PROTOCOL_OVERHEAD = 208
RESPONDER_PROTOCOL_OVERHEAD = 241


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-paper-values", action="store_true")
    args = parser.parse_args()
    failures: list[str] = []

    with BREAKDOWN.open(newline="", encoding="utf-8") as stream:
        totals: dict[str, int] = {}
        for row in csv.DictReader(stream):
            totals[row["direction"]] = totals.get(row["direction"], 0) + int(row["size_bytes"])
    expected_totals = {
        "initiator_to_responder": INITIATOR_PROTOCOL_OVERHEAD,
        "responder_to_initiator": RESPONDER_PROTOCOL_OVERHEAD,
    }
    if totals != expected_totals:
        failures.append(f"Table 2 overhead totals: expected {expected_totals}, got {totals}")
    print(
        "Table 2 fixed overhead: "
        f"I->R={totals.get('initiator_to_responder')} bytes, "
        f"R->I={totals.get('responder_to_initiator')} bytes"
    )
    print()

    print("scheme                    I->R  spare@1280  spare@1500  R->I  spare@1280  spare@1500")
    print("------------------------  ----  ----------  ----------  ----  ----------  ----------")
    with DATA.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            pk = int(row["public_key_bytes"])
            ct = int(row["ciphertext_bytes"])
            initiator = pk + INITIATOR_PROTOCOL_OVERHEAD
            responder = ct + RESPONDER_PROTOCOL_OVERHEAD
            expected_i = int(row["initiator_sa_init_bytes"])
            expected_r = int(row["responder_sa_init_bytes"])
            if args.check_paper_values and (initiator, responder) != (expected_i, expected_r):
                failures.append(
                    f"{row['scheme']}: calculated {(initiator, responder)}, "
                    f"recorded {(expected_i, expected_r)}"
                )
            print(
                f"{row['scheme']:<24}  {initiator:>4}  "
                f"{1280-IPV6_UDP_HEADERS-initiator:>10}  {1500-IPV6_UDP_HEADERS-initiator:>10}  "
                f"{responder:>4}  {1280-IPV6_UDP_HEADERS-responder:>10}  "
                f"{1500-IPV6_UDP_HEADERS-responder:>10}"
            )

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    if args.check_paper_values:
        print("PASS: reference values match the paper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
