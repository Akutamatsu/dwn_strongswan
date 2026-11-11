#!/usr/bin/env python3
"""Reconstruct the statistics reported in paper Table 4."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference_results"

PAPER_VALUES = {
    ("a", "ecp384"): (31, 171, 76, 50, 51),
    ("a", "emlkem768"): (34, 88, 71, 48, 49),
    ("a", "mlkem1024"): (46, 153, 111, 64, 66),
    ("a", "emlkem1024"): (47, 139, 107, 63, 65),
    ("b", "ecp384"): (577, 2616, 808, 597, 612),
    ("b", "emlkem768"): (581, 796, 717, 592, 596),
    ("b", "mlkem1024"): (586, 2834, 1746, 796, 780),
    ("b", "emlkem1024"): (568, 1614, 816, 631, 666),
    ("c", "ecp384"): (662, 8687, 3672, 674, 867),
    ("c", "emlkem768"): (657, 4677, 3668, 671, 845),
    ("c", "emlkem1024"): (669, 16674, 4684, 683, 1139),
    ("d", "ecp384"): (483, 16500, 7501, 494, 1057),
    ("d", "emlkem768"): (450, 18497, 7493, 490, 870),
    ("d", "mlkem1024"): (453, 22609, 15460, 461, 1213),
    ("d", "emlkem1024"): (451, 15455, 3579, 458, 692),
}


def rounded_stats(values: list[float]) -> tuple[int, int, int, int, int]:
    ordered = sorted(values)
    n = len(ordered)
    return (
        round(ordered[0]),
        round(ordered[-1]),
        round(ordered[int(0.99 * n)]),
        round(ordered[int(0.5 * n)]),
        round(sum(ordered) / n),
    )


def analyze_file(path: Path, link: str, scheme: str, check_paper_values: bool) -> int:
    result = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(result, dict):
        values = result["latencies_ms"]
        counts = (
            str(result["udp_failures"]),
            str(result["decryption_retries"]),
            str(result["decryption_failures"]),
            str(result["handshake_failures"]),
        )
    else:
        values = result
        counts = ("n/a", "n/a", "n/a", "n/a")
    if not values:
        print(f"ERROR: {path}: no latency samples", file=sys.stderr)
        return 1
    stats = rounded_stats(values)
    print("link  scheme       n      min    max    p99    med    avg   UF/DR/DF/HF")
    print("----  -----------  -----  -----  -----  -----  -----  -----  -----------")
    print(
        f"{link:<4}  {scheme:<11}  {len(values):>5}  "
        f"{stats[0]:>5}  {stats[1]:>5}  {stats[2]:>5}  "
        f"{stats[3]:>5}  {stats[4]:>5}  {'/'.join(counts)}"
    )
    if check_paper_values:
        expected = PAPER_VALUES.get((link, scheme))
        if expected is None:
            print(f"ERROR: no paper values for ({link!r}, {scheme!r})", file=sys.stderr)
            return 1
        if expected != stats:
            print(f"ERROR: expected {expected}, got {stats}", file=sys.stderr)
            return 1
        print("PASS: values match the paper")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path, nargs="?", help="latency JSON file to analyze")
    parser.add_argument("--check-paper-values", action="store_true")
    parser.add_argument("--link", choices=("a", "b", "c", "d"))
    parser.add_argument("--scheme")
    args = parser.parse_args()

    if args.json_file is not None:
        match = re.fullmatch(r"(?:route-)?([a-d])-(.+)\.json", args.json_file.name)
        link = args.link or (match.group(1) if match else None)
        scheme = args.scheme or (match.group(2) if match else None)
        if link is None or scheme is None:
            parser.error("JSON filename must be route-LINK-SCHEME.json, or provide --link and --scheme")
        try:
            return analyze_file(args.json_file, link, scheme, args.check_paper_values)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1

    manifest = REFERENCE / "network_summary.csv"
    failures: list[str] = []
    print("link  scheme       n      min    max    p99    med    avg   UF/DR/DF/HF")
    print("----  -----------  -----  -----  -----  -----  -----  -----  -----------")
    with manifest.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            key = (row["link"], row["scheme"])
            counts = (
                row["udp_failures"],
                row["decryption_retries"],
                str(int(row["handshake_failures"]) - int(row["udp_failures"]))
                if row["handshake_failures"] and row["udp_failures"]
                else "n/a",
                row["handshake_failures"],
            )
            count_display = "/".join(counts) if all(counts) else "n/a"
            if not row["data_file"]:
                print(f"{key[0]:<4}  {key[1]:<11}  unreachable{'':25}  {count_display}")
                continue
            path = REFERENCE / "latency" / row["data_file"]
            result = json.loads(path.read_text(encoding="utf-8"))
            values = result["latencies_ms"] if isinstance(result, dict) else result
            if len(values) != int(row["successful_samples"]):
                failures.append(f"{path.name}: expected {row['successful_samples']} samples, got {len(values)}")
            stats = rounded_stats(values)
            print(
                f"{key[0]:<4}  {key[1]:<11}  {len(values):>5}  "
                f"{stats[0]:>5}  {stats[1]:>5}  {stats[2]:>5}  "
                f"{stats[3]:>5}  {stats[4]:>5}  {count_display}"
            )
            if args.check_paper_values and PAPER_VALUES.get(key) != stats:
                failures.append(f"{key}: expected {PAPER_VALUES.get(key)}, got {stats}")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    if args.check_paper_values:
        print("PASS: reference values match the paper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
