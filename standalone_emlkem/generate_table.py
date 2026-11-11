#!/usr/bin/env python3
"""Read saved eMLKEM test outputs and generate a LaTeX comparison table."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent
SECURITY_RESULTS = ROOT / "security-estimates"
LWE_RESULTS_FILE = SECURITY_RESULTS / "lwe_estimates.txt"
FAILURE_ESTIMATES_FILE = SECURITY_RESULTS / "failure_estimates.txt"
PARAMETERS = (("512", "1"), ("768", "3"), ("1024", "5"))


@dataclass(frozen=True)
class Implementation:
    scheme: str
    qualifier: str
    executable_prefix: str
    estimate_prefix: str


@dataclass(frozen=True)
class Result:
    level: str
    security_bits: int
    public_key_bytes: int
    ciphertext_bytes: int
    log_delta: str
    failures: int
    keygen: int
    encaps: int
    decaps: int


IMPLEMENTATIONS = (
    Implementation("MLKEM", "IND-CCA", "", "Kyber"),
    Implementation("This work", "IND-CPAF", "e", "eMLKEM"),
)


def read_result(directory: Path, stem: str) -> str:
    """Read one required raw-output file without running any programs."""
    result_file = directory / f"{stem}.txt"
    if not result_file.is_file():
        raise RuntimeError(
            f"result file not found: {result_file.relative_to(ROOT)}\n"
            "Run 'python3 run_tests.py' first."
        )
    return result_file.read_text(encoding="utf-8", errors="replace")


def read_security_result(path: Path, generator: str) -> str:
    if not path.is_file():
        raise RuntimeError(
            f"result file not found: {path.relative_to(ROOT)}\n"
            f"Run 'python3 security-estimates/{generator}' first."
        )
    return path.read_text(encoding="utf-8", errors="replace")


def parse_failure_output(output: str, source: str) -> tuple[int, int, int]:
    patterns = {
        "public key length": r"(?im)^pk length:\s*(\d+)\s*$",
        "ciphertext length": r"(?im)^ct length:\s*(\d+)\s*$",
        "failure count": r"(?im)^Failure times:\s*(\d+)\s*/",
    }
    values: dict[str, int] = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, output)
        if match is None:
            raise RuntimeError(f"could not find {name} in {source}")
        values[name] = int(match.group(1))
    return (
        values["public key length"],
        values["ciphertext length"],
        values["failure count"],
    )


def parse_speed_output(output: str, source: str) -> dict[str, int]:
    wanted = {
        "kyber_keypair": "keygen",
        "kyber_encaps": "encaps",
        "kyber_decaps": "decaps",
    }
    averages: dict[str, int] = {}
    current: str | None = None
    for line in output.splitlines():
        label = re.fullmatch(r"\s*(kyber_[a-z_]+):\s*", line)
        if label:
            current = wanted.get(label.group(1))
            continue
        average = re.fullmatch(r"\s*average:\s*(\d+)\s+cycles/ticks\s*", line)
        if average and current is not None:
            averages[current] = int(average.group(1))
            current = None

    missing = set(wanted.values()) - averages.keys()
    if missing:
        raise RuntimeError(
            f"could not find speed-test average(s) in {source}: "
            + ", ".join(sorted(missing))
        )
    return averages


def parse_lwe_security(output: str, source: str) -> dict[str, int]:
    """Extract the rounded usvp rop exponent for every named scheme."""
    security: dict[str, int] = {}
    current_scheme: str | None = None
    for line in output.splitlines():
        heading = re.fullmatch(r"\s*===\s*schemes\.([A-Za-z0-9_-]+)\s*===\s*", line)
        if heading:
            current_scheme = heading.group(1).replace("-", "")
            continue
        if current_scheme is None or not re.match(r"\s*usvp\s+::", line):
            continue
        exponent = re.search(r"\brop:\s*.*?\^\s*([+-]?\d+(?:\.\d+)?)", line)
        if exponent is None:
            raise RuntimeError(f"could not find usvp rop exponent in {source}")
        security[current_scheme] = rounded_decimal(exponent.group(1))
        current_scheme = None

    if not security:
        raise RuntimeError(f"could not find any LWE security estimates in {source}")
    return security


def parse_log_delta(output: str, source: str) -> dict[str, str]:
    """Extract log2(failure probability) for every named scheme."""
    estimates: dict[str, str] = {}
    current_scheme: str | None = None
    for line in output.splitlines():
        heading = re.fullmatch(
            r"\s*(Kyber|eMLKEM)-?(\d+)(?:\s+\([^)]*\))?:\s*", line
        )
        if heading:
            current_scheme = heading.group(1) + heading.group(2)
            continue
        if current_scheme is None:
            continue
        exponent = re.search(r"\bfailure:.*?=\s*2\^([+-]?\d+(?:\.\d+)?)", line)
        if exponent:
            value = Decimal(exponent.group(1))
            estimates[current_scheme] = format(value.normalize(), "f")
            current_scheme = None

    if not estimates:
        raise RuntimeError(f"could not find any failure estimates in {source}")
    return estimates


def rounded_decimal(value: str) -> int:
    """Round a decimal value to the nearest integer using half-up rounding."""
    return int(Decimal(value).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def thousands_rounded(cycles: int) -> int:
    """Divide cycles by 1000 and use conventional half-up rounding."""
    value = Decimal(cycles) / Decimal(1000)
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def collect(
    implementation: Implementation,
    security: dict[str, int],
    log_deltas: dict[str, str],
) -> list[Result]:
    results: list[Result] = []
    for parameter, level in PARAMETERS:
        failure_name = f"{implementation.executable_prefix}{parameter}-failure"
        speed_name = f"{implementation.executable_prefix}{parameter}-speed"
        failure_file = f"failure_test/{failure_name}.txt"
        speed_file = f"speed_test/{speed_name}.txt"
        estimate_name = f"{implementation.estimate_prefix}{parameter}"
        if estimate_name not in security:
            raise RuntimeError(
                f"missing {estimate_name} usvp estimate in "
                f"{LWE_RESULTS_FILE.relative_to(ROOT)}"
            )
        if estimate_name not in log_deltas:
            raise RuntimeError(
                f"missing {estimate_name} failure estimate in "
                f"{FAILURE_ESTIMATES_FILE.relative_to(ROOT)}"
            )

        failure_output = read_result(ROOT / "failure_test", failure_name)
        public_key_bytes, ciphertext_bytes, failures = parse_failure_output(
            failure_output, failure_file
        )
        speed = parse_speed_output(
            read_result(ROOT / "speed_test", speed_name), speed_file
        )
        results.append(
            Result(
                level=level,
                security_bits=security[estimate_name],
                public_key_bytes=public_key_bytes,
                ciphertext_bytes=ciphertext_bytes,
                log_delta=log_deltas[estimate_name],
                failures=failures,
                keygen=thousands_rounded(speed["keygen"]),
                encaps=thousands_rounded(speed["encaps"]),
                decaps=thousands_rounded(speed["decaps"]),
            )
        )
    return results


def latex_table(all_results: list[tuple[Implementation, list[Result]]]) -> str:
    lines = [
        r"\begin{tabular}{c|cc|cccc|rrr}",
        r"\toprule",
        r"Scheme & Level & Sec.(C) & $|pk|$ & $|ct|$ & $\log \delta$ & fails & KGen & Encap & Decap \\",
        r"\midrule",
    ]
    for implementation_index, (implementation, results) in enumerate(all_results):
        scheme = (
            r"\multirow{3}{*}{\shortstack{"
            + implementation.scheme
            + r" \\ ("
            + implementation.qualifier
            + ")}}"
        )
        for row_index, result in enumerate(results):
            prefix = scheme if row_index == 0 else ""
            lines.append(
                f"{prefix} & {result.level} & {result.security_bits} & "
                f"{result.public_key_bytes} & {result.ciphertext_bytes} & "
                f"{result.log_delta} & {result.failures} & {result.keygen} & "
                f"{result.encaps} & {result.decaps} \\\\"
            )
        if implementation_index != len(all_results) - 1:
            lines.append(r"\midrule")
    lines.extend((r"\bottomrule", r"\end{tabular}"))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read saved .txt results and generate a LaTeX comparison table."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=ROOT / "benchmark_table.tex",
        help="LaTeX output file (default: benchmark_table.tex)",
    )
    args = parser.parse_args()

    try:
        security = parse_lwe_security(
            read_security_result(LWE_RESULTS_FILE, "run_lwe_estimates.py"),
            str(LWE_RESULTS_FILE.relative_to(ROOT)),
        )
        log_deltas = parse_log_delta(
            read_security_result(
                FAILURE_ESTIMATES_FILE, "run_failure_estimates.py"
            ),
            str(FAILURE_ESTIMATES_FILE.relative_to(ROOT)),
        )
        all_results = [
            (implementation, collect(implementation, security, log_deltas))
            for implementation in IMPLEMENTATIONS
        ]
        table = latex_table(all_results)
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(table, encoding="utf-8")
        print(f"LaTeX table written to {output}\n")
        print(table, end="")
        return 0
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
