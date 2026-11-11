#!/usr/bin/env python3
"""Run the six Sage lattice estimates and save their output to a text file."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
ESTIMATOR_DIRECTORY = SCRIPT_DIRECTORY / "lattice-estimator"
DEFAULT_OUTPUT = SCRIPT_DIRECTORY / "lwe_estimates.txt"

SAGE_PROGRAM = r"""
import os
import sys

sys.path.insert(0, os.getcwd())
from estimator import *

scheme_names = (
    "Kyber512",
    "Kyber768",
    "Kyber1024",
    "eMLKEM512",
    "eMLKEM768",
    "eMLKEM1024",
)

for index, scheme_name in enumerate(scheme_names):
    if index:
        print()
    print("=== schemes.{} ===".format(scheme_name), flush=True)
    r = LWE.estimate.rough(getattr(schemes, scheme_name))
""".strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Sage LWE rough estimates and save the output as UTF-8 text."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="result file (default: security-estimates/lwe_estimates.txt)",
    )
    parser.add_argument(
        "--sage",
        default="sage",
        help="Sage executable name or path (default: sage)",
    )
    args = parser.parse_args()

    if not ESTIMATOR_DIRECTORY.is_dir():
        print(
            f"error: lattice-estimator directory not found: {ESTIMATOR_DIRECTORY}\n"
            "Run setup_lattice_estimator.py first.",
            file=sys.stderr,
        )
        return 1
    if shutil.which(args.sage) is None:
        print(f"error: Sage executable not found: {args.sage}", file=sys.stderr)
        return 1

    output_file = args.output.resolve()
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        existing_python_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = str(ESTIMATOR_DIRECTORY)
        if existing_python_path:
            environment["PYTHONPATH"] += os.pathsep + existing_python_path

        print(f"Running estimates in {ESTIMATOR_DIRECTORY}...", flush=True)
        print(f"Saving output to {output_file}\n", flush=True)
        with output_file.open("w", encoding="utf-8", newline="\n") as destination:
            process = subprocess.Popen(
                [args.sage, "-c", SAGE_PROGRAM],
                cwd=ESTIMATOR_DIRECTORY,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="", flush=True)
                destination.write(line)
                destination.flush()
            return_code = process.wait()

        if return_code != 0:
            print(
                f"error: Sage exited with status {return_code}; partial output is in "
                f"{output_file}",
                file=sys.stderr,
            )
            return return_code

        print(f"\nEstimate output saved to {output_file}")
        return 0
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
