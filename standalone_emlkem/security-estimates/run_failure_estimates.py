#!/usr/bin/env python3
"""Run Kyber_failure.py and save its output to a text file."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
FAILURE_PROGRAM = SCRIPT_DIRECTORY / "Kyber_failure.py"
DEFAULT_OUTPUT = SCRIPT_DIRECTORY / "failure_estimates.txt"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Kyber_failure.py and save its output as UTF-8 text."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="result file (default: security-estimates/failure_estimates.txt)",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable name or path (default: current Python)",
    )
    args = parser.parse_args()

    if not FAILURE_PROGRAM.is_file():
        print(f"error: program not found: {FAILURE_PROGRAM}", file=sys.stderr)
        return 1
    if shutil.which(args.python) is None:
        print(f"error: Python executable not found: {args.python}", file=sys.stderr)
        return 1

    output_file = args.output.resolve()
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"

        print(f"Running {FAILURE_PROGRAM.name} in {SCRIPT_DIRECTORY}...", flush=True)
        print(f"Saving output to {output_file}\n", flush=True)
        with output_file.open("w", encoding="utf-8", newline="\n") as destination:
            process = subprocess.Popen(
                [args.python, str(FAILURE_PROGRAM)],
                cwd=SCRIPT_DIRECTORY,
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
                f"error: Kyber_failure.py exited with status {return_code}; "
                f"partial output is in {output_file}",
                file=sys.stderr,
            )
            return return_code

        print(f"\nFailure-analysis output saved to {output_file}")
        return 0
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
