#!/usr/bin/env python3
"""Build and run all eMLKEM tests, saving each program's output as text."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
PARAMETERS = ("512", "768", "1024")


@dataclass(frozen=True)
class Implementation:
    name: str
    makefile: str
    executable_prefix: str


IMPLEMENTATIONS = (
    Implementation("MLKEM (IND-CCA)", "Makefile_cca", ""),
    Implementation("This work (IND-CPAF)", "Makefile", "e"),
)


def run(command: list[str], *, cwd: Path, show_output: bool = False) -> str:
    """Run a command and return its combined stdout and stderr."""
    if show_output:
        print(f"$ {' '.join(command)}  (in {cwd})", flush=True)
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    if show_output and completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.returncode != 0:
        detail = completed.stdout.strip()
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    return completed.stdout


def executable(directory: Path, stem: str) -> Path:
    """Locate an executable produced by make on Linux or Windows."""
    for candidate in (directory / stem, directory / f"{stem}.exe"):
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"executable not found after build: {directory / stem}")


def result_file(directory: Path, stem: str) -> Path:
    return directory / f"{stem}.txt"


def build_missing(
    make_command: str,
    implementation: Implementation,
    verbose: bool,
    force: bool,
) -> None:
    for directory, test_name in (
        (ROOT / "failure_test", "failure"),
        (ROOT / "speed_test", "speed"),
    ):
        all_results_exist = all(
            result_file(
                directory,
                f"{implementation.executable_prefix}{parameter}-{test_name}",
            ).is_file()
            for parameter in PARAMETERS
        )
        if all_results_exist and not force:
            print(
                f"All {implementation.name} {test_name} results exist; "
                "skipping build.",
                flush=True,
            )
            continue
        print(f"Building {implementation.name} tests in {directory.name}...", flush=True)
        run(
            [make_command, "-f", implementation.makefile],
            cwd=directory,
            show_output=verbose,
        )


def run_and_save(directory: Path, stem: str, verbose: bool, force: bool) -> None:
    output_file = result_file(directory, stem)
    if output_file.is_file() and not force:
        print(
            f"Result already exists, skipping test: {output_file.relative_to(ROOT)}",
            flush=True,
        )
        return

    print(f"Running {stem}...", flush=True)
    output = run(
        [str(executable(directory, stem))],
        cwd=directory,
        show_output=verbose,
    )
    output_file.write_text(output, encoding="utf-8")
    print(f"Saved result: {output_file.relative_to(ROOT)}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and run all comparison tests, saving their raw output as .txt files."
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="run existing executables without invoking make",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="run all tests again and overwrite existing .txt results",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="also show build and test program output on screen",
    )
    args = parser.parse_args()

    make_command = os.environ.get("MAKE", "make")
    try:
        for implementation in IMPLEMENTATIONS:
            if not args.no_build:
                build_missing(
                    make_command,
                    implementation,
                    args.verbose,
                    args.force,
                )
            for parameter in PARAMETERS:
                run_and_save(
                    ROOT / "failure_test",
                    f"{implementation.executable_prefix}{parameter}-failure",
                    args.verbose,
                    args.force,
                )
                run_and_save(
                    ROOT / "speed_test",
                    f"{implementation.executable_prefix}{parameter}-speed",
                    args.verbose,
                    args.force,
                )
        print("\nTest result check complete.")
        return 0
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
