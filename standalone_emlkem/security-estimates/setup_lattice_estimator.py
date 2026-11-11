#!/usr/bin/env python3
"""Clone lattice-estimator locally, optionally at an explicit Git revision."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys


REPOSITORY_URL = "https://github.com/malb/lattice-estimator.git"
HERE = Path(__file__).resolve().parent
DESTINATION = HERE / "lattice-estimator"
SOURCE_SCHEMES = HERE / "schemes.py"
TARGET_SCHEMES = DESTINATION / "estimator" / "schemes.py"


def run(*command: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        list(command), cwd=cwd, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit",
        help="commit/tag to check out; omit to use current main and record its commit",
    )
    args = parser.parse_args()
    try:
        if shutil.which("git") is None:
            raise RuntimeError("git was not found in PATH")
        if not (DESTINATION / ".git").is_dir():
            if DESTINATION.exists():
                raise RuntimeError(f"non-Git destination already exists: {DESTINATION}")
            print(f"Cloning {REPOSITORY_URL}...")
            run("git", "clone", REPOSITORY_URL, str(DESTINATION))
        if args.commit:
            run("git", "fetch", "--all", "--tags", cwd=DESTINATION)
            run("git", "checkout", "--detach", args.commit, cwd=DESTINATION)
        revision = run("git", "rev-parse", "HEAD", cwd=DESTINATION)
        if not TARGET_SCHEMES.parent.is_dir():
            raise RuntimeError("invalid lattice-estimator checkout: estimator/ missing")
        shutil.copy2(SOURCE_SCHEMES, TARGET_SCHEMES)
        print(f"lattice-estimator commit: {revision}")
        if not args.commit:
            print("NOTE: record this commit in the archived artifact metadata")
        print("PASS: installed customized schemes.py")
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
