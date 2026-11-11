#!/usr/bin/env python3
"""Conservative pre-upload scan for accidental secrets and endpoint data."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SKIP_PARTS = {".git", "generated", "__pycache__", "private-ae", "strongswan_6.0.4", "standalone_emlkem"}
TEXT_SUFFIXES = {"", ".c", ".h", ".md", ".txt", ".py", ".sh", ".csv", ".conf", ".in", ".am", ".ac"}
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----"),
    "credential assignment": re.compile(r"(?i)(?<!\*)\b(?:password|passwd|api[_-]?key|secret)\s*[:=]\s*\S+"),
    "public IPv4-like address": re.compile(r"(?<![\w.])(?:[1-9]\d{0,2}\.){3}\d{1,3}(?![\w.])"),
    "public IPv6-like address": re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){3,}[0-9a-f]{1,4}\b"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        action="store_true",
        help="also reject camera-ready DOI placeholders",
    )
    args = parser.parse_args()
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(ROOT)}:{line}: {label}")
    if args.release:
        for relative in (Path("README.md"), Path("ARTIFACT_APPENDIX.md")):
            text = (ROOT / relative).read_text(encoding="utf-8")
            if "<ARTIFACT_DOI>" in text:
                findings.append(f"{relative}: unresolved permanent DOI placeholder")
    if findings:
        print("Potential publication-sensitive content:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("PASS: no private keys, credential assignments, or public IP-like addresses found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
