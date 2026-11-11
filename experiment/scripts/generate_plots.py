#!/usr/bin/env python3
"""Regenerate the latency CDF and box-plot panels corresponding to Figure 6."""

from __future__ import annotations

import json
import inspect
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "reference_results" / "latency"
OUTPUT = ROOT / "generated" / "figure6"

PAIRS = {
    "a": (("ecp384", "ecdh_bj_sh.json"), ("emlkem768", "emlkem_bj_sh.json")),
    "b": (("ecp384", "ecdh_bj_kr.json"), ("emlkem768", "emlkem_bj_kr.json")),
    "c": (("ecp384", "ecdh_bj_sg.json"), ("emlkem768", "emlkem_bj_sg.json")),
    "d": (("ecp384", "ecdh_uk_sh.json"), ("emlkem768", "emlkem_uk_sh.json")),
    "a-level5": (("mlkem1024", "mlkem1024_bj_sh.json"), ("emlkem1024", "emlkem1024_bj_sh.json")),
    "b-level5": (("mlkem1024", "mlkem1024_bj_kr.json"), ("emlkem1024", "emlkem1024_bj_kr.json")),
    "c-level5": (None, ("emlkem1024", "emlkem1024_bj_sg.json")),
    "d-level5": (("mlkem1024", "mlkem1024_uk_sh.json"), ("emlkem1024", "emlkem1024_uk_sh.json")),
}


def load(filename: str) -> list[float]:
    return sorted(json.loads((DATA / filename).read_text(encoding="utf-8")))


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for panel, pair in PAIRS.items():
        available = [entry for entry in pair if entry is not None]

        fig, axis = plt.subplots(figsize=(6, 4))
        for label, filename in available:
            values = load(filename)
            probabilities = [(index + 1) / len(values) for index in range(len(values))]
            is_emlkem = label.startswith("emlkem")
            axis.plot(
                values,
                probabilities,
                label=label,
                color="tab:orange" if is_emlkem else "tab:blue",
                linestyle="-." if is_emlkem else "-",
            )
        axis.set_xlabel("Handshake time (ms)")
        axis.set_ylabel("CDF")
        axis.legend()
        fig.tight_layout()
        fig.savefig(OUTPUT / f"cdf-{panel}.png", dpi=200)
        plt.close(fig)

        fig, axis = plt.subplots(figsize=(6, 4))
        boxplot_labels = [label for label, _ in available]
        boxplot_kwargs = {
            "tick_labels" if "tick_labels" in inspect.signature(axis.boxplot).parameters else "labels": boxplot_labels
        }
        axis.boxplot(
            [load(filename) for _, filename in available],
            showfliers=True,
            **boxplot_kwargs,
        )
        axis.set_ylabel("Handshake time (ms)")
        axis.grid(True, axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(OUTPUT / f"boxplot-{panel}.png", dpi=200)
        plt.close(fig)

    print(f"PASS: generated {len(PAIRS) * 2} plots in {OUTPUT}")


if __name__ == "__main__":
    main()
