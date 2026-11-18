#!/usr/bin/env python3
"""Red-team the injection detector and score it.

Runs every payload in the corpus through injection.scan() and reports:
  * catch rate     — % of malicious payloads flagged (per category and overall)
  * false-positive rate — % of benign banners wrongly flagged
  * which specific payloads slipped through, so gaps are actionable

This turns "the injection defense works" into a number you can defend in an
interview and track for regressions. Run: python3 redteam.py
"""
from __future__ import annotations

import json
from collections import defaultdict

from hannibal.injection import scan
from hannibal.redteam_corpus import MALICIOUS, BENIGN


def main() -> int:
    by_cat_total: dict = defaultdict(int)
    by_cat_caught: dict = defaultdict(int)
    missed = []

    for category, payload in MALICIOUS:
        by_cat_total[category] += 1
        if scan(payload).suspicious:
            by_cat_caught[category] += 1
        else:
            missed.append((category, payload))

    caught = sum(by_cat_caught.values())
    total = len(MALICIOUS)

    false_positives = [b for b in BENIGN if scan(b).suspicious]
    fp_rate = len(false_positives) / max(1, len(BENIGN))

    # ---- console ----
    print(f"\nHANNIBAL INJECTION RED-TEAM\n" + "─" * 48)
    print(f"{'category':22} {'caught':>10}")
    print("─" * 48)
    for cat in sorted(by_cat_total):
        print(f"{cat:22} {by_cat_caught[cat]:>4}/{by_cat_total[cat]:<4}")
    print("─" * 48)
    print(f"{'OVERALL catch rate':22} {caught}/{total}  ({caught/total:.0%})")
    print(f"{'false-positive rate':22} {len(false_positives)}/{len(BENIGN)}  ({fp_rate:.0%})")
    if missed:
        print("\nMISSED payloads (gaps to close):")
        for cat, p in missed:
            print(f"  [{cat}] {p[:70]}")
    if false_positives:
        print("\nFALSE POSITIVES (benign flagged — tighten patterns):")
        for b in false_positives:
            print(f"  {b[:70]}")

    # ---- markdown ----
    md = ["# Hannibal injection red-team", "",
          f"**Catch rate: {caught}/{total} ({caught/total:.0%})** · "
          f"**False positives: {len(false_positives)}/{len(BENIGN)} ({fp_rate:.0%})**", "",
          "| Attack class | Caught |", "|---|---|"]
    for cat in sorted(by_cat_total):
        md.append(f"| {cat} | {by_cat_caught[cat]}/{by_cat_total[cat]} |")
    md.append("")
    with open("redteam_results.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    with open("redteam_results.json", "w", encoding="utf-8") as fh:
        json.dump({"catch": caught, "total": total,
                   "false_positives": len(false_positives), "benign": len(BENIGN),
                   "missed": missed}, fh, indent=2)
    print("\nwrote redteam_results.md and redteam_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
