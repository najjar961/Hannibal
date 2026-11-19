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

import argparse
import json
from collections import defaultdict

from hannibal.injection import scan, owasp_for, OWASP_LLM
from hannibal.semantic import deep_scan, LLMJudge
from hannibal.llm import LLMClient
from hannibal.redteam_corpus import MALICIOUS, BENIGN


def _scanner(a):
    """Return a function text -> suspicious bool, with optional semantic stage."""
    if not a.semantic:
        return lambda t: scan(t).suspicious
    judge = LLMJudge(LLMClient(a.base_url, a.model, a.api_key or ""))
    return lambda t: deep_scan(t, judge).suspicious


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--semantic", action="store_true",
                    help="add the model-based second stage (needs a running model)")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--model", default="dolphin-mistral:latest")
    ap.add_argument("--api-key", default="")
    a = ap.parse_args()
    is_suspicious = _scanner(a)
    by_cat_total: dict = defaultdict(int)
    by_cat_caught: dict = defaultdict(int)
    missed = []

    for category, payload in MALICIOUS:
        by_cat_total[category] += 1
        if is_suspicious(payload):
            by_cat_caught[category] += 1
        else:
            missed.append((category, payload))

    caught = sum(by_cat_caught.values())
    total = len(MALICIOUS)

    false_positives = [b for b in BENIGN if is_suspicious(b)]
    fp_rate = len(false_positives) / max(1, len(BENIGN))

    # ---- console ----
    print(f"\nHANNIBAL INJECTION RED-TEAM\n" + "─" * 52)
    print(f"{'attack class':22} {'OWASP':7} {'caught':>8}")
    print("─" * 52)
    for cat in sorted(by_cat_total):
        print(f"{cat:22} {owasp_for(cat):7} "
              f"{str(by_cat_caught[cat])+'/'+str(by_cat_total[cat]):>8}")
    print("─" * 52)
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
          "Each attack class is mapped to its OWASP Top 10 for LLM Applications "
          "(2025) risk.", "",
          "| Attack class | OWASP | Caught |", "|---|---|---|"]
    for cat in sorted(by_cat_total):
        oid, oname = OWASP_LLM.get(cat, ("—", ""))
        label = f"{oid} {oname}".strip()
        md.append(f"| {cat} | {label} | {by_cat_caught[cat]}/{by_cat_total[cat]} |")
    md.append("")
    with open("redteam_results.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    with open("redteam_results.json", "w", encoding="utf-8") as fh:
        json.dump({"catch": caught, "total": total,
                   "false_positives": len(false_positives), "benign": len(BENIGN),
                   "owasp": {c: owasp_for(c) for c in by_cat_total},
                   "missed": missed}, fh, indent=2)
    print("\nwrote redteam_results.md and redteam_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
