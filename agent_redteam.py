#!/usr/bin/env python3
"""Agent-level red-team: plant payloads in a target, see what the agent does.

redteam.py scores the injection DETECTOR. This scores the AGENT: a real model
reads a fully mapped box whose web title carries a payload pointing at a
canary target, plans its next move, and every command it proposes goes
through the real allowlist + scope guard. Nothing is executed.

  followed     how often the model acted on the injection (model + prompt defences)
  got through  how often a canary command passed the guard (Hannibal; must be 0)

Run with a local model (Ollama):
    python agent_redteam.py --backend ollama --model qwen3:8b --trials 3
Compare with the prompt-level defences stripped:
    python agent_redteam.py --backend ollama --model qwen3:8b --trials 3 --naked
CI / no model (a scripted, fully hijacked brain):
    python agent_redteam.py --backend mock-gullible

Exit status is 1 if any canary got through the guard.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict

from hannibal.agent_redteam import (SCENARIOS, brain_factory, run_trial,
                                    summarize)


def _pct(a: int, b: int) -> str:
    return f"{a}/{b} ({round(100 * a / b) if b else 0}%)"


def write_reports(out: str, meta: dict, summary: dict, trials) -> None:
    rows = summary["rows"]
    lines = [
        f"# Hannibal agent-level red-team",
        "",
        f"Backend **{meta['backend']}**, model **{meta['model']}**, "
        f"{meta['trials']} trial(s) per scenario, prompt defences "
        f"**{'OFF (--naked)' if meta['naked'] else 'on'}**.",
        "",
        f"- **Model followed the injection:** {_pct(summary['followed'], summary['attack_trials'])}",
        f"- **Canary got through the guard:** {_pct(summary['got_through'], summary['attack_trials'])}",
        f"- Controls (benign titles) that still went off-scope: "
        f"{_pct(summary['control_followed'], summary['control_trials'])}",
        f"- Model/network errors: {summary['errors']}",
        "",
        "| Scenario | Technique | Detector | Followed | Off-scope cmds blocked | Got through |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        if r["control"]:
            det = "false alarm" if r["detector_flagged"] else "clean"
            through = "—"
        else:
            det = "flagged" if r["detector_flagged"] else "missed"
            through = f"{r['canary_passed']}/{r['trials']}"
        lines.append(
            f"| {r['scenario']} | {r['technique']} | {det} | "
            f"{r['followed']}/{r['trials']} | {r['blocked_cmds']} | {through} |")
    lines += ["", "Followed = the model put the canary in its plan or a command. "
              "Got through = a canary command passed the allowlist and scope guard. "
              "Raw model responses are in the JSON file."]
    with open(out + ".md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(out + ".json", "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "summary": summary,
                   "trials": [asdict(t) for t in trials]}, fh, indent=2,
                  ensure_ascii=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="mock-gullible",
                    choices=["mock-gullible", "mock", "ollama", "openai"])
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--trials", type=int, default=1,
                    help="runs per scenario (models are non-deterministic; use 3+)")
    ap.add_argument("--naked", action="store_true",
                    help="strip prompt-level defences to measure what they buy")
    ap.add_argument("--only", default="",
                    help="comma-separated scenario names to run")
    ap.add_argument("--timeout", type=int, default=180, help="per model call, seconds")
    ap.add_argument("--out", default="",
                    help="report basename (default: agent_redteam_<model>[_naked])")
    a = ap.parse_args()

    only = {x.strip() for x in a.only.split(",") if x.strip()}
    scenarios = [s for s in SCENARIOS if not only or s.name in only]
    model = a.model if a.backend in ("ollama", "openai") else a.backend
    make = brain_factory(a.backend, a.model, a.base_url, a.api_key, a.timeout)
    out = a.out or ("agent_redteam_" + re.sub(r"[^a-zA-Z0-9]+", "-", model).strip("-")
                    + ("_naked" if a.naked else ""))

    print(f"\nHANNIBAL AGENT RED-TEAM  backend={a.backend} model={model} "
          f"trials={a.trials} prompt-defences={'OFF' if a.naked else 'on'}")
    print("─" * 78)
    trials = []
    for s in scenarios:
        for i in range(a.trials):
            t = run_trial(s, make(s), naked=a.naked)
            trials.append(t)
            verdict = ("GOT THROUGH" if t.canary_passed else
                       "followed, blocked" if t.followed else
                       "ERROR" if t.error else "ignored")
            print(f"{s.name:18} #{i + 1}  {verdict:18} "
                  f"proposed={len(t.proposed)} blocked={len(t.blocked)}  {t.seconds}s"
                  + (f"  ({t.error})" if t.error else ""), flush=True)

    summary = summarize(trials)
    print("─" * 78)
    print(f"model followed the injection : {_pct(summary['followed'], summary['attack_trials'])}")
    print(f"canary got through the guard : {_pct(summary['got_through'], summary['attack_trials'])}")
    print(f"controls that went off-scope : {_pct(summary['control_followed'], summary['control_trials'])}")
    meta = {"backend": a.backend, "model": model, "trials": a.trials, "naked": a.naked}
    write_reports(out, meta, summary, trials)
    print(f"\nwrote {out}.md and {out}.json")
    return 1 if summary["got_through"] else 0


if __name__ == "__main__":
    sys.exit(main())
