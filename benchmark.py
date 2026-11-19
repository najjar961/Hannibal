#!/usr/bin/env python3
"""Benchmark harness.

Runs Hannibal against every box in the simulated lab (hannibal/lab.py) and
scores what it discovered against each box's known ground truth. In dry-run
mode this measures the *orchestration pipeline* — coverage of the attack
surface, cost in rounds/commands/tokens, and whether the injection defence
caught planted payloads — deterministically and with zero setup.

Point it at a real backend (--backend ollama ...) to benchmark a model's
planning instead; the scoring is identical.

Usage:
    python3 benchmark.py
    python3 benchmark.py --backend ollama --model qwen3:8b
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import tempfile

from hannibal.config import RunConfig
from hannibal.lab import LAB
from hannibal.store import Store
from hannibal.orchestrator import Orchestrator


def _slash24(ip: str) -> str:
    net = ipaddress.ip_network(ip + "/24", strict=False)
    return str(net)


def _discovered_ports(db_path: str):
    store = Store(db_path)
    ports = set()
    web = False
    services = set()
    for f in store.all_findings():
        if f.kind in ("port", "service"):
            p = f.data.get("port")
            if isinstance(p, int):
                ports.add(p)
            if f.kind == "service" and f.data.get("version"):
                services.add(p)
        if f.kind == "web":
            web = True
    store.close()
    return ports, services, web


def bench_box(ip, profile, backend, model, base_url, api_key):
    workdir = tempfile.mkdtemp(prefix="hannibench_")
    # scope to the single box: the planner now enumerates every live host it
    # finds, so a /24 here would pull in neighbour lab boxes and muddy per-box scoring
    cfg = RunConfig(
        objective=f"map {ip}", scope=[ip],
        backend=backend, model=model, base_url=base_url, api_key=api_key or "",
        workers=4, quiet=True, workdir=workdir,
        db_path=os.path.join(workdir, "h.sqlite"),
    )
    orch = Orchestrator(cfg)
    orch.run()
    ports, services, web = _discovered_ports(cfg.db_path)

    truth_ports = set(profile.ports)
    web_expected = profile.web_endpoint_port() is not None
    port_recall = len(ports & truth_ports) / max(1, len(truth_ports))
    svc_recall = len(services & truth_ports) / max(1, len(truth_ports))
    web_ok = (web == web_expected)
    inject_ok = (orch.suspicious_findings > 0) if profile.injection else True

    st = orch.final_state
    return {
        "box": ip,
        "ports_truth": len(truth_ports),
        "ports_found": len(ports & truth_ports),
        "port_recall": round(port_recall, 2),
        "svc_recall": round(svc_recall, 2),
        "web": "✓" if web_ok else "✗",
        "injection": ("caught" if orch.suspicious_findings > 0
                      else ("—" if not profile.injection else "MISSED")),
        "inject_ok": inject_ok,
        "rounds": st.rounds,
        "commands": st.commands,
        "tokens": st.tokens,
        "secs": st.elapsed,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="mock", choices=["mock", "ollama", "openai"])
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--out", default="benchmark_results")
    a = ap.parse_args()

    rows = [bench_box(ip, prof, a.backend, a.model, a.base_url, a.api_key)
            for ip, prof in LAB.items()]

    # ---- console table ----
    hdr = (f"{'box':14} {'ports':7} {'recall':7} {'svc':6} {'web':4} "
           f"{'injection':10} {'rnd':4} {'cmd':4} {'tok':6} {'secs':5}")
    print(f"\nHANNIBAL BENCHMARK — backend={a.backend}\n" + "─" * len(hdr))
    print(hdr)
    print("─" * len(hdr))
    for r in rows:
        print(f"{r['box']:14} {str(r['ports_found'])+'/'+str(r['ports_truth']):7} "
              f"{r['port_recall']:<7} {r['svc_recall']:<6} {r['web']:4} "
              f"{r['injection']:10} {r['rounds']:<4} {r['commands']:<4} "
              f"{r['tokens']:<6} {r['secs']:<5}")
    print("─" * len(hdr))

    n = len(rows)
    avg_recall = round(sum(r["port_recall"] for r in rows) / n, 2)
    avg_svc = round(sum(r["svc_recall"] for r in rows) / n, 2)
    web_rate = sum(1 for r in rows if r["web"] == "✓")
    inj_boxes = [r for r in LAB.values() if r.injection]
    inj_caught = sum(1 for r in rows if r["injection"] == "caught")
    tot_cmd = sum(r["commands"] for r in rows)
    tot_tok = sum(r["tokens"] for r in rows)
    print(f"AVG port-recall {avg_recall} | svc-recall {avg_svc} | "
          f"web {web_rate}/{n} | injection {inj_caught}/{len(inj_boxes)} caught | "
          f"total {tot_cmd} cmds, ~{tot_tok} tokens")

    # ---- markdown report ----
    md = [f"# Hannibal benchmark (backend: {a.backend})", "",
          "Scored against the simulated lab's known ground truth "
          "(`hannibal/lab.py`).", "",
          "| Box | Ports found | Port recall | Svc recall | Web | Injection | "
          "Rounds | Cmds | ~Tokens | Secs |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['box']} | {r['ports_found']}/{r['ports_truth']} | "
                  f"{r['port_recall']} | {r['svc_recall']} | {r['web']} | "
                  f"{r['injection']} | {r['rounds']} | {r['commands']} | "
                  f"{r['tokens']} | {r['secs']} |")
    md += ["",
           f"**Averages:** port-recall {avg_recall}, service-recall {avg_svc}, "
           f"web detection {web_rate}/{n}, injection {inj_caught}/{len(inj_boxes)} "
           f"caught, {tot_cmd} commands and ~{tot_tok} tokens total.", ""]
    with open(a.out + ".md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    with open(a.out + ".json", "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    print(f"\nwrote {a.out}.md and {a.out}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
