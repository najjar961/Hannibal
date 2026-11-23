#!/usr/bin/env python3
"""Hannibal command-line interface.

Installed as the ``hannibal`` console command (see pyproject.toml); also runnable
as ``python -m hannibal`` or via the thin ``hannibal.py`` shim at the repo root.

Examples
--------
  # full loop, zero setup, nothing touches the network (deterministic sim):
  hannibal run --objective "map my lab host" --scope 10.10.10.5,10.10.10.0/24

  # drive it with a local model via Ollama, still dry-run:
  hannibal run -o "enumerate HTB box" -s 10.10.11.20 --backend ollama --model qwen3:8b

  # actually execute the recon tools (only ever against authorized scope):
  hannibal run -o "..." -s 10.10.10.5 --execute

  # prove what the tool did:
  hannibal verify-audit hannibal_run
  hannibal report hannibal_run --html
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import RunConfig
from .audit import AuditLog
from .orchestrator import Orchestrator


BANNER = r"""
  _   _                       _ _           _
 | | | | __ _ _ __  _ __ (_) |__   __ _| |
 | |_| |/ _` | '_ \| '_ \| | '_ \ / _` | |   autonomous recon, on a leash
 |  _  | (_| | | | | | | | | |_) | (_| | |   commander → generals → wraiths
 |_| |_|\__,_|_| |_|_| |_|_|_.__/ \__,_|_|   authorized lab use only
"""


def _split(csv: str):
    return [x.strip() for x in csv.split(",") if x.strip()]


def cmd_run(a: argparse.Namespace) -> int:
    cfg = RunConfig(
        objective=a.objective, scope=_split(a.scope), backend=a.backend,
        model=a.model, base_url=a.base_url, api_key=a.api_key or "",
        workers=a.workers, max_rounds=a.max_rounds, max_seconds=a.max_seconds,
        max_tokens=a.max_tokens, max_commands=a.max_commands,
        execute=a.execute, workdir=a.workdir, semantic=a.semantic,
        max_auto_tier=a.max_auto_tier, approval=a.approve,
    )
    if not cfg.scope:
        print("error: --scope is required (the authorized targets)", file=sys.stderr)
        return 2
    if a.execute:
        print("⚠  EXECUTE mode: real recon tools will run against the scope above.")
        print("   Only proceed on systems you own or are authorized to test.\n")
    if a.execute and a.max_auto_tier >= 2:
        print("⚠  ATTACK tier auto-approved: vulnerability probes will run "
              "without asking.")
        print("   Use this only in your own isolated lab.\n")
    Orchestrator(cfg).run()
    return 0


def cmd_watch(a: argparse.Namespace) -> int:
    from .watch import run_watch, demo_injector, detection_table
    cfg = RunConfig(
        objective="continuously map and attack the scope", scope=_split(a.scope),
        backend=a.backend, model=a.model, base_url=a.base_url,
        api_key=a.api_key or "", workers=a.workers, execute=a.execute,
        workdir=a.workdir, max_auto_tier=a.max_auto_tier, approval=a.approve,
    )
    if not cfg.scope:
        print("error: --scope is required (the authorized targets)", file=sys.stderr)
        return 2
    injector = demo_injector() if a.demo else None
    if a.demo and a.execute:
        print("error: --demo mutates the simulated lab; it cannot be used with "
              "--execute", file=sys.stderr)
        return 2
    if a.execute:
        print("⚠  EXECUTE mode: real tools will run against the scope above, "
              "every cycle.")
        print("   Only proceed on systems you own or are authorized to test.\n")
    forever = a.cycles <= 0
    print(f"⟳  watch: {'until interrupted' if forever else f'{a.cycles} cycle(s)'}"
          f", interval {a.interval}s\n")
    try:
        run_watch(cfg, a.cycles, injector=injector, interval=a.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    if injector:
        print("\ntime to detection\n" + detection_table(injector))
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    import os
    path = a.path if a.path.endswith(".log") else os.path.join(a.path, "audit.log")
    ok, msg, n = AuditLog.verify(path, key=os.environ.get("HANNIBAL_AUDIT_KEY"))
    status = "OK" if ok else "FAILED"
    print(f"[{status}] {msg} — {n} entries verified")
    return 0 if ok else 1


def cmd_report(a: argparse.Namespace) -> int:
    import os
    from .store import Store, to_mermaid
    db = os.path.join(a.path, "hannibal.sqlite")
    if not os.path.exists(db):
        print(f"no run found at {db}", file=sys.stderr)
        return 1
    if a.html:
        from .htmlreport import write_report
        out = a.html if a.html is not True else os.path.join(a.path, "report.html")
        write_report(a.path, out)
        print(f"wrote HTML report → {out}")
        return 0
    store = Store(db)
    findings = store.all_findings()
    print(f"\nFindings ({len(findings)}):")
    for f in findings:
        tag = " [quarantined]" if f.suspicious else ""
        print(f"  ({f.kind:7}) {f.target:22} {f.summary}{tag}")
    print("\nMermaid graph (paste into mermaid.live):\n")
    print(to_mermaid(findings))
    store.close()
    return 0


def cmd_analyze(a: argparse.Namespace) -> int:
    import os
    from .store import Store
    from .analysis import analyze, summarize
    db = os.path.join(a.path, "hannibal.sqlite")
    if not os.path.exists(db):
        print(f"no run found at {db}", file=sys.stderr)
        return 1
    store = Store(db)
    weaknesses = analyze(store.all_findings())
    store.close()

    if not weaknesses:
        print("No known weaknesses matched the discovered services.")
        return 0

    counts = summarize(weaknesses)
    head = " · ".join(f"{counts[s]} {s}" for s in
                      ("critical", "high", "medium", "low", "info") if counts[s])
    print(f"\nATTACK-SURFACE ANALYSIS (advisory — verify manually)\n" + "─" * 60)
    print(head + "\n" + "─" * 60)
    for w in weaknesses:
        ref = f"  [{w.cve}]" if w.cve else ""
        print(f"{w.severity.upper():8} {w.host}:{w.port:<6} {w.title}{ref}")
        print(f"         ↳ {w.evidence}")
        print(f"         ↳ {w.note}")
    print("─" * 60)
    print("Leads only — each must be confirmed by hand, under authorization. "
          "No exploit steps are provided.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hannibal", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"hannibal {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run a recon campaign")
    r.add_argument("-o", "--objective", required=True)
    r.add_argument("-s", "--scope", required=True,
                   help="comma-separated authorized IPs/CIDRs/hosts")
    r.add_argument("--backend", default="mock", choices=["mock", "ollama", "openai"])
    r.add_argument("--model", default="qwen3:8b")
    r.add_argument("--base-url", default="http://localhost:11434/v1")
    r.add_argument("--api-key", default="")
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--max-rounds", type=int, default=8)
    r.add_argument("--max-seconds", type=int, default=600)
    r.add_argument("--max-tokens", type=int, default=200_000)
    r.add_argument("--max-commands", type=int, default=200)
    r.add_argument("--execute", action="store_true",
                   help="actually run the tools (default: deterministic dry-run)")
    r.add_argument("--semantic", action="store_true",
                   help="enable the model-based second-stage injection judge "
                        "(needs a real --backend; catches paraphrase/multilingual)")
    r.add_argument("--max-auto-tier", type=int, default=1, choices=[1, 2],
                   help="highest risk tier that runs without a human: "
                        "1 = recon only (default), 2 = attack wraiths too "
                        "(only for your own isolated lab)")
    r.add_argument("--approve", default="deny", choices=["deny", "prompt"],
                   help="commands above --max-auto-tier: 'deny' holds them "
                        "(default), 'prompt' asks you y/N for each one")
    r.add_argument("--workdir", default="hannibal_run")
    r.set_defaults(func=cmd_run)

    w = sub.add_parser("watch", help="monitor a scope continuously, report what changed")
    w.add_argument("-s", "--scope", required=True,
                   help="comma-separated authorized IPs/CIDRs/hosts")
    w.add_argument("--cycles", type=int, default=0,
                   help="number of passes (0 = until interrupted)")
    w.add_argument("--interval", type=float, default=0.0,
                   help="seconds to wait between passes")
    w.add_argument("--demo", action="store_true",
                   help="simulated lab only: inject changes on a schedule and "
                        "print a time-to-detection table")
    w.add_argument("--backend", default="mock", choices=["mock", "ollama", "openai"])
    w.add_argument("--model", default="qwen3:8b")
    w.add_argument("--base-url", default="http://localhost:11434/v1")
    w.add_argument("--api-key", default="")
    w.add_argument("--workers", type=int, default=4)
    w.add_argument("--execute", action="store_true",
                   help="actually run the tools (default: deterministic dry-run)")
    w.add_argument("--max-auto-tier", type=int, default=1, choices=[1, 2],
                   help="1 = recon only (default), 2 = attack wraiths too "
                        "(only for your own isolated lab)")
    w.add_argument("--approve", default="deny", choices=["deny", "prompt"])
    w.add_argument("--workdir", default="hannibal_watch")
    w.set_defaults(func=cmd_watch)

    v = sub.add_parser("verify-audit", help="verify the audit hash-chain")
    v.add_argument("path", help="run directory or path to audit.log")
    v.set_defaults(func=cmd_verify)

    rep = sub.add_parser("report", help="print findings + graph from a run")
    rep.add_argument("path", help="run directory")
    rep.add_argument("--html", nargs="?", const=True, default=None,
                     metavar="FILE",
                     help="write a self-contained HTML report (default: "
                          "<run>/report.html)")
    rep.set_defaults(func=cmd_report)

    an = sub.add_parser("analyze",
                        help="map discovered services to known weaknesses (advisory)")
    an.add_argument("path", help="run directory")
    an.set_defaults(func=cmd_analyze)
    return p


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(BANNER)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
