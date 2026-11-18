#!/usr/bin/env python3
"""Hannibal CLI.

Examples
--------
  # full loop, zero setup, nothing touches the network (deterministic sim):
  python3 hannibal.py run --objective "map my lab host" --scope 10.10.10.5,10.10.10.0/24

  # drive it with a local model via Ollama, still dry-run:
  python3 hannibal.py run -o "enumerate HTB box" -s 10.10.11.20 \
      --backend ollama --model qwen3:8b

  # actually execute the recon tools (only ever against authorized scope):
  python3 hannibal.py run -o "..." -s 10.10.10.5 --execute

  # prove what the tool did:
  python3 hannibal.py verify-audit hannibal_run
  python3 hannibal.py report hannibal_run
"""
from __future__ import annotations

import argparse
import sys

from hannibal import __version__
from hannibal.config import RunConfig
from hannibal.audit import AuditLog
from hannibal.orchestrator import Orchestrator


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
        execute=a.execute, workdir=a.workdir,
    )
    if not cfg.scope:
        print("error: --scope is required (the authorized targets)", file=sys.stderr)
        return 2
    if a.execute:
        print("⚠  EXECUTE mode: real recon tools will run against the scope above.")
        print("   Only proceed on systems you own or are authorized to test.\n")
    Orchestrator(cfg).run()
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    import os
    path = a.path if a.path.endswith(".log") else os.path.join(a.path, "audit.log")
    ok, msg, n = AuditLog.verify(path)
    status = "OK" if ok else "FAILED"
    print(f"[{status}] {msg} — {n} entries verified")
    return 0 if ok else 1


def cmd_report(a: argparse.Namespace) -> int:
    import os, json
    from hannibal.store import Store, to_mermaid
    db = os.path.join(a.path, "hannibal.sqlite")
    if not os.path.exists(db):
        print(f"no run found at {db}", file=sys.stderr)
        return 1
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
    r.add_argument("--max-rounds", type=int, default=6)
    r.add_argument("--max-seconds", type=int, default=600)
    r.add_argument("--max-tokens", type=int, default=200_000)
    r.add_argument("--max-commands", type=int, default=200)
    r.add_argument("--execute", action="store_true",
                   help="actually run the tools (default: deterministic dry-run)")
    r.add_argument("--workdir", default="hannibal_run")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify-audit", help="verify the audit hash-chain")
    v.add_argument("path", help="run directory or path to audit.log")
    v.set_defaults(func=cmd_verify)

    rep = sub.add_parser("report", help="print findings + graph from a run")
    rep.add_argument("path", help="run directory")
    rep.set_defaults(func=cmd_report)
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
