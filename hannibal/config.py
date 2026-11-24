"""Run configuration — one object threaded through the whole orchestrator."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class RunConfig:
    objective: str
    scope: List[str]                      # allow-listed hosts / CIDRs
    backend: str = "mock"                 # mock | ollama | openai
    model: str = "qwen3:8b"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = ""

    # workers
    workers: int = 4

    # budget / kill-switch
    max_rounds: int = 8
    max_seconds: int = 600
    max_tokens: int = 200_000
    max_commands: int = 200

    # execution
    execute: bool = False                 # False = dry-run (never spawns real tools)
    command_timeout: int = 180            # per-command; real -sV over a WAN is slow
    max_phase_attempts: int = 2           # convergence guard: give up on a recon
    #                                       phase that makes no progress after N tries
    #                                       (e.g. a service scan that keeps timing out)
    #                                       instead of re-queuing it until the budget

    # detection
    semantic: bool = False                # second-stage model-based injection judge

    # paths
    workdir: str = "hannibal_run"
    db_path: str = ""                     # filled in at runtime if empty

    # safety
    require_scope: bool = True            # refuse to start with an empty scope
    # runtime egress backstop: route HTTP-speaking tools through an in-process
    # scope proxy so their on-the-wire destinations are enforced too (catches
    # redirects / runtime-resolved hosts the static guard can't see). Only has
    # an effect with --execute (dry-run spawns no real traffic).
    proxy: bool = False
    # Phase 2: also intercept HTTPS (terminate TLS with an on-the-fly minted
    # leaf) so response bodies feed the validator. Implies proxy. Needs the
    # optional `cryptography` package; without it the proxy logs a notice and
    # falls back to Phase-1 tunnelling (scope still enforced, bodies not seen).
    proxy_intercept: bool = False
    # rules of engagement: highest risk tier that runs without a human.
    # 1 = recon only (default). 2 = attack-tier wraiths run on their own —
    # only for your own isolated lab.
    max_auto_tier: int = 1
    # what happens to a command above max_auto_tier:
    #   "deny"   — held: logged, recorded in the report, never run (default)
    #   "prompt" — the operator is asked y/N on the console for each one
    approval: str = "deny"

    # output
    quiet: bool = False                   # suppress per-step console logging
    fresh: bool = True                    # clear prior findings/audit in workdir at start

    def summary(self) -> str:
        mode = "EXECUTE" if self.execute else "DRY-RUN"
        return (f"objective={self.objective!r} scope={self.scope} "
                f"backend={self.backend} mode={mode} workers={self.workers} "
                f"auto-tier≤{self.max_auto_tier} approval={self.approval}")
