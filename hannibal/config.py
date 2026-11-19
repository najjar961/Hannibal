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
    max_rounds: int = 6
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

    # output
    quiet: bool = False                   # suppress per-step console logging
    fresh: bool = True                    # clear prior findings/audit in workdir at start

    def summary(self) -> str:
        mode = "EXECUTE" if self.execute else "DRY-RUN"
        return (f"objective={self.objective!r} scope={self.scope} "
                f"backend={self.backend} mode={mode} workers={self.workers}")
