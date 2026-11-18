"""Budget / kill-switch.

An autonomous loop with a language model in it must always be able to stop
itself. The Budget tracks wall-clock time, LLM tokens, rounds and commands, and
exposes a single `check()` the orchestrator consults before every round and
every command. `trip()` sets a hard manual stop (the kill switch).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class BudgetState:
    rounds: int = 0
    tokens: int = 0
    commands: int = 0
    elapsed: float = 0.0


class Budget:
    def __init__(self, max_rounds: int, max_seconds: int, max_tokens: int,
                 max_commands: int):
        self.max_rounds = max_rounds
        self.max_seconds = max_seconds
        self.max_tokens = max_tokens
        self.max_commands = max_commands
        self._start = time.time()
        self._lock = threading.Lock()
        self.rounds = 0
        self.tokens = 0
        self.commands = 0
        self._tripped: Optional[str] = None

    # -- counters (thread-safe; wraiths run in parallel) --------------------
    def add_tokens(self, n: int) -> None:
        with self._lock:
            self.tokens += max(0, n)

    def add_command(self) -> None:
        with self._lock:
            self.commands += 1

    def next_round(self) -> None:
        with self._lock:
            self.rounds += 1

    def trip(self, reason: str = "manual kill switch") -> None:
        with self._lock:
            self._tripped = reason

    # -- the gate -----------------------------------------------------------
    def check(self) -> Optional[str]:
        """Return a stop reason, or None if there is budget left."""
        with self._lock:
            if self._tripped:
                return self._tripped
            if time.time() - self._start >= self.max_seconds:
                return f"time budget exhausted (>{self.max_seconds}s)"
            if self.rounds >= self.max_rounds:
                return f"round budget exhausted ({self.max_rounds})"
            if self.tokens >= self.max_tokens:
                return f"token budget exhausted ({self.max_tokens})"
            if self.commands >= self.max_commands:
                return f"command budget exhausted ({self.max_commands})"
            return None

    def state(self) -> BudgetState:
        with self._lock:
            return BudgetState(self.rounds, self.tokens, self.commands,
                               round(time.time() - self._start, 2))
