"""Tamper-evident audit log.

Every meaningful event — task created, scope decision, command executed, LLM
call, finding recorded, budget trip — is appended as one JSON line. Each entry
carries the SHA-256 of the previous entry, forming a hash chain: altering or
deleting any past line breaks verification of every line after it.

This is the kind of control a blue team or an auditor asks for first ("prove
what the tool actually did"), and it is cheap to add. `verify` recomputes the
chain; the CLI exposes it as `hannibal verify-audit`.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, List, Tuple

GENESIS = "0" * 64


def _canonical(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._prev = GENESIS
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # resume chain if the file already exists
        if os.path.exists(path):
            last = None
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = line
            if last:
                self._prev = hashlib.sha256(last.encode("utf-8")).hexdigest()

    def record(self, event: str, **fields: Any) -> str:
        """Append one event; returns the entry's hash."""
        with self._lock:
            entry = {
                "ts": round(time.time(), 3),
                "event": event,
                "data": fields,
                "prev": self._prev,
            }
            line = _canonical(entry)
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._prev = digest
            return digest

    @staticmethod
    def verify(path: str) -> Tuple[bool, str, int]:
        """Recompute the chain. Returns (ok, message, n_entries)."""
        prev = GENESIS
        n = 0
        with open(path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {i}: not valid JSON", n
                if entry.get("prev") != prev:
                    return False, f"line {i}: chain broken (prev hash mismatch)", n
                prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                n += 1
        return True, "audit chain intact", n
