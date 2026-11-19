"""Tamper-evident (and optionally tamper-proof) audit log.

Every meaningful event — task created, scope decision, command executed, LLM
call, finding recorded, budget trip — is appended as one JSON line. Each entry
carries the SHA-256 of the previous entry, forming a hash chain: altering or
deleting any past line breaks verification of every line after it.

The hash chain alone is tamper-*evident*, but not tamper-*proof*: anyone who
edits a line can recompute the chain, because the hash needs no secret. When an
audit key is supplied (the HANNIBAL_AUDIT_KEY environment variable), each entry
is additionally signed with a keyed HMAC. Now an attacker who edits the log
cannot forge valid signatures without the key, so the log becomes unforgeable
by anyone who doesn't hold it — the key is never written to the log, so having
the log is not enough.

`verify` recomputes the chain and, when given the key, checks every signature.
The CLI exposes it as `hannibal verify-audit` (it reads the same env var).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

GENESIS = "0" * 64


def _canonical(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _key_bytes(key: Optional[str | bytes]) -> Optional[bytes]:
    if not key:
        return None
    return key.encode("utf-8") if isinstance(key, str) else key


def _sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


class AuditLog:
    def __init__(self, path: str, key: Optional[str | bytes] = None):
        self.path = path
        self.key = _key_bytes(key)
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
            if self.key is not None:
                # sign the entry (without the sig field), then include the sig
                entry["sig"] = _sign(self.key, _canonical(entry))
            line = _canonical(entry)
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._prev = digest
            return digest

    @staticmethod
    def verify(path: str, key: Optional[str | bytes] = None) -> Tuple[bool, str, int]:
        """Recompute the chain and, if a key is given, check every signature.

        Returns (ok, message, n_entries).
        """
        kb = _key_bytes(key)
        prev = GENESIS
        n = 0
        any_signed = False
        checked_sigs = 0
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
                sig = entry.get("sig")
                if sig is not None:
                    any_signed = True
                    if kb is not None:
                        unsigned = {k: v for k, v in entry.items() if k != "sig"}
                        expected = _sign(kb, _canonical(unsigned))
                        if not hmac.compare_digest(sig, expected):
                            return False, f"line {i}: signature invalid (wrong key or forged)", n
                        checked_sigs += 1
                prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                n += 1

        if any_signed and kb is not None:
            msg = f"audit chain intact + {checked_sigs} signatures valid"
        elif any_signed and kb is None:
            msg = "audit chain intact (log is signed; pass the key to verify signatures)"
        else:
            msg = "audit chain intact (unsigned — set HANNIBAL_AUDIT_KEY to sign)"
        return True, msg, n
