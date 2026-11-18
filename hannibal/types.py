"""Shared data types passed between the orchestrator, the brain and the workers.

Keeping these as small frozen dataclasses makes the whole pipeline easy to
reason about: the brain returns Plans and CommandSpecs, the workers turn
CommandSpecs into Findings, and Findings feed back into the next Plan.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class GeneralObjective:
    """A mid-level goal the commander hands to a general."""
    goal: str
    rationale: str = ""


@dataclass(frozen=True)
class CommandSpec:
    """One concrete recon command a wraith should run.

    `targets` is the explicit list of hosts/networks the command touches. The
    scope guard checks it *and* re-parses the raw args, so a brain that forgets
    to fill this in cannot smuggle an out-of-scope target through.
    """
    binary: str
    args: List[str]
    targets: List[str]
    rationale: str = ""

    def as_cmdline(self) -> str:
        return " ".join([self.binary, *self.args])


@dataclass(frozen=True)
class Plan:
    """The commander's decision for one round."""
    done: bool
    reason: str
    objectives: List[GeneralObjective] = field(default_factory=list)


@dataclass
class Finding:
    """A structured fact learned from a command, plus provenance.

    `suspicious` is set when the source output tripped the injection scanner,
    so downstream code never treats quarantined content as trusted.
    """
    kind: str                      # host | port | service | web | note
    target: str                    # the host/endpoint it pertains to
    summary: str                   # one-line human summary
    data: Dict[str, Any] = field(default_factory=dict)
    source_task: Optional[int] = None
    parent_target: Optional[str] = None   # for the findings graph
    suspicious: bool = False
    ts: float = field(default_factory=time.time)

    def to_row(self) -> Dict[str, Any]:
        d = asdict(self)
        d["data"] = self.data
        return d


@dataclass
class Task:
    """A unit of work in the SQLite queue (always a wraith command)."""
    id: int
    round: int
    spec: CommandSpec
    status: str = "pending"        # pending | running | done | blocked | error
    result: str = ""
