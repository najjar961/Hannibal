"""The orchestrator — the army hierarchy in motion.

Round loop:
  1. COMMANDER consults the findings and either declares the objective done or
     issues general-level objectives.
  2. Each GENERAL decomposes its objective into concrete, allow-listed commands.
  3. Commands are enqueued; a pool of WRAITH workers claim and run them in
     parallel, each one passing through the scope guard and command validator
     before anything executes, then parsing output into findings.
  4. Findings feed the next round. Budget is checked before every round and
     every command; the audit log records every decision.

Every control (scope, allowlist, budget, injection scan, audit) sits on the
path between "the model wants to" and "a command runs". That is the whole point.
"""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List

from .config import RunConfig
from .types import CommandSpec, Finding, Plan
from .audit import AuditLog
from .budget import Budget
from .scope import ScopeGuard
from .store import Store, to_mermaid
from .brain import Brain, MockBrain, LLMBrain, coverage_next
from .llm import LLMClient
from .semantic import LLMJudge
from . import commands as cmd
from .parse import parse


class Orchestrator:
    def __init__(self, cfg: RunConfig):
        self.cfg = cfg
        os.makedirs(cfg.workdir, exist_ok=True)
        if not cfg.db_path:
            cfg.db_path = os.path.join(cfg.workdir, "hannibal.sqlite")
        # each run starts clean: a re-run into the same workdir must not inherit
        # a previous run's findings or audit chain (that would short-circuit the
        # Commander on stale state and mix two runs' audit logs).
        if cfg.fresh:
            for stale in (cfg.db_path, os.path.join(cfg.workdir, "audit.log")):
                try:
                    if os.path.exists(stale):
                        os.remove(stale)
                except OSError:
                    pass
        self.store = Store(cfg.db_path)
        self.audit = AuditLog(os.path.join(cfg.workdir, "audit.log"))
        self.scope = ScopeGuard(cfg.scope)
        self.budget = Budget(cfg.max_rounds, cfg.max_seconds,
                             cfg.max_tokens, cfg.max_commands)
        self.brain: Brain = self._build_brain()
        self.judge = self._build_judge()
        self._print_lock = threading.Lock()
        self.stopped_reason = ""

    def _build_brain(self) -> Brain:
        if self.cfg.backend == "mock":
            return MockBrain()
        client = LLMClient(self.cfg.base_url, self.cfg.model, self.cfg.api_key,
                           self.cfg.command_timeout)
        return LLMBrain(client, self.cfg.scope)

    def _build_judge(self):
        """Second-stage semantic injection judge, only when a model is available."""
        if not self.cfg.semantic or self.cfg.backend == "mock":
            return None
        client = LLMClient(self.cfg.base_url, self.cfg.model, self.cfg.api_key,
                           self.cfg.command_timeout)
        return LLMJudge(client)

    def _log(self, msg: str) -> None:
        if self.cfg.quiet:
            return
        with self._print_lock:
            print(msg, flush=True)

    # -- worker -------------------------------------------------------------
    def _run_one(self, task) -> None:
        spec: CommandSpec = task.spec

        # 1. command allowlist
        verr = cmd.validate(spec)
        if verr:
            self.audit.record("command_blocked", task=task.id,
                              cmd=spec.as_cmdline(), reason=verr, control="allowlist")
            self.store.finish_task(task.id, "blocked", verr)
            self._log(f"  ⃠ [blocked] {spec.as_cmdline()} — {verr}")
            return

        # 2. scope guard
        decision = self.scope.check(spec.targets, spec.args)
        self.audit.record("scope_decision", task=task.id, cmd=spec.as_cmdline(),
                          allowed=decision.allowed, reason=decision.reason,
                          checked=decision.checked)
        if not decision.allowed:
            self.store.finish_task(task.id, "blocked", decision.reason)
            self._log(f"  ⃠ [out-of-scope] {spec.as_cmdline()} — {decision.reason}")
            return

        # 3. budget
        stop = self.budget.check()
        if stop:
            self.store.finish_task(task.id, "blocked", f"budget: {stop}")
            return
        self.budget.add_command()

        # 4. execute (or simulate)
        self.audit.record("command_exec", task=task.id, cmd=spec.as_cmdline(),
                          mode="execute" if self.cfg.execute else "dry-run")
        output = cmd.run(spec, self.cfg.execute, self.cfg.command_timeout)
        self.store.finish_task(task.id, "done", output)

        # 5. parse -> findings (+ injection scan on untrusted output)
        findings, sr = parse(spec, output, task.id)

        # 5b. second-stage semantic judge: only when the regex pass is clean,
        # so the model cost is paid only where it might catch something new
        if self.judge is not None and not sr.suspicious and self.judge.judge(output):
            sr.suspicious = True
            sr.hits.append("[semantic] intent-based injection (no trigger words)")
            for f in findings:
                f.suspicious = True
            self.audit.record("semantic_injection_flagged", task=task.id,
                              cmd=spec.as_cmdline())

        if sr.suspicious:
            self.audit.record("injection_flagged", task=task.id,
                              cmd=spec.as_cmdline(), hits=sr.hits)
            self._log(f"  ⚠ injection attempt in output of {spec.binary} "
                      f"→ quarantined (hits: {sr.hits})")
        for f in findings:
            self.store.add_finding(f)
            self.audit.record("finding", kind=f.kind, target=f.target,
                              summary=f.summary, suspicious=f.suspicious)
        tag = "⚑" if sr.suspicious else "✓"
        self._log(f"  {tag} {spec.binary} {' '.join(spec.targets)} "
                  f"→ {len(findings)} finding(s)")

    # -- main loop ----------------------------------------------------------
    def run(self) -> None:
        cfg = self.cfg
        self.audit.record("run_start", objective=cfg.objective, scope=cfg.scope,
                          backend=cfg.backend, execute=cfg.execute)
        self._log(f"\n⚔  HANNIBAL — {cfg.summary()}\n" + "─" * 60)

        while True:
            stop = self.budget.check()
            if stop:
                self.stopped_reason = stop
                break
            self.budget.next_round()
            rnd = self.budget.state().rounds
            findings = self.store.all_findings()

            plan = self.brain.plan(cfg.objective, findings)
            self.budget.add_tokens(self.brain.tokens_used() - self.budget.state().tokens)

            # coverage guard: a weak model can declare victory too early. If it
            # says done but the standard recon depth isn't reached, override and
            # keep going. (A strong model can still exceed the floor.)
            if plan.done:
                gap = coverage_next(findings)
                if gap is not None:
                    self.audit.record("coverage_guard", round=rnd,
                                      overrode_done=True, forced=gap.goal)
                    plan = Plan(False, f"coverage guard — {gap.goal} still pending",
                                [gap])

            self.audit.record("commander_plan", round=rnd, done=plan.done,
                              reason=plan.reason,
                              objectives=[o.goal for o in plan.objectives])
            self._log(f"\n[round {rnd}] Commander: {plan.reason}")
            if plan.done:
                self.stopped_reason = "objective complete"
                break

            # generals -> commands
            specs: List[CommandSpec] = []
            for obj in plan.objectives:
                self._log(f"  General ▸ {obj.goal}")
                specs.extend(self.brain.decompose(obj.goal, findings, cfg.scope))
            self.budget.add_tokens(self.brain.tokens_used() - self.budget.state().tokens)

            task_ids = [self.store.add_task(rnd, s) for s in specs]
            for tid, s in zip(task_ids, specs):
                self.audit.record("task_created", task=tid, round=rnd,
                                  cmd=s.as_cmdline())

            # wraiths run in parallel
            with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
                futures = []
                while True:
                    t = self.store.claim_task()
                    if t is None:
                        break
                    futures.append(pool.submit(self._run_one, t))
                for f in futures:
                    f.result()

        self._finish()

    def _finish(self) -> None:
        state = self.budget.state()
        counts = self.store.counts()
        # expose final metrics for the benchmark harness
        self.final_state = state
        self.final_counts = counts
        self.suspicious_findings = sum(
            1 for f in self.store.all_findings() if f.suspicious)
        self.audit.record("run_end", reason=self.stopped_reason,
                          rounds=state.rounds, commands=state.commands,
                          tokens=state.tokens, findings=sum(counts.values()))
        # write the findings graph
        graph = to_mermaid(self.store.all_findings())
        gpath = os.path.join(self.cfg.workdir, "findings_graph.mmd")
        with open(gpath, "w", encoding="utf-8") as fh:
            fh.write(graph)

        self._log("\n" + "─" * 60)
        self._log(f"stopped: {self.stopped_reason}")
        self._log(f"rounds={state.rounds} commands={state.commands} "
                  f"~tokens={state.tokens} elapsed={state.elapsed}s")
        self._log(f"findings: {counts}")
        self._log(f"graph → {gpath}")
        self._log(f"audit → {os.path.join(self.cfg.workdir, 'audit.log')} "
                  f"(verify with: hannibal verify-audit {self.cfg.workdir})")
        self.store.close()
