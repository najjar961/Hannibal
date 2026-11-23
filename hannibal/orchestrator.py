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
        # optional HMAC signing of the audit log (see audit.py); key from env so
        # it never lands on the command line or in the log itself
        self.audit = AuditLog(os.path.join(cfg.workdir, "audit.log"),
                              key=os.environ.get("HANNIBAL_AUDIT_KEY"))
        self.scope = ScopeGuard(cfg.scope)
        self.budget = Budget(cfg.max_rounds, cfg.max_seconds,
                             cfg.max_tokens, cfg.max_commands)
        self.brain: Brain = self._build_brain()
        self.judge = self._build_judge()
        self._print_lock = threading.Lock()
        self.stopped_reason = ""
        self._phase_attempts: dict = {}   # objective goal -> times issued

    def _note_inconclusive(self, goal: str) -> None:
        """Record a visible note that a recon phase gave up, so the report is
        honest about what was *attempted* but not resolved (not just silent)."""
        host = goal.split()[-1]
        self.store.add_finding(Finding(
            "note", f"inconclusive:{goal}", f"phase inconclusive — {goal}",
            {"phase": goal}, None, host))

    def _ask_approval(self, spec: CommandSpec, tier: int) -> bool:
        """Human-in-the-loop gate for commands above max_auto_tier."""
        if self.cfg.approval != "prompt":
            return False
        with self._print_lock:   # one question at a time across wraiths
            try:
                ans = input(f"\n  ⚔ approve tier-{tier} "
                            f"({cmd.TIER_NAMES.get(tier, '?')}) command?\n"
                            f"    {spec.as_cmdline()}\n    [y/N] ")
            except EOFError:      # no operator attached -> deny
                return False
        return ans.strip().lower() in ("y", "yes")

    def _note_held(self, spec: CommandSpec, tier: int, task_id: int) -> None:
        """Record a held command so the report shows what was NOT done, and the
        planner treats the phase as resolved instead of re-queuing it."""
        from urllib.parse import urlsplit
        t = (spec.targets or ["target"])[0]
        host = urlsplit(t).hostname if "://" in t else t
        self.store.add_finding(Finding(
            "note", f"held:{host}:{spec.binary}",
            f"awaiting approval — tier {tier}: {spec.as_cmdline()}",
            {"phase": "vulnscan" if spec.binary == "nuclei" else spec.binary,
             "status": "awaiting_approval", "tier": tier,
             "cmd": spec.as_cmdline()}, task_id, host))

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
        decision = self.scope.check(spec.targets, spec.args, binary=spec.binary)
        self.audit.record("scope_decision", task=task.id, cmd=spec.as_cmdline(),
                          allowed=decision.allowed, reason=decision.reason,
                          checked=decision.checked)
        if not decision.allowed:
            self.store.finish_task(task.id, "blocked", decision.reason)
            self._log(f"  ⃠ [out-of-scope] {spec.as_cmdline()} — {decision.reason}")
            return

        # 3. rules of engagement: commands above the auto tier need a human.
        # Checked after scope, so an out-of-scope command is never even offered
        # for approval.
        tier = cmd.tier_of(spec.binary)
        if tier > self.cfg.max_auto_tier:
            approved = self._ask_approval(spec, tier)
            self.audit.record("approval_decision", task=task.id,
                              cmd=spec.as_cmdline(), tier=tier,
                              mode=self.cfg.approval, approved=approved)
            if not approved:
                reason = (f"tier {tier} ({cmd.TIER_NAMES.get(tier, '?')}) "
                          f"needs approval — held")
                self.store.finish_task(task.id, "held", reason)
                self._note_held(spec, tier, task.id)
                self._log(f"  ⏸ [held] {spec.as_cmdline()} — {reason}")
                return

        # 4. budget
        stop = self.budget.check()
        if stop:
            self.store.finish_task(task.id, "blocked", f"budget: {stop}")
            return
        self.budget.add_command()

        # 5. execute (or simulate)
        self.audit.record("command_exec", task=task.id, cmd=spec.as_cmdline(),
                          mode="execute" if self.cfg.execute else "dry-run")
        output = cmd.run(spec, self.cfg.execute, self.cfg.command_timeout)
        self.store.finish_task(task.id, "done", output)

        # 6. parse -> findings (+ injection scan on untrusted output)
        findings, sr = parse(spec, output, task.id)

        # 6b. second-stage semantic judge: only when the regex pass is clean,
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

            # convergence guard: a phase that keeps reappearing with no progress
            # (classically a service scan that times out on a slow WAN host) would
            # otherwise be re-queued every round until the budget runs out. Cap
            # attempts per distinct objective; once exhausted, mark the phase
            # inconclusive and move on so the run converges instead of spinning.
            live_objs = []
            for obj in plan.objectives:
                self._phase_attempts[obj.goal] = self._phase_attempts.get(obj.goal, 0) + 1
                if self._phase_attempts[obj.goal] > cfg.max_phase_attempts:
                    self.audit.record("phase_inconclusive", round=rnd,
                                      objective=obj.goal,
                                      attempts=self._phase_attempts[obj.goal] - 1)
                    self._note_inconclusive(obj.goal)
                    continue
                live_objs.append(obj)

            if not live_objs:
                self.stopped_reason = "converged — remaining phases inconclusive"
                self._log("  (no further progress available — stopping)")
                break

            # generals -> commands
            specs: List[CommandSpec] = []
            for obj in live_objs:
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
