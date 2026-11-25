"""Run the continuous monitor as an unattended, signal-aware service.

``run_monitor`` is the loop; this module is the thin layer that makes it behave
like a daemon:

  * **Graceful shutdown.** SIGTERM (what ``systemd stop`` / a container stop
    sends) and SIGINT (Ctrl-C) set a stop flag instead of killing the process
    mid-scan. The loop finishes the campaign it is in, writes its state, and
    exits cleanly — so the baseline is never left half-written.
  * **Timestamped logging**, optionally tee'd to a file, so a background run
    leaves an audit trail even when no terminal is attached.

Deployment recipes (systemd unit, Windows Task Scheduler / NSSM) live under
``deploy/``. Everything here is stdlib-only.
"""
from __future__ import annotations

import signal
import threading
import time
from typing import Callable, List, Optional

from .config import RunConfig
from .monitor import run_monitor, AlertSink, MonitorCycle


def make_logger(log_file: str = "",
                clock: Callable[[], float] = time.time) -> Callable[[str], None]:
    """A logger that prefixes an ISO timestamp and optionally appends to a file.

    stdout is line-buffered and flushed so `journalctl`/`tail -f` see each line
    as it happens.
    """
    def log(msg: str) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))
        line = f"{stamp} {msg}"
        print(line, flush=True)
        if log_file:
            try:
                with open(log_file, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                pass
    return log


def install_stop_handlers(event: threading.Event,
                          log: Callable[[str], None] = print) -> None:
    """Make SIGINT/SIGTERM request a graceful stop instead of killing us.

    Registered on a best-effort basis: a platform that lacks a given signal
    (notably SIGTERM handling on Windows) simply skips it. Must be called from
    the main thread.
    """
    def handler(signum, _frame):
        name = signal.Signals(signum).name if hasattr(signal, "Signals") else signum
        log(f"received {name} — finishing current run, then stopping")
        event.set()

    for signame in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):  # pragma: no cover - not main thread / unsupported
            pass


def serve(cfg: RunConfig, state_path: str, sinks: AlertSink,
          interval: float, cycles: int = 0,
          injector=None, heartbeat_path: str = "", log_file: str = "",
          stop_event: Optional[threading.Event] = None,
          log: Optional[Callable[[str], None]] = None) -> List[MonitorCycle]:
    """Run the monitor until a stop signal arrives (or ``cycles`` is reached).

    Returns the per-run results, same as ``run_monitor``.
    """
    log = log or make_logger(log_file)
    event = stop_event or threading.Event()
    install_stop_handlers(event, log)

    log(f"service starting — interval {interval}s, state {state_path}"
        + (f", heartbeat {heartbeat_path}" if heartbeat_path else ""))
    results = run_monitor(cfg, state_path, sinks, cycles=cycles,
                          interval=interval, injector=injector,
                          should_stop=event.is_set,
                          heartbeat_path=heartbeat_path, log=log)
    log(f"service stopped — {len(results)} run(s) completed")
    return results
