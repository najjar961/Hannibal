"""Tests for the daemon/service layer (hannibal/service.py + the service hooks
added to run_monitor): graceful stop, interruptible sleep, heartbeat, logging.

Signal delivery itself is not unit-tested (it is OS-level and flaky in CI);
instead the stop *mechanism* that signals drive — a flag the loop checks — is
tested directly, which is what actually governs shutdown behaviour.
"""
import json
import os
import signal
import tempfile
import threading
import unittest

from hannibal.config import RunConfig
from hannibal.monitor import (run_monitor, MultiSink,
                              _interruptible_sleep, _write_heartbeat)
from hannibal.service import serve, make_logger, install_stop_handlers


def cfg(workdir):
    return RunConfig(objective="map", scope=["10.10.10.5"],
                     backend="mock", quiet=True, workdir=workdir)


class InterruptibleSleepTest(unittest.TestCase):
    def test_sleeps_full_when_no_stop(self):
        slept = []
        _interruptible_sleep(5.0, None, slept.append)
        self.assertEqual(slept, [5.0])

    def test_wakes_early_and_slices_when_stopping(self):
        slept = []
        calls = {"n": 0}

        def stop():
            calls["n"] += 1
            return calls["n"] > 2        # stop after a couple of slices

        _interruptible_sleep(10.0, stop, slept.append)
        self.assertLess(sum(slept), 10.0)            # did not sleep the full interval
        self.assertTrue(all(s <= 1.0 for s in slept))  # sliced, so stop is responsive


class GracefulStopTest(unittest.TestCase):
    def test_should_stop_halts_the_loop(self):
        with tempfile.TemporaryDirectory() as d:
            calls = []

            def stop():
                calls.append(1)
                return len(calls) > 1    # False once, True after the first run

            res = run_monitor(cfg(os.path.join(d, "runs")),
                              os.path.join(d, "s.sqlite"), MultiSink([]),
                              cycles=0, interval=0.0, should_stop=stop,
                              now=lambda: 1.0, sleep=lambda s: None,
                              log=lambda m: None)
            self.assertEqual(len(res), 1)   # ran once, then stopped despite cycles=0


class HeartbeatTest(unittest.TestCase):
    def test_heartbeat_written_each_run(self):
        with tempfile.TemporaryDirectory() as d:
            hb = os.path.join(d, "beat", "hb.json")   # nested dir is created
            run_monitor(cfg(os.path.join(d, "runs")), os.path.join(d, "s.sqlite"),
                        MultiSink([]), cycles=1, heartbeat_path=hb,
                        now=lambda: 1000.0, sleep=lambda s: None,
                        log=lambda m: None)
            data = json.load(open(hb))
            self.assertEqual(data["run"], 1)
            self.assertGreater(data["total"], 0)
            self.assertIn("pid", data)
            self.assertIn("iso", data)


class LoggerTest(unittest.TestCase):
    def test_timestamps_and_tees_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            lf = os.path.join(d, "svc.log")
            log = make_logger(lf, clock=lambda: 1000.0)
            log("hello world")
            content = open(lf).read()
            self.assertIn("hello world", content)
            self.assertIn("1970-01-01T00:16:40Z", content)   # gmtime(1000)


class ServeTest(unittest.TestCase):
    def setUp(self):
        # serve() installs SIGINT/SIGTERM handlers; save and restore them so the
        # test runner's own handling is left untouched.
        self._saved = {}
        for name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, name, None)
            if sig is not None:
                self._saved[sig] = signal.getsignal(sig)

    def tearDown(self):
        for sig, handler in self._saved.items():
            signal.signal(sig, handler)

    def test_serve_runs_bounded_cycles(self):
        with tempfile.TemporaryDirectory() as d:
            res = serve(cfg(os.path.join(d, "runs")), os.path.join(d, "s.sqlite"),
                        MultiSink([]), interval=0.0, cycles=1,
                        stop_event=threading.Event(), log=lambda m: None)
            self.assertEqual(len(res), 1)

    def test_preset_stop_event_prevents_any_run(self):
        with tempfile.TemporaryDirectory() as d:
            ev = threading.Event()
            ev.set()                     # already stopped before we begin
            res = serve(cfg(os.path.join(d, "runs")), os.path.join(d, "s.sqlite"),
                        MultiSink([]), interval=0.0, cycles=0,
                        stop_event=ev, log=lambda m: None)
            self.assertEqual(len(res), 0)

    def test_install_handlers_main_thread(self):
        ev = threading.Event()
        install_stop_handlers(ev, log=lambda m: None)   # must not raise


if __name__ == "__main__":
    unittest.main()
