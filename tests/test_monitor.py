"""Tests for continuous monitor mode (hannibal/monitor.py).

The behaviour that matters — and that plain ``watch`` does not have — is that
the baseline survives the process. These tests prove: a stable fingerprint, a
diff that separates new from ongoing from resolved, persistence across separate
MonitorState instances, working alert sinks (including a webhook that tolerates
failure), and a full restart that resumes the baseline instead of re-alerting.
"""
import json
import os
import tempfile
import unittest

from hannibal.types import Finding
from hannibal.config import RunConfig
from hannibal.monitor import (
    finding_fingerprint, MonitorState, Alert,
    ConsoleSink, JsonlSink, WebhookSink, MultiSink, run_monitor,
)


def F(kind, target, summary="", **data):
    return Finding(kind=kind, target=target, summary=summary, data=data)


class FingerprintTest(unittest.TestCase):
    def test_same_finding_same_fingerprint(self):
        a = F("service", "10.0.0.1:22", "OpenSSH 8.9")
        b = F("service", "10.0.0.1:22", "OpenSSH 8.9 (rescan)")
        # summary differs, identity does not
        self.assertEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_different_target_differs(self):
        self.assertNotEqual(
            finding_fingerprint(F("host", "10.0.0.1")),
            finding_fingerprint(F("host", "10.0.0.2")))

    def test_two_vulns_on_one_endpoint_differ(self):
        a = F("vuln", "http://10.0.0.1/", template="cve-a", severity="high")
        b = F("vuln", "http://10.0.0.1/", template="cve-b", severity="high")
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))


class StatePersistenceTest(unittest.TestCase):
    def test_baseline_survives_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.sqlite")
            findings = [F("host", "10.0.0.1"), F("service", "10.0.0.1:22")]

            s1 = MonitorState(path)
            run = s1.next_run()
            cs = s1.diff(findings, run)
            self.assertEqual(len(cs.new), 2)      # first time: both new
            self.assertEqual(len(cs.ongoing), 0)
            s1.commit(findings, run, 1000.0)
            s1.record_run(run, 1000.0, len(findings), len(cs.new), 0)
            s1.close()

            # a brand-new instance (as a restarted process would be)
            s2 = MonitorState(path)
            self.assertEqual(s2.run_count(), 1)
            cs2 = s2.diff(findings, s2.next_run())
            self.assertEqual(len(cs2.new), 0)     # nothing new after restart
            self.assertEqual(len(cs2.ongoing), 2)
            s2.close()

    def test_new_ongoing_resolved(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.sqlite")
            st = MonitorState(path)

            base = [F("host", "10.0.0.1"), F("port", "10.0.0.1:80")]
            st.commit(base, 1, 1000.0)

            # next run: 80 gone, a new vuln appears, host persists
            nxt = [F("host", "10.0.0.1"),
                   F("vuln", "http://10.0.0.1/", template="php-rce",
                     severity="high")]
            cs = st.diff(nxt, 2)
            kinds_new = sorted(f.kind for f in cs.new)
            self.assertEqual(kinds_new, ["vuln"])
            self.assertEqual([f.kind for f in cs.ongoing], ["host"])
            self.assertEqual([r["kind"] for r in cs.resolved], ["port"])
            st.close()


class SinkTest(unittest.TestCase):
    def _alert(self):
        return Alert("new", "abc123", "vuln", "http://10.0.0.1/",
                     "PHP CGI RCE", "high", 2, 1000.0)

    def test_jsonl_sink_appends_json_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "alerts.jsonl")
            sink = JsonlSink(path)
            sink.emit(self._alert())
            sink.emit(self._alert())
            lines = open(path).read().strip().splitlines()
            self.assertEqual(len(lines), 2)
            rec = json.loads(lines[0])
            self.assertEqual(rec["change"], "new")
            self.assertEqual(rec["severity"], "high")
            self.assertIn("iso", rec)

    def test_webhook_posts_payload(self):
        captured = {}

        def fake_opener(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            return None

        WebhookSink("http://example.test/hook", opener=fake_opener).emit(self._alert())
        self.assertEqual(captured["url"], "http://example.test/hook")
        self.assertTrue(captured["body"]["text"].startswith("Hannibal:"))
        self.assertEqual(captured["body"]["kind"], "vuln")

    def test_webhook_failure_does_not_raise(self):
        def boom(req, timeout=None):
            raise OSError("connection refused")

        msgs = []
        sink = WebhookSink("http://down.test/hook", opener=boom, log=msgs.append)
        sink.emit(self._alert())   # must not raise
        self.assertTrue(any("webhook delivery failed" in m for m in msgs))


class RunMonitorTest(unittest.TestCase):
    def _cfg(self, workdir):
        return RunConfig(objective="map", scope=["10.10.10.5"],
                         backend="mock", quiet=True, workdir=workdir)

    def test_first_run_all_new_then_steady(self):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state.sqlite")
            cfg = self._cfg(os.path.join(d, "runs"))
            alerts = []
            sink = JsonlSink(os.path.join(d, "a.jsonl"))
            res = run_monitor(cfg, state, MultiSink([sink]), cycles=2,
                              now=lambda: 1000.0, sleep=lambda s: None,
                              log=alerts.append)
            self.assertEqual(len(res), 2)
            self.assertGreater(res[0].new, 0)      # first run establishes baseline
            self.assertEqual(res[1].new, 0)        # deterministic sim: nothing new
            self.assertEqual(res[1].resolved, 0)

    def test_restart_resumes_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state.sqlite")
            cfg = self._cfg(os.path.join(d, "runs"))

            first = run_monitor(cfg, state, MultiSink([]), cycles=1,
                                now=lambda: 1000.0, sleep=lambda s: None,
                                log=lambda m: None)
            self.assertGreater(first[0].new, 0)

            # a completely separate invocation, same state file
            second = run_monitor(cfg, state, MultiSink([]), cycles=1,
                                 now=lambda: 2000.0, sleep=lambda s: None,
                                 log=lambda m: None)
            self.assertEqual(second[0].new, 0)     # the whole point vs watch
            self.assertEqual(second[0].run, 2)     # run numbering persisted


if __name__ == "__main__":
    unittest.main()
