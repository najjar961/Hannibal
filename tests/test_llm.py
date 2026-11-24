"""Tests for constrained JSON decoding (hannibal/llm.py) and the autonomy
counters in the LLM brain (hannibal/brain.py).

The point of constrained decoding is that the benchmark measures the model's
*judgement*, not its JSON hygiene — so these pin two things: the client steps
down the response_format ladder exactly when a server refuses a format (and no
further), and the brain counts how often it fell back to the deterministic
rules, which is the number that keeps an autonomy claim honest.
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hannibal.llm import LLMClient, LLMError
from hannibal.brain import LLMBrain
from hannibal.types import Finding


class _FakeOpenAI(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        rf = body.get("response_format")
        rftype = rf.get("type") if isinstance(rf, dict) else None
        self.server.seen.append(rftype)                 # type: ignore[attr-defined]
        if self.server.force_status:                    # type: ignore[attr-defined]
            return self._send(self.server.force_status, {"error": "boom"})
        if rftype in self.server.reject:                # type: ignore[attr-defined]
            return self._send(400, {"error": {"message": f"{rftype} unsupported"}})
        self._send(200, {"choices": [{"message":
                   {"content": self.server.content}}]})  # type: ignore[attr-defined]

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ConstrainedDecodingTest(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAI)
        self.srv.seen = []
        self.srv.reject = set()
        self.srv.force_status = None
        self.srv.content = '{"ok": true}'
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        port = self.srv.server_address[1]
        self.client = LLMClient(f"http://127.0.0.1:{port}", "test-model")

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_schema_tried_first(self):
        out = self.client.chat_json([{"role": "user", "content": "hi"}],
                                    schema={"type": "object"}, name="x")
        self.assertEqual(out, '{"ok": true}')
        self.assertEqual(self.srv.seen[0], "json_schema")

    def test_steps_down_to_json_object(self):
        self.srv.reject = {"json_schema"}
        out = self.client.chat_json([{"role": "user", "content": "hi"}],
                                    schema={"type": "object"})
        self.assertEqual(out, '{"ok": true}')
        self.assertEqual(self.srv.seen, ["json_schema", "json_object"])

    def test_steps_down_to_unconstrained(self):
        self.srv.reject = {"json_schema", "json_object"}
        out = self.client.chat_json([{"role": "user", "content": "hi"}],
                                    schema={"type": "object"})
        self.assertEqual(out, '{"ok": true}')
        self.assertEqual(self.srv.seen, ["json_schema", "json_object", None])

    def test_server_error_is_not_swallowed(self):
        # a 500 is a real failure, not a format rejection — raise, don't step down
        self.srv.force_status = 500
        with self.assertRaises(LLMError) as cm:
            self.client.chat_json([{"role": "user", "content": "hi"}],
                                  schema={"type": "object"})
        self.assertEqual(cm.exception.status, 500)
        self.assertEqual(len(self.srv.seen), 1)       # no step-down on 500


class _StubClient:
    """A fake LLMClient that returns canned chat_json outputs (or raises)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def chat_json(self, messages, schema=None, name="response", temperature=0.2):
        r = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        if isinstance(r, Exception):
            raise r
        return r


class BrainAutonomyTest(unittest.TestCase):
    SCOPE = ["10.0.0.1"]

    def test_valid_plan_counts_no_fallback(self):
        brain = LLMBrain(_StubClient([
            '{"done": false, "reason": "go", '
            '"objectives": [{"goal": "port scan on 10.0.0.1"}]}']), self.SCOPE)
        plan = brain.plan("map", [])
        self.assertFalse(plan.done)
        self.assertEqual(len(plan.objectives), 1)
        s = brain.stats()
        self.assertEqual(s["plan_calls"], 1)
        self.assertEqual(s["plan_fallbacks"], 0)

    def test_bad_json_counts_a_fallback(self):
        brain = LLMBrain(_StubClient(["not json at all"]), self.SCOPE)
        plan = brain.plan("map", [])        # falls back to rule_plan
        self.assertIsNotNone(plan)
        s = brain.stats()
        self.assertEqual(s["plan_calls"], 1)
        self.assertEqual(s["plan_fallbacks"], 1)

    def test_empty_commands_counts_a_fallback(self):
        brain = LLMBrain(_StubClient(['{"commands": []}']), self.SCOPE)
        specs = brain.decompose("port scan on 10.0.0.1", [], self.SCOPE)
        self.assertTrue(specs)              # rule fallback still produced work
        self.assertEqual(brain.stats()["decompose_fallbacks"], 1)

    def test_unhelpful_commands_count_as_augmented(self):
        # a 'service' objective but the model returned a non -sV command:
        # valid JSON, so not a hard fallback — but the phase needed topping up
        brain = LLMBrain(_StubClient([
            '{"commands": [{"binary": "nmap", "args": ["-sn", "10.0.0.1"], '
            '"targets": ["10.0.0.1"]}]}']), self.SCOPE)
        brain.decompose("service and version enumeration on 10.0.0.1", [], self.SCOPE)
        s = brain.stats()
        self.assertEqual(s["decompose_fallbacks"], 0)
        self.assertEqual(s["decompose_augmented"], 1)


if __name__ == "__main__":
    unittest.main()
