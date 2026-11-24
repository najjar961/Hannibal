"""Minimal OpenAI-compatible chat client (stdlib only).

Works against anything that speaks the /chat/completions API: Ollama's OpenAI
endpoint (local, free), LM Studio, DeepSeek, OpenRouter, OpenAI. No third-party
dependencies — just urllib — so the whole project installs with nothing.

`chat_json` adds constrained decoding: it asks the server to emit JSON that
matches a schema (OpenAI-style `response_format`), so a small local model can't
drift into prose or a missing field. Servers vary in what they support, so it
steps down a ladder — json_schema → json_object → unconstrained — and the
caller's tolerant parser is the final net. This is the single biggest lever for
making weak local planners reliable: the model's *judgement* is what the
benchmark should measure, not its JSON hygiene.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class LLMError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status          # HTTP status, when the failure was one


class LLMClient:
    def __init__(self, base_url: str, model: str, api_key: str = "",
                 timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2,
             response_format: Optional[Dict[str, Any]] = None) -> str:
        url = f"{self.base_url}/chat/completions"
        body_obj: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if response_format is not None:
            body_obj["response_format"] = response_format
        payload = json.dumps(body_obj).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            raise LLMError(f"LLM HTTP {e.code}: {detail}", status=e.code) from e
        except urllib.error.URLError as e:
            raise LLMError(f"LLM request failed: {e}") from e
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected LLM response: {body}") from e

    def chat_json(self, messages: List[Dict[str, str]],
                  schema: Optional[Dict[str, Any]] = None,
                  name: str = "response", temperature: float = 0.2) -> str:
        """Chat with constrained JSON output, degrading gracefully.

        Tries the strongest constraint the server accepts, stepping down only on
        a client-side rejection of the format (4xx): a strict JSON schema, then
        plain JSON mode, then no constraint at all. Any other error (network, a
        5xx) is raised immediately rather than silently weakened.
        """
        attempts: List[Optional[Dict[str, Any]]] = []
        if schema is not None:
            attempts.append({"type": "json_schema",
                             "json_schema": {"name": name, "schema": schema}})
        attempts.append({"type": "json_object"})
        attempts.append(None)

        last: Optional[LLMError] = None
        for rf in attempts:
            try:
                return self.chat(messages, temperature=temperature,
                                 response_format=rf)
            except LLMError as e:
                last = e
                # step down only when the server refused *this format*
                if rf is not None and e.status in (400, 404, 422, 501):
                    continue
                raise
        raise last if last is not None else LLMError("no response_format worked")


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) for budgeting without a tokenizer."""
    return max(1, len(text) // 4)
