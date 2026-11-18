"""Minimal OpenAI-compatible chat client (stdlib only).

Works against anything that speaks the /chat/completions API: Ollama's OpenAI
endpoint (local, free), LM Studio, DeepSeek, OpenRouter, OpenAI. No third-party
dependencies — just urllib — so the whole project installs with nothing.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import List, Dict


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, base_url: str, model: str, api_key: str = "",
                 timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise LLMError(f"LLM request failed: {e}") from e
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LLMError(f"unexpected LLM response: {body}") from e


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) for budgeting without a tokenizer."""
    return max(1, len(text) // 4)
