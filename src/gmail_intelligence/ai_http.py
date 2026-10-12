"""Loopback-only HTTP client for an already-running local Ollama-compatible server (M3). Stdlib only.

This is the ONLY classification module allowed to import `urllib`. It refuses any non-loopback host, ignores proxy
environment variables, caps the reply size, and never calls model-management endpoints (no pull/download).
"""
import json
import urllib.request

from gmail_intelligence.ai import AiError, is_loopback


class OllamaBackend:
    """Calls an already-running local Ollama-compatible server on a loopback address. Never pulls models."""

    def __init__(self, host, port, model, timeout=60):
        if not is_loopback(host):
            raise AiError("AI host must be a loopback address")
        self.url = f"http://{'[%s]' % host if ':' in host else host}:{int(port)}/api/generate"
        self.model, self.timeout = model, timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never via a proxy

    def complete(self, prompt):
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False, "format": "json"}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read(1_000_000).decode()).get("response", "")
        except (OSError, ValueError):
            raise AiError("could not get a reply from the local AI server (is it running? is the model installed?)") from None
