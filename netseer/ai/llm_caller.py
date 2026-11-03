"""LLM backends returning JSON that should match the ExplainOutput schema (brief §7)."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Protocol

import httpx

from netseer.src.config import app_config, get_setting
from netseer.src.keystore import get_key

TIMEOUT_S = 300
# num_thread 4: on the 6-core box 6 threads fell to 1.8 tok/s under contention, 4 gave 8.8 (progress.md step 0).
# num_predict caps a reply that loops inside the JSON grammar; a cut reply fails the schema check and is retried once.
OPTIONS = {"temperature": 0.2, "num_ctx": 4096, "num_thread": 4, "num_predict": 900}


class LLMError(RuntimeError):
    """The model could not be reached or returned nothing usable."""


class Stopped(LLMError):
    """The user stopped the explanation."""


class LLMBackend(Protocol):
    """Anything that turns a system + user prompt into JSON text constrained by `schema`."""

    model: str

    def chat(self, system: str, user: str, schema: dict, stop: threading.Event | None = None) -> str:
        """Return the model's reply (a JSON document as text); raise Stopped once `stop` is set."""
        ...


class OllamaBackend:
    """Local Ollama (`/api/chat`, streamed so it can be stopped, JSON-schema `format`)."""

    def __init__(self, model: str, url: str | None = None) -> None:
        self.model = model
        self.url = (url or app_config("ollama_url")).rstrip("/")

    def chat(self, system: str, user: str, schema: dict, stop: threading.Event | None = None) -> str:
        """Ask Ollama for one reply constrained by `schema`; closing the stream on `stop` makes Ollama stop too."""
        body = {"model": self.model, "stream": True, "format": schema, "options": OPTIONS,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        parts = []
        try:
            with httpx.stream("POST", f"{self.url}/api/chat", json=body, timeout=TIMEOUT_S) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if stop is not None and stop.is_set():
                        raise Stopped("Stopped.")
                    if line:
                        chunk = json.loads(line)
                        parts.append(chunk["message"]["content"])
                        if chunk.get("done"):
                            break
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise LLMError(f"Ollama ({self.model}) failed: {exc}") from exc
        return "".join(parts)


class CloudBackend:
    """Opt-in OpenAI-compatible API (`/chat/completions` with a JSON-schema response format) and the user's key.
    The evidence package leaves the machine, so it is used only when the administrator selects it."""

    def __init__(self, model: str, url: str, key: str) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.key = key

    def chat(self, system: str, user: str, schema: dict, stop: threading.Event | None = None) -> str:
        """Ask the cloud model for one reply constrained by `schema` (not streamed: `stop` is checked by the caller)."""
        body = {"model": self.model, "temperature": OPTIONS["temperature"],
                "response_format": {"type": "json_schema", "json_schema": {"name": "explain_output", "schema": schema}},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            r = httpx.post(f"{self.url}/chat/completions", json=body, timeout=TIMEOUT_S,
                           headers={"Authorization": f"Bearer {self.key}"})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"Cloud LLM ({self.model}) failed: {exc}") from exc


def backend_for(conn: sqlite3.Connection) -> LLMBackend:
    """The backend chosen in the NetSeer configuration (cloud only with a URL, model and key)."""
    if get_setting(conn, "llm_backend") == "cloud":
        key = get_key(conn, "cloud_llm")
        if not (key and get_setting(conn, "cloud_url") and get_setting(conn, "cloud_model")):
            raise LLMError("The cloud LLM is selected but its URL, model or API key is missing (Settings).")
        return CloudBackend(get_setting(conn, "cloud_model"), get_setting(conn, "cloud_url"), key)
    return OllamaBackend(get_setting(conn, "llm_model"))
