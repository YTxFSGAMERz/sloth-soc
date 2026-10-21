"""Deterministic Fake LLM client for tests and offline CI."""

from __future__ import annotations

from typing import Any

from sloth_soc.llm.fallback import TemplateNarrator
from sloth_soc.schema import Brief, NarratorOutput


class FakeLLM:
    """Mock LLM client returning schema-compliant digests without network calls."""

    def __init__(self, model_name: str = "fake-gemma") -> None:
        self.model_name = model_name
        self._fallback = TemplateNarrator()
        self.call_count = 0

    def generate(
        self, brief: Brief, hardened: bool = True
    ) -> tuple[NarratorOutput, dict[str, Any]]:
        self.call_count += 1
        output = self._fallback.narrate(brief)

        meta = {
            "model": self.model_name,
            "narrator": "fake",
            "retries": 0,
            "latency_seconds": 0.05,
            "tokens_per_second": 120.0,
        }
        return output, meta
