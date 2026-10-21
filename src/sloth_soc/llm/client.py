"""Local LLM client with loopback guardrail, retry loop, and fallback."""

from __future__ import annotations

import time
from typing import Any, Protocol

import httpx

from sloth_soc.config import SlothSocConfig
from sloth_soc.llm.fallback import TemplateNarrator
from sloth_soc.llm.prompts import SYSTEM_PROMPT, serialize_brief
from sloth_soc.llm.schema import DIGEST_SCHEMA
from sloth_soc.llm.validator import DigestValidator
from sloth_soc.schema import Brief, NarratorOutput


class LLMClient(Protocol):
    """Protocol for LLM narrators."""

    def generate(
        self, brief: Brief, hardened: bool = True
    ) -> tuple[NarratorOutput, dict[str, Any]]: ...


class OllamaClient:
    """Client for local Ollama server running on loopback with grounding validator."""

    def __init__(self, config: SlothSocConfig | None = None) -> None:
        self.cfg = config or SlothSocConfig()
        self.validator = DigestValidator()
        self.fallback = TemplateNarrator()

    def generate(
        self, brief: Brief, hardened: bool = True
    ) -> tuple[NarratorOutput, dict[str, Any]]:
        """Generate structured digest with validation, retry, and template fallback."""
        start_time = time.perf_counter()
        retries = 0
        prompt_text = serialize_brief(brief, hardened=hardened)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ]

        payload = {
            "model": self.cfg.llm.model,
            "messages": messages,
            "stream": False,
            "format": DIGEST_SCHEMA,
            "think": False,
            "options": {
                "temperature": self.cfg.llm.temperature,
                "seed": 7,
                "num_ctx": self.cfg.llm.num_ctx,
                "num_predict": 700,
            },
        }

        # Attempt up to 3 tries (initial + 2 retries)
        last_error = ""
        while retries <= 2:
            try:
                resp = httpx.post(
                    f"{self.cfg.llm.host}/api/chat",
                    json=payload,
                    timeout=60.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("message", {}).get("content", "")

                    val_res = self.validator.validate(content, brief)
                    if val_res.is_valid and val_res.output:
                        latency = time.perf_counter() - start_time
                        eval_count = data.get("eval_count", 0)
                        eval_dur = data.get("eval_duration", 1) / 1e9
                        tps = (eval_count / eval_dur) if eval_dur > 0 else 0.0

                        meta = {
                            "model": self.cfg.llm.model,
                            "narrator": "llm",
                            "retries": retries,
                            "latency_seconds": round(latency, 2),
                            "tokens_per_second": round(tps, 1),
                        }
                        return val_res.output, meta

                    # Validation failed: append retry message with violated rule codes
                    retries += 1
                    last_error = f"Rules violated: {', '.join(val_res.violations)}"
                    messages.append({"role": "assistant", "content": content})
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"Your output was rejected: {last_error}. "
                                "Re-read the instructions, maintain exact grounding, and return strictly valid JSON."
                            ),
                        }
                    )
                    payload["messages"] = messages
                else:
                    last_error = f"HTTP {resp.status_code}"
                    break
            except Exception as e:
                last_error = str(e)
                break

        # Fallback to deterministic template narrator
        latency = time.perf_counter() - start_time
        output = self.fallback.narrate(brief)
        meta = {
            "model": self.cfg.llm.model,
            "narrator": "template",
            "retries": retries,
            "latency_seconds": round(latency, 2),
            "fallback_reason": last_error or "Validation failed after retries",
        }
        return output, meta
