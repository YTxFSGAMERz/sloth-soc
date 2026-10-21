"""LLM narrator components: client, validator, prompts, fallback, and fake."""

from sloth_soc.llm.client import LLMClient, OllamaClient
from sloth_soc.llm.fake import FakeLLM
from sloth_soc.llm.fallback import TemplateNarrator
from sloth_soc.llm.prompts import SYSTEM_PROMPT, serialize_brief
from sloth_soc.llm.schema import DIGEST_SCHEMA
from sloth_soc.llm.validator import DigestValidator, ValidationResult

__all__ = [
    "DIGEST_SCHEMA",
    "DigestValidator",
    "FakeLLM",
    "LLMClient",
    "OllamaClient",
    "SYSTEM_PROMPT",
    "TemplateNarrator",
    "ValidationResult",
    "serialize_brief",
]
