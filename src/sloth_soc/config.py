"""Configuration models and loader for Sloth SOC.

Strictly enforces loopback-only LLM host unless allow_remote is explicitly set.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, model_validator


class SourcePaths(BaseModel):
    paths: list[str] = Field(default_factory=list)


class SourcesConfig(BaseModel):
    sshd: SourcePaths = Field(default_factory=lambda: SourcePaths(paths=["/var/log/auth.log*"]))
    nginx: SourcePaths = Field(
        default_factory=lambda: SourcePaths(paths=["/var/log/nginx/access.log*"])
    )
    fail2ban: SourcePaths = Field(
        default_factory=lambda: SourcePaths(paths=["/var/log/fail2ban.log*"])
    )
    ufw: SourcePaths = Field(default_factory=lambda: SourcePaths(paths=["/var/log/ufw.log*"]))


class RulesConfig(BaseModel):
    r1_fail_5m: int = 10
    r2_users: int = 8
    r3_probes: int = 5
    r4_ports: int = 15


class TabPFNConfig(BaseModel):
    enabled: bool = False
    model_version: str = "default"


class DetectConfig(BaseModel):
    attention_budget: int = 5
    rules: RulesConfig = Field(default_factory=RulesConfig)
    tabpfn: TabPFNConfig = Field(default_factory=TabPFNConfig)


class LLMConfig(BaseModel):
    backend: Literal["ollama", "openai_compatible"] = "ollama"
    host: str = "http://127.0.0.1:11434"
    model: str = "gemma4:e4b"
    temperature: float = 0.0
    num_ctx: int = 8192
    think: bool = False
    allow_remote: bool = False

    @model_validator(mode="after")
    def verify_loopback(self) -> LLMConfig:
        if self.allow_remote:
            return self

        parsed = urlparse(self.host)
        hostname = parsed.hostname or self.host

        # Allow localhost
        if hostname.lower() == "localhost":
            return self

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback:
                return self
        except ValueError:
            pass

        raise ValueError(
            f"Non-loopback LLM host '{self.host}' rejected for offline safety. "
            "Set allow_remote: true if you intentionally wish to allow remote connections."
        )


class OutputConfig(BaseModel):
    dir: str = "digests"
    formats: list[Literal["md", "html", "json"]] = Field(
        default_factory=lambda: ["md", "html", "json"]
    )
    tone: Literal["plain", "sloth"] = "plain"


class SlothSocConfig(BaseModel):
    host_label: str = "lab-vps"
    timezone: str = "UTC"
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    detect: DetectConfig = Field(default_factory=DetectConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def load_config(config_path: str | Path | None = None) -> SlothSocConfig:
    """Load and validate configuration from YAML, falling back to defaults."""
    if config_path is None:
        default_candidates = [Path("config.yaml"), Path("config.yml")]
        for cand in default_candidates:
            if cand.exists():
                config_path = cand
                break

    if config_path is None or not Path(config_path).exists():
        return SlothSocConfig()

    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return SlothSocConfig.model_validate(data)
