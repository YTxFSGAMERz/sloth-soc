"""Tests for configuration loading and loopback host guardrails."""

import pytest
from pydantic import ValidationError

from sloth_soc.config import LLMConfig, load_config


def test_default_config():
    cfg = load_config(None)
    assert cfg.host_label == "lab-vps"
    assert cfg.timezone == "UTC"
    assert cfg.llm.host == "http://127.0.0.1:11434"
    assert cfg.llm.backend == "ollama"
    assert cfg.llm.allow_remote is False


def test_loopback_validation():
    # Loopback IP should pass
    c1 = LLMConfig(host="http://127.0.0.1:11434")
    assert c1.host == "http://127.0.0.1:11434"

    # localhost should pass
    c2 = LLMConfig(host="http://localhost:11434")
    assert c2.host == "http://localhost:11434"

    # IPv6 loopback should pass
    c3 = LLMConfig(host="http://[::1]:11434")
    assert "[::1]" in c3.host

    # Remote hosts MUST be rejected when allow_remote=False
    with pytest.raises(ValidationError):
        LLMConfig(host="http://api.openai.com/v1", allow_remote=False)

    with pytest.raises(ValidationError):
        LLMConfig(host="http://192.168.1.100:11434", allow_remote=False)

    # Remote host passes when allow_remote is explicitly True
    c4 = LLMConfig(host="http://remote.host:11434", allow_remote=True)
    assert c4.host == "http://remote.host:11434"


def test_load_example_config(tmp_path):
    yaml_content = """
host_label: test-host
timezone: UTC
llm:
  backend: ollama
  host: http://127.0.0.1:11434
  model: gemma4:e2b
"""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml_content, encoding="utf-8")

    cfg = load_config(cfg_file)
    assert cfg.host_label == "test-host"
    assert cfg.llm.model == "gemma4:e2b"
