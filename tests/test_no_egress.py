"""Test enforcing strictly offline execution (no external network egress)."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest

from sloth_soc.config import SlothSocConfig
from sloth_soc.pipeline import run_synthetic_demo

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture
def enforce_no_egress(monkeypatch: pytest.MonkeyPatch):
    """Intercept socket connections to strictly forbid any non-loopback egress."""
    original_connect = socket.socket.connect

    def guarded_connect(sock_self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in LOOPBACK_HOSTS:
            raise AssertionError(
                f"ILLEGAL NETWORK EGRESS: Attempted connection to non-loopback address: {host!r}. "
                "Sloth SOC must be strictly offline at runtime."
            )
        return original_connect(sock_self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


def test_pipeline_runtime_no_egress(enforce_no_egress, tmp_path: Path):
    """Verify that end-to-end pipeline execution triggers zero external network traffic."""
    out_dir = tmp_path / "digests"
    synth_dir = tmp_path / "synthetic"

    cfg = SlothSocConfig()
    # Host is loopback
    assert "127.0.0.1" in cfg.llm.host or "localhost" in cfg.llm.host

    res = run_synthetic_demo(
        seed=42,
        days=2,
        no_llm=True,
        out_dir=out_dir,
        synth_dir=synth_dir,
        config=cfg,
    )

    assert res["brief"] is not None
    assert len(res["saved_files"]) == 3
