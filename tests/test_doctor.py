"""Tests for doctor CLI command."""

from typer.testing import CliRunner

from sloth_soc.cli import app

runner = CliRunner()


def test_doctor_runs_without_crashing():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Sloth SOC" in result.stdout
    assert "Diagnostic Checks" in result.stdout
    assert "Python Version" in result.stdout
    assert "Network Status" in result.stdout
