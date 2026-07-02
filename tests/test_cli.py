"""Tests for the Click CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from failfast.cli import main

FIXTURES_DIR = str(Path(__file__).parent / "fixtures")


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "failfast" in result.output.lower()


def test_cli_explain_valid() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "FF-TIMEOUT"])
    assert result.exit_code == 0
    assert "HTTP Request Timeout" in result.output
    assert "OWASP" in result.output


def test_cli_explain_invalid() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "INVALID-CODE"])
    assert result.exit_code == 1
    assert "Unknown finding ID" in result.output


def test_cli_scan_json() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", FIXTURES_DIR, "--format", "json"])
    # Should exit with non-zero code (1) because blockers are found in fixtures
    assert result.exit_code == 1
    
    # Parse output as JSON
    data = json.loads(result.output)
    assert data["verdict"] == "fail"
    assert "reliability" in data["categories"]
    assert len(data["findings"]) > 0


def test_cli_scan_rich() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", FIXTURES_DIR, "--format", "rich"])
    assert result.exit_code == 1
    assert "BLOCKERS" in result.output
    assert "WARNINGS" in result.output
    assert "Verdict: FAIL" in result.output


def test_cli_check_json() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["check", FIXTURES_DIR, "--category", "reliability", "--format", "json"])
    assert result.exit_code == 0  # check command returns 0 on success of command execution
    
    data = json.loads(result.output)
    assert data["category"] == "reliability"
    assert data["verdict"] == "fail"
    assert len(data["findings"]) > 0


def test_cli_check_rich() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["check", FIXTURES_DIR, "--category", "reliability", "--format", "rich"])
    assert result.exit_code == 0
    assert "Category: reliability" in result.output
    assert "Verdict: FAIL" in result.output
