"""Tests for the MCP server transport layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from failfast.server import check, explain, mcp, ping, scan

FIXTURES_DIR = str(Path(__file__).parent / "fixtures")


def test_mcp_metadata() -> None:
    """Verify the MCP server configuration metadata is set correctly."""
    assert mcp.name == "failfast-developer-mcp"


def test_mcp_registered_tools() -> None:
    """Ensure all expected tools are registered on the FastMCP instance."""
    if hasattr(mcp, "_tool_manager") and hasattr(mcp._tool_manager, "_tools"):
        tool_names = list(mcp._tool_manager._tools.keys())
    elif hasattr(mcp, "_tools"):
        tool_names = [tool.name for tool in mcp._tools]  # type: ignore[attr-defined]
    else:
        tool_names = []
    
    assert "ping" in tool_names
    assert "scan" in tool_names
    assert "scan_diff" in tool_names
    assert "check" in tool_names
    assert "explain" in tool_names


def test_ping_tool() -> None:
    """Verify ping tool returns active status."""
    res = ping()
    assert "alive" in res
    assert "FailFast" in res


def test_explain_tool() -> None:
    """Verify explain tool returns the correct rule explanation dictionary."""
    res = explain("FF-TIMEOUT")
    assert isinstance(res, dict)
    assert res["id"] == "FF-TIMEOUT"
    assert "why" in res
    assert "fix" in res
    assert "standard_refs" in res


def test_explain_tool_invalid() -> None:
    """Verify explain tool returns an error message for unknown rule."""
    res = explain("INVALID-RULE")
    assert "error" in res


def test_check_tool_valid() -> None:
    """Verify check tool returns category specific findings."""
    res = check(FIXTURES_DIR, "reliability")
    assert isinstance(res, dict)
    assert res["category"] == "reliability"
    assert "findings" in res
    assert len(res["findings"]) > 0


def test_check_tool_invalid_category() -> None:
    """Verify check tool handles invalid categories gracefully."""
    res = check(FIXTURES_DIR, "invalid-category")
    assert "error" in res


def test_scan_tool() -> None:
    """Verify scan tool runs analysis and returns expected scorecard structure."""
    res = scan(FIXTURES_DIR)
    assert isinstance(res, dict)
    assert res["verdict"] == "fail"
    assert "summary" in res
    assert "blockers" in res
    assert "warnings" in res
    assert len(res["blockers"]) > 0
