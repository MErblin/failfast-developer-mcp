"""Tests for all reporters: JSON, Markdown, and SARIF."""

from __future__ import annotations

import json

import pytest

from failfast.models import (
    Category,
    CategoryResult,
    Finding,
    Scorecard,
    Severity,
    Verdict,
)
from failfast.reporters.json_reporter import to_dict, to_json
from failfast.reporters.markdown_reporter import to_markdown
from failfast.reporters.sarif_reporter import to_sarif, to_sarif_dict


@pytest.fixture
def sample_scorecard() -> Scorecard:
    """A scorecard with one blocker and one warning for testing reporters."""
    blocker = Finding(
        id="FF-TIMEOUT-0042",
        title="HTTP call without timeout: requests.get()",
        severity=Severity.HIGH,
        category=Category.RELIABILITY,
        file_path="src/client.py",
        line=42,
        evidence="requests.get(url)",
        why="Can hang indefinitely, causing cascading failures.",
        fix="Add timeout=10 to the requests.get() call.",
        standard_refs=["OWASP API4:2023", "AWS Well-Architected"],
        blocking=True,
    )
    warning = Finding(
        id="FF-RETRY-CONSTANT-0099",
        title="Retry with constant delay (no backoff)",
        severity=Severity.MEDIUM,
        category=Category.RELIABILITY,
        file_path="src/client.py",
        line=99,
        evidence="time.sleep(5)",
        why="Constant delay doesn't give the service time to recover.",
        fix="Use exponential backoff with jitter.",
        standard_refs=["AWS Exponential Backoff and Jitter"],
        blocking=False,
    )
    return Scorecard(
        verdict=Verdict.FAIL,
        categories={
            Category.RELIABILITY: CategoryResult(
                category=Category.RELIABILITY,
                verdict=Verdict.FAIL,
                findings=[blocker, warning],
            ),
        },
        scan_path="/repo/project",
        profile="python-api",
    )


@pytest.fixture
def empty_scorecard() -> Scorecard:
    """A passing scorecard with no findings."""
    return Scorecard(
        verdict=Verdict.PASS,
        categories={},
        scan_path="/repo/clean",
        profile="python-api",
    )


# --- JSON Reporter Tests ---


class TestJsonReporter:
    def test_to_json_is_valid_json(self, sample_scorecard: Scorecard) -> None:
        result = to_json(sample_scorecard)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_to_dict_has_version(self, sample_scorecard: Scorecard) -> None:
        result = to_dict(sample_scorecard)
        assert "version" in result
        assert result["version"] == "1.0.0"

    def test_to_dict_has_verdict(self, sample_scorecard: Scorecard) -> None:
        result = to_dict(sample_scorecard)
        assert result["verdict"] == "fail"

    def test_to_dict_has_stats(self, sample_scorecard: Scorecard) -> None:
        result = to_dict(sample_scorecard)
        assert result["stats"]["total_findings"] == 2
        assert result["stats"]["blocker_count"] == 1
        assert result["stats"]["warning_count"] == 1

    def test_to_dict_has_categories(self, sample_scorecard: Scorecard) -> None:
        result = to_dict(sample_scorecard)
        assert "reliability" in result["categories"]
        cat = result["categories"]["reliability"]
        assert cat["verdict"] == "fail"
        assert len(cat["findings"]) == 2

    def test_findings_have_all_fields(self, sample_scorecard: Scorecard) -> None:
        result = to_dict(sample_scorecard)
        finding = result["categories"]["reliability"]["findings"][0]
        required_fields = ["id", "title", "severity", "category", "file", "line",
                          "evidence", "why", "fix", "standard_refs", "blocking"]
        for field in required_fields:
            assert field in finding, f"Missing field: {field}"

    def test_empty_scorecard(self, empty_scorecard: Scorecard) -> None:
        result = to_dict(empty_scorecard)
        assert result["verdict"] == "pass"
        assert result["stats"]["total_findings"] == 0


# --- Markdown Reporter Tests ---


class TestMarkdownReporter:
    def test_contains_header(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "# FailFast Production Readiness Report" in md

    def test_contains_verdict(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "FAIL" in md

    def test_contains_blockers_section(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "## ⛔ Blockers" in md

    def test_contains_finding_details(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "FF-TIMEOUT-0042" in md
        assert "requests.get(url)" in md
        assert "OWASP API4:2023" in md

    def test_contains_category_table(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "| Category |" in md
        assert "reliability" in md

    def test_contains_fix_guidance(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "How to fix:" in md

    def test_contains_footer(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "FailFast Developer MCP" in md

    def test_empty_scorecard_passes(self, empty_scorecard: Scorecard) -> None:
        md = to_markdown(empty_scorecard)
        assert "PASS" in md
        assert "Blockers" not in md.split("## ⛔")[0] if "## ⛔" in md else True

    def test_code_blocks_for_evidence(self, sample_scorecard: Scorecard) -> None:
        md = to_markdown(sample_scorecard)
        assert "```python" in md


# --- SARIF Reporter Tests ---


class TestSarifReporter:
    def test_to_sarif_is_valid_json(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif(sample_scorecard)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_sarif_has_correct_version(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        assert result["version"] == "2.1.0"

    def test_sarif_has_schema(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        assert "$schema" in result

    def test_sarif_has_tool_info(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        tool = result["runs"][0]["tool"]["driver"]
        assert tool["name"] == "FailFast Developer MCP"
        assert "version" in tool

    def test_sarif_has_rules(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        rules = result["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        # Check rule structure
        rule = rules[0]
        assert "id" in rule
        assert "shortDescription" in rule
        assert "help" in rule

    def test_sarif_has_results(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        results = result["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_results_have_locations(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        sarif_result = result["runs"][0]["results"][0]
        location = sarif_result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "src/client.py"
        assert location["region"]["startLine"] == 42

    def test_sarif_severity_mapping(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        results = result["runs"][0]["results"]
        # HIGH severity -> "error"
        blocker = [r for r in results if "TIMEOUT" in r["ruleId"]][0]
        assert blocker["level"] == "error"
        # MEDIUM severity -> "warning"
        warning = [r for r in results if "CONSTANT" in r["ruleId"]][0]
        assert warning["level"] == "warning"

    def test_sarif_has_invocations(self, sample_scorecard: Scorecard) -> None:
        result = to_sarif_dict(sample_scorecard)
        invocations = result["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
        assert invocations[0]["properties"]["verdict"] == "fail"

    def test_empty_scorecard(self, empty_scorecard: Scorecard) -> None:
        result = to_sarif_dict(empty_scorecard)
        assert len(result["runs"][0]["results"]) == 0
