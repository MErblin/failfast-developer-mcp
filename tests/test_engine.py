"""Tests for the core engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from failfast.engine import get_rule_explanation, run_scan
from failfast.models import AnalysisContext, Verdict

FIXTURES_DIR = str(Path(__file__).parent / "fixtures")


class TestRunScan:
    """Integration tests for the scan engine."""

    def test_scan_fixtures_directory(self) -> None:
        """Scanning the fixtures dir should find issues (it has bad code)."""
        context = AnalysisContext(repo_path=FIXTURES_DIR)
        scorecard = run_scan(context)

        # The fixtures have intentional problems — should not pass
        assert scorecard.verdict in (Verdict.FAIL, Verdict.WARN)
        assert len(scorecard.all_findings) > 0

    def test_scan_produces_scorecard_with_categories(self) -> None:
        """Scorecard should have category results."""
        context = AnalysisContext(repo_path=FIXTURES_DIR)
        scorecard = run_scan(context)

        assert len(scorecard.categories) > 0

    def test_scan_clean_file_only(self) -> None:
        """Scanning only the clean fixture should produce minimal findings."""
        context = AnalysisContext(
            repo_path=FIXTURES_DIR,
            files=["clean_api.py"],
        )
        scorecard = run_scan(context)

        # Clean code should have no custom analyzer findings
        # (might have some ruff style findings depending on config)
        timeout_findings = [f for f in scorecard.all_findings if "TIMEOUT" in f.id]
        retry_findings = [f for f in scorecard.all_findings if "RETRY" in f.id]
        assert len(timeout_findings) == 0
        assert len(retry_findings) == 0

    def test_scan_with_specific_files(self) -> None:
        """Should only scan the specified files."""
        context = AnalysisContext(
            repo_path=FIXTURES_DIR,
            files=["no_timeout.py"],
        )
        scorecard = run_scan(context)

        # Should find timeout issues
        timeout_findings = [f for f in scorecard.all_findings if "TIMEOUT" in f.id]
        assert len(timeout_findings) >= 1

    def test_scorecard_summary_is_set(self) -> None:
        """Scorecard should have a summary string."""
        context = AnalysisContext(repo_path=FIXTURES_DIR)
        scorecard = run_scan(context)
        assert scorecard.summary
        assert len(scorecard.summary) > 10


class TestGetRuleExplanation:
    """Tests for the rule catalog lookup."""

    def test_known_prefix_returns_explanation(self) -> None:
        result = get_rule_explanation("FF-TIMEOUT")
        assert result is not None
        assert "title" in result
        assert "fix" in result

    def test_finding_id_matches_prefix(self) -> None:
        result = get_rule_explanation("FF-RETRY-001")
        assert result is not None
        assert result["matched_rule"] == "FF-RETRY"

    def test_unknown_id_returns_none(self) -> None:
        result = get_rule_explanation("UNKNOWN-RULE")
        assert result is None

    def test_explanations_have_standard_refs(self) -> None:
        for rule_id in ["FF-TIMEOUT", "FF-RETRY", "FF-COMPLEXITY"]:
            result = get_rule_explanation(rule_id)
            assert result is not None
            assert "standard_refs" in result
            assert len(result["standard_refs"]) > 0
