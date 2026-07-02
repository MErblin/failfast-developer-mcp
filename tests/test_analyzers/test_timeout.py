"""Tests for the timeout analyzer — FailFast's custom AST-based detection."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from failfast.analyzers.timeout import TimeoutAnalyzer
from failfast.models import AnalysisContext, Category, Severity

FIXTURES_DIR = str(Path(__file__).parent.parent / "fixtures")


@pytest.fixture
def analyzer() -> TimeoutAnalyzer:
    return TimeoutAnalyzer()


@pytest.fixture
def context_no_timeout() -> AnalysisContext:
    return AnalysisContext(
        repo_path=FIXTURES_DIR,
        files=["no_timeout.py"],
    )


@pytest.fixture
def context_clean() -> AnalysisContext:
    return AnalysisContext(
        repo_path=FIXTURES_DIR,
        files=["clean_api.py"],
    )


class TestTimeoutAnalyzer:
    """Tests for timeout detection on HTTP client calls."""

    def test_name(self, analyzer: TimeoutAnalyzer) -> None:
        assert analyzer.name == "TimeoutAnalyzer"

    def test_detects_requests_get_without_timeout(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Should flag requests.get() without timeout=."""
        findings = analyzer.analyze(context_no_timeout)
        requests_get_findings = [
            f for f in findings if "requests.get" in f.title.lower()
        ]
        assert len(requests_get_findings) >= 1

    def test_detects_requests_post_without_timeout(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Should flag requests.post() without timeout=."""
        findings = analyzer.analyze(context_no_timeout)
        post_findings = [f for f in findings if "requests.post" in f.title.lower()]
        assert len(post_findings) >= 1

    def test_detects_httpx_without_timeout(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Should flag httpx.get() without timeout=."""
        findings = analyzer.analyze(context_no_timeout)
        httpx_findings = [f for f in findings if "httpx.get" in f.title.lower()]
        assert len(httpx_findings) >= 1

    def test_all_findings_are_reliability_category(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """All timeout findings should be in the RELIABILITY category."""
        findings = analyzer.analyze(context_no_timeout)
        for finding in findings:
            assert finding.category == Category.RELIABILITY

    def test_all_findings_are_blocking(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Missing timeouts should always be blocking."""
        findings = analyzer.analyze(context_no_timeout)
        for finding in findings:
            assert finding.blocking is True

    def test_all_findings_have_high_severity(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Missing timeouts should be HIGH severity."""
        findings = analyzer.analyze(context_no_timeout)
        for finding in findings:
            assert finding.severity == Severity.HIGH

    def test_findings_have_standard_refs(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Each finding should map to OWASP or AWS standards."""
        findings = analyzer.analyze(context_no_timeout)
        for finding in findings:
            assert len(finding.standard_refs) > 0
            assert any("OWASP" in ref or "AWS" in ref for ref in finding.standard_refs)

    def test_clean_code_produces_no_findings(
        self, analyzer: TimeoutAnalyzer, context_clean: AnalysisContext
    ) -> None:
        """Clean code with timeouts should produce zero timeout findings."""
        findings = analyzer.analyze(context_clean)
        assert len(findings) == 0

    def test_findings_have_fix_guidance(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Every finding should have actionable fix guidance."""
        findings = analyzer.analyze(context_no_timeout)
        for finding in findings:
            assert finding.fix
            assert "timeout" in finding.fix.lower()

    def test_finding_ids_start_with_ff_timeout(
        self, analyzer: TimeoutAnalyzer, context_no_timeout: AnalysisContext
    ) -> None:
        """Finding IDs should follow the FF-TIMEOUT-XXXX convention."""
        findings = analyzer.analyze(context_no_timeout)
        for finding in findings:
            assert finding.id.startswith("FF-TIMEOUT-")
