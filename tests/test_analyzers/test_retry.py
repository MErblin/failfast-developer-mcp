"""Tests for the retry analyzer — FailFast's custom AST-based detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from failfast.analyzers.retry import RetryAnalyzer
from failfast.models import AnalysisContext, Category, Severity

FIXTURES_DIR = str(Path(__file__).parent.parent / "fixtures")


@pytest.fixture
def analyzer() -> RetryAnalyzer:
    return RetryAnalyzer()


@pytest.fixture
def context_bad_retry() -> AnalysisContext:
    return AnalysisContext(
        repo_path=FIXTURES_DIR,
        files=["bad_retry.py"],
    )


@pytest.fixture
def context_clean() -> AnalysisContext:
    return AnalysisContext(
        repo_path=FIXTURES_DIR,
        files=["clean_api.py"],
    )


class TestRetryAnalyzer:
    """Tests for retry pattern detection."""

    def test_name(self, analyzer: RetryAnalyzer) -> None:
        assert analyzer.name == "RetryAnalyzer"

    def test_detects_retry_without_jitter(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Should flag retry loops without jitter."""
        findings = analyzer.analyze(context_bad_retry)
        jitter_findings = [f for f in findings if "jitter" in f.title.lower()]
        assert len(jitter_findings) >= 1

    def test_detects_retry_without_max_attempts(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Should flag while True retry loops without max attempts."""
        findings = analyzer.analyze(context_bad_retry)
        max_findings = [f for f in findings if "maximum attempts" in f.title.lower()]
        assert len(max_findings) >= 1

    def test_detects_constant_sleep(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Should flag retry with constant delay (no backoff)."""
        findings = analyzer.analyze(context_bad_retry)
        constant_findings = [f for f in findings if "constant" in f.title.lower()]
        assert len(constant_findings) >= 1

    def test_all_findings_are_reliability_category(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """All retry findings should be in the RELIABILITY category."""
        findings = analyzer.analyze(context_bad_retry)
        for finding in findings:
            assert finding.category == Category.RELIABILITY

    def test_jitter_findings_are_blocking(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Missing jitter should be a blocker."""
        findings = analyzer.analyze(context_bad_retry)
        jitter_findings = [f for f in findings if "jitter" in f.title.lower() and "NOJITTER" in f.id]
        for finding in jitter_findings:
            assert finding.blocking is True

    def test_findings_reference_aws_backoff(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Findings should reference AWS Exponential Backoff and Jitter."""
        findings = analyzer.analyze(context_bad_retry)
        for finding in findings:
            assert any("AWS" in ref for ref in finding.standard_refs)

    def test_clean_code_no_retry_findings(
        self, analyzer: RetryAnalyzer, context_clean: AnalysisContext
    ) -> None:
        """Clean code with proper retry+jitter should produce no findings."""
        findings = analyzer.analyze(context_clean)
        assert len(findings) == 0

    def test_finding_ids_start_with_ff_retry(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Finding IDs should follow the FF-RETRY-* convention."""
        findings = analyzer.analyze(context_bad_retry)
        for finding in findings:
            assert finding.id.startswith("FF-RETRY-")

    def test_findings_have_fix_guidance(
        self, analyzer: RetryAnalyzer, context_bad_retry: AnalysisContext
    ) -> None:
        """Every finding should have actionable fix guidance."""
        findings = analyzer.analyze(context_bad_retry)
        for finding in findings:
            assert finding.fix
            assert len(finding.fix) > 20  # Meaningful guidance, not empty
