"""Tests for the data models."""

from __future__ import annotations

import pytest

from failfast.models import (
    Category,
    CategoryResult,
    Finding,
    Scorecard,
    Severity,
    Verdict,
)


@pytest.fixture
def sample_blocker() -> Finding:
    return Finding(
        id="FF-TIMEOUT-0042",
        title="HTTP call without timeout",
        severity=Severity.HIGH,
        category=Category.RELIABILITY,
        file_path="src/client.py",
        line=42,
        evidence="requests.get(url)",
        why="Can hang indefinitely.",
        fix="Add timeout=10.",
        standard_refs=["OWASP API4:2023"],
        blocking=True,
    )


@pytest.fixture
def sample_warning() -> Finding:
    return Finding(
        id="FF-LINT-E501",
        title="Line too long",
        severity=Severity.LOW,
        category=Category.MAINTAINABILITY,
        file_path="src/utils.py",
        line=10,
        evidence="x = ...",
        why="Readability.",
        fix="Break the line.",
        blocking=False,
    )


class TestFinding:
    def test_finding_is_frozen(self, sample_blocker: Finding) -> None:
        with pytest.raises(AttributeError):
            sample_blocker.title = "changed"  # type: ignore[misc]

    def test_finding_has_all_fields(self, sample_blocker: Finding) -> None:
        assert sample_blocker.id == "FF-TIMEOUT-0042"
        assert sample_blocker.severity == Severity.HIGH
        assert sample_blocker.category == Category.RELIABILITY
        assert sample_blocker.blocking is True
        assert len(sample_blocker.standard_refs) > 0


class TestCategoryResult:
    def test_blocker_count(self, sample_blocker: Finding, sample_warning: Finding) -> None:
        result = CategoryResult(
            category=Category.RELIABILITY,
            verdict=Verdict.FAIL,
            findings=[sample_blocker, sample_warning],
        )
        assert result.blocker_count == 1
        assert result.warning_count == 1


class TestScorecard:
    def test_pass_verdict_summary(self) -> None:
        sc = Scorecard(verdict=Verdict.PASS, scan_path="/repo")
        assert "Production-ready" in sc.summary

    def test_fail_verdict_summary(self, sample_blocker: Finding) -> None:
        sc = Scorecard(
            verdict=Verdict.FAIL,
            categories={
                Category.RELIABILITY: CategoryResult(
                    category=Category.RELIABILITY,
                    verdict=Verdict.FAIL,
                    findings=[sample_blocker],
                )
            },
            scan_path="/repo",
        )
        assert "Not production-ready" in sc.summary
        assert len(sc.blockers) == 1
        assert len(sc.warnings) == 0

    def test_all_findings_aggregation(
        self, sample_blocker: Finding, sample_warning: Finding
    ) -> None:
        sc = Scorecard(
            verdict=Verdict.FAIL,
            categories={
                Category.RELIABILITY: CategoryResult(
                    category=Category.RELIABILITY,
                    verdict=Verdict.FAIL,
                    findings=[sample_blocker],
                ),
                Category.MAINTAINABILITY: CategoryResult(
                    category=Category.MAINTAINABILITY,
                    verdict=Verdict.WARN,
                    findings=[sample_warning],
                ),
            },
        )
        assert len(sc.all_findings) == 2
        assert len(sc.blockers) == 1
        assert len(sc.warnings) == 1
