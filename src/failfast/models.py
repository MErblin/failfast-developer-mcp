"""Data models for FailFast findings, scorecards, and analysis context."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Severity levels for findings, ordered from most to least critical."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(enum.Enum):
    """Analysis categories that map to production-readiness dimensions."""

    SECURITY = "security"
    RELIABILITY = "reliability"
    API_QUALITY = "api_quality"
    MAINTAINABILITY = "maintainability"
    DEPENDENCIES = "dependencies"


class Verdict(enum.Enum):
    """Overall production-readiness verdict."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


@dataclass(frozen=True)
class Finding:
    """A single production-readiness finding.

    Each finding represents one specific issue detected during analysis,
    with enough context for a developer to understand *why* it matters
    and *how* to fix it.
    """

    id: str
    """Unique rule ID, e.g. 'FF-RETRY-001'."""

    title: str
    """Human-readable summary of the issue."""

    severity: Severity
    """How critical this finding is."""

    category: Category
    """Which production-readiness dimension this belongs to."""

    file_path: str
    """Path to the file containing the issue, relative to repo root."""

    line: int
    """Line number where the issue occurs (1-indexed)."""

    evidence: str
    """The offending code snippet or pattern detected."""

    why: str
    """Why this matters in a production environment."""

    fix: str
    """Actionable guidance on how to resolve the issue."""

    standard_refs: list[str] = field(default_factory=list)
    """References to industry standards, e.g. ['OWASP API4:2023', 'RFC 9457']."""

    blocking: bool = False
    """Whether this finding should block production deployment."""


@dataclass(frozen=True)
class CategoryResult:
    """Result for a single analysis category."""

    category: Category
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocker_count(self) -> int:
        """Number of blocking findings in this category."""
        return sum(1 for f in self.findings if f.blocking)

    @property
    def warning_count(self) -> int:
        """Number of non-blocking findings in this category."""
        return sum(1 for f in self.findings if not f.blocking)


@dataclass(frozen=True)
class Scorecard:
    """Production-readiness scorecard aggregating all analysis results.

    The scorecard is the primary output of a FailFast scan. It provides
    a quick 'can this ship?' answer with supporting evidence.
    """

    verdict: Verdict
    """Overall verdict: PASS, FAIL, or WARN."""

    categories: dict[Category, CategoryResult] = field(default_factory=dict)
    """Per-category breakdown of results."""

    scan_path: str = ""
    """Path that was scanned."""

    profile: str = "python-api"
    """Profile used for the scan."""

    @property
    def all_findings(self) -> list[Finding]:
        """All findings across all categories."""
        findings: list[Finding] = []
        for result in self.categories.values():
            findings.extend(result.findings)
        return findings

    @property
    def blockers(self) -> list[Finding]:
        """All blocking findings."""
        return [f for f in self.all_findings if f.blocking]

    @property
    def warnings(self) -> list[Finding]:
        """All non-blocking findings."""
        return [f for f in self.all_findings if not f.blocking]

    @property
    def summary(self) -> str:
        """One-line summary of the scan result."""
        if self.verdict == Verdict.PASS:
            return "Production-ready. No blockers found."
        elif self.verdict == Verdict.FAIL:
            return (
                f"Not production-ready. {len(self.blockers)} blocker(s), "
                f"{len(self.warnings)} warning(s)."
            )
        else:
            return f"Conditionally ready. {len(self.warnings)} warning(s) to review."


@dataclass(frozen=True)
class AnalysisContext:
    """Context passed to each analyzer, containing everything it needs to run."""

    repo_path: str
    """Absolute path to the repository root."""

    files: list[str] = field(default_factory=list)
    """List of file paths to analyze (relative to repo_path).
    If empty, the analyzer should discover files itself."""

    profile: str = "python-api"
    """Profile name controlling thresholds and enabled rules."""

    max_complexity: int = 15
    """Maximum allowed cyclomatic complexity before a finding is blocking."""
