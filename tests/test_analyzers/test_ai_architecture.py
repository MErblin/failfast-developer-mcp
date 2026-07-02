"""Tests for the LLM & Agentic Architecture Verification analyzers."""

from __future__ import annotations

from pathlib import Path
import pytest

from failfast.analyzers.ai_observability import TelemetryAnalyzer
from failfast.analyzers.ai_guardrails import GuardrailsAnalyzer
from failfast.analyzers.ai_prompts import PromptInlineAnalyzer
from failfast.analyzers.ai_cache import CacheAnalyzer
from failfast.analyzers.ai_fallback import FallbackAnalyzer
from failfast.models import AnalysisContext, Category, Severity

FIXTURES_DIR = str(Path(__file__).parent.parent / "fixtures")


@pytest.fixture
def context_clean_ai() -> AnalysisContext:
    return AnalysisContext(
        repo_path=FIXTURES_DIR,
        files=["clean_ai.py"],
    )


class TestTelemetryAnalyzer:
    """Verify TelemetryAnalyzer flags missing observability setups."""

    def test_name(self) -> None:
        assert TelemetryAnalyzer().name == "TelemetryAnalyzer"

    def test_detects_missing_telemetry(self) -> None:
        analyzer = TelemetryAnalyzer()
        ctx = AnalysisContext(repo_path=FIXTURES_DIR, files=["bad_telemetry.py"])
        findings = analyzer.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "FF-AI-OBSERVABILITY"
        assert finding.category == Category.AI_SAFETY
        assert finding.severity == Severity.MEDIUM
        assert finding.blocking is False

    def test_bypass_clean_observability(self, context_clean_ai: AnalysisContext) -> None:
        analyzer = TelemetryAnalyzer()
        findings = analyzer.analyze(context_clean_ai)
        assert len(findings) == 0


class TestGuardrailsAnalyzer:
    """Verify GuardrailsAnalyzer flags missing validation/guardrail layers."""

    def test_name(self) -> None:
        assert GuardrailsAnalyzer().name == "GuardrailsAnalyzer"

    def test_detects_missing_guardrails(self) -> None:
        analyzer = GuardrailsAnalyzer()
        ctx = AnalysisContext(repo_path=FIXTURES_DIR, files=["bad_guardrails.py"])
        findings = analyzer.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "FF-AI-GUARDRAILS"
        assert finding.category == Category.AI_SAFETY
        assert finding.severity == Severity.MEDIUM

    def test_bypass_clean_guardrails(self, context_clean_ai: AnalysisContext) -> None:
        analyzer = GuardrailsAnalyzer()
        findings = analyzer.analyze(context_clean_ai)
        assert len(findings) == 0


class TestPromptInlineAnalyzer:
    """Verify PromptInlineAnalyzer flags massive inline prompt declarations."""

    def test_name(self) -> None:
        assert PromptInlineAnalyzer().name == "PromptInlineAnalyzer"

    def test_detects_inline_prompt(self) -> None:
        analyzer = PromptInlineAnalyzer()
        ctx = AnalysisContext(repo_path=FIXTURES_DIR, files=["bad_prompts.py"])
        findings = analyzer.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "FF-AI-PROMPT-INLINE"
        assert "medical assistant" in finding.evidence
        assert finding.category == Category.AI_SAFETY

    def test_bypass_clean_prompt(self, context_clean_ai: AnalysisContext) -> None:
        analyzer = PromptInlineAnalyzer()
        findings = analyzer.analyze(context_clean_ai)
        assert len(findings) == 0


class TestCacheAnalyzer:
    """Verify CacheAnalyzer flags missing prompt caching layer setups."""

    def test_name(self) -> None:
        assert CacheAnalyzer().name == "CacheAnalyzer"

    def test_detects_missing_cache(self) -> None:
        analyzer = CacheAnalyzer()
        ctx = AnalysisContext(repo_path=FIXTURES_DIR, files=["bad_cache.py"])
        findings = analyzer.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "FF-AI-CACHE"
        assert finding.category == Category.AI_SAFETY

    def test_bypass_clean_cache(self, context_clean_ai: AnalysisContext) -> None:
        analyzer = CacheAnalyzer()
        findings = analyzer.analyze(context_clean_ai)
        assert len(findings) == 0


class TestFallbackAnalyzer:
    """Verify FallbackAnalyzer flags LLM calls missing a failover request strategy."""

    def test_name(self) -> None:
        assert FallbackAnalyzer().name == "FallbackAnalyzer"

    def test_detects_missing_fallback(self) -> None:
        analyzer = FallbackAnalyzer()
        ctx = AnalysisContext(repo_path=FIXTURES_DIR, files=["bad_fallback.py"])
        findings = analyzer.analyze(ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "FF-AI-FALLBACK"
        assert finding.category == Category.AI_SAFETY

    def test_bypass_clean_fallback(self) -> None:
        analyzer = FallbackAnalyzer()
        ctx = AnalysisContext(repo_path=FIXTURES_DIR, files=["clean_fallback.py"])
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0
