"""Tests for the AI Safety and Agentic Reliability analyzers."""

from __future__ import annotations

from pathlib import Path
import pytest

from failfast.analyzers.ai_loops import AgentLoopAnalyzer
from failfast.analyzers.ai_providers import ProviderConfigAnalyzer
from failfast.analyzers.ai_parsing import OutputParsingAnalyzer
from failfast.models import AnalysisContext, Category, Severity

FIXTURES_DIR = str(Path(__file__).parent.parent / "fixtures")


@pytest.fixture
def context_bad_agents() -> AnalysisContext:
    return AnalysisContext(
        repo_path=FIXTURES_DIR,
        files=["bad_agents.py"],
    )


class TestAgentLoopAnalyzer:
    """Verify detection of runaway agent reasoning loops."""

    def test_name(self) -> None:
        assert AgentLoopAnalyzer().name == "AgentLoopAnalyzer"

    def test_detects_unbounded_agent_loop(self, context_bad_agents: AnalysisContext) -> None:
        analyzer = AgentLoopAnalyzer()
        findings = analyzer.analyze(context_bad_agents)

        runaway_findings = [f for f in findings if f.id == "FF-AI-RUNAWAY"]
        assert len(runaway_findings) == 1
        finding = runaway_findings[0]
        assert finding.line == 16  # runaway_agent while True loop line
        assert finding.blocking is True
        assert finding.category == Category.RELIABILITY  # Runaway is reliability issue


class TestProviderConfigAnalyzer:
    """Verify safety configurations for cloud AI providers (Bedrock, Vertex, Azure)."""

    def test_name(self) -> None:
        assert ProviderConfigAnalyzer().name == "ProviderConfigAnalyzer"

    def test_detects_bedrock_unsafe(self, context_bad_agents: AnalysisContext) -> None:
        analyzer = ProviderConfigAnalyzer()
        findings = analyzer.analyze(context_bad_agents)

        bedrock_findings = [f for f in findings if f.id == "FF-AI-BEDROCK-GUARD"]
        assert len(bedrock_findings) == 1
        finding = bedrock_findings[0]
        assert "call_bedrock_unsafe" in finding.evidence or "invoke_model" in finding.evidence
        assert finding.category == Category.SECURITY

    def test_detects_vertex_unsafe(self, context_bad_agents: AnalysisContext) -> None:
        analyzer = ProviderConfigAnalyzer()
        findings = analyzer.analyze(context_bad_agents)

        vertex_findings = [f for f in findings if f.id == "FF-AI-VERTEX-SAFETY"]
        assert len(vertex_findings) == 1
        finding = vertex_findings[0]
        assert "GenerativeModel" in finding.evidence
        assert finding.category == Category.SECURITY

    def test_detects_azure_unsafe(self, context_bad_agents: AnalysisContext) -> None:
        analyzer = ProviderConfigAnalyzer()
        findings = analyzer.analyze(context_bad_agents)

        azure_findings = [f for f in findings if f.id == "FF-AI-AZURE-VERSION"]
        assert len(azure_findings) == 2  # One missing api_version, one deprecated api_version
        assert azure_findings[0].category == Category.SECURITY


class TestOutputParsingAnalyzer:
    """Verify structured and safe json parsing for LLM variables."""

    def test_name(self) -> None:
        assert OutputParsingAnalyzer().name == "OutputParsingAnalyzer"

    def test_detects_unsafe_parsing(self, context_bad_agents: AnalysisContext) -> None:
        analyzer = OutputParsingAnalyzer()
        findings = analyzer.analyze(context_bad_agents)

        parsing_findings = [f for f in findings if f.id == "FF-AI-RAWPARSING"]
        assert len(parsing_findings) == 1
        finding = parsing_findings[0]
        assert "json.loads(response_content)" in finding.evidence
        assert finding.category == Category.RELIABILITY
