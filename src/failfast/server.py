"""FailFast MCP Server — Production-readiness tools for IDEs and editors.

This is a thin transport layer over the core engine. The MCP server exposes
tools that modern development tools can invoke to check whether Python code is production-ready.

Run with: uv run mcp dev src/failfast/server.py
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from failfast import __version__

# Create the MCP server instance
mcp = FastMCP(
    "failfast-developer-mcp",
    instructions=(
        "FailFast is a production-readiness reviewer for Python code. "
        "Use the scan tool to check if code is ready for production. "
        "It checks security, reliability, API quality, maintainability, "
        "and dependency safety — not just lint rules."
    ),
)


@mcp.tool()
def ping() -> str:
    """Health check. Returns a confirmation that FailFast is running.

    Use this to verify that the FailFast MCP server is connected and responsive.
    """
    return f"FailFast Developer MCP v{__version__} is alive and ready to review code."


@mcp.tool()
def scan(path: str, profile: str = "python-api") -> dict:  # type: ignore[type-arg]
    """Scan a Python repository or directory for production-readiness.

    Runs all enabled analyzers (security, complexity, reliability, etc.)
    and returns a scorecard with a PASS/FAIL/WARN verdict plus detailed findings.

    Args:
        path: Absolute path to the repository or directory to scan.
        profile: Analysis profile to use. Default: 'python-api'.

    Returns:
        A scorecard dict with verdict, category results, blockers, and warnings.
    """
    from failfast.engine import run_scan
    from failfast.models import AnalysisContext

    context = AnalysisContext(repo_path=path, profile=profile)
    scorecard = run_scan(context)

    return {
        "verdict": scorecard.verdict.value,
        "summary": scorecard.summary,
        "blocker_count": len(scorecard.blockers),
        "warning_count": len(scorecard.warnings),
        "blockers": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "file": f.file_path,
                "line": f.line,
                "evidence": f.evidence,
                "why": f.why,
                "fix": f.fix,
                "standard_refs": f.standard_refs,
            }
            for f in scorecard.blockers
        ],
        "warnings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "file": f.file_path,
                "line": f.line,
                "why": f.why,
                "fix": f.fix,
            }
            for f in scorecard.warnings
        ],
    }


@mcp.tool()
def scan_diff(path: str, base_ref: str = "main") -> dict:  # type: ignore[type-arg]
    """Scan only files changed since a git ref (branch, tag, or commit).

    Use this in PR workflows to check only newly introduced problems,
    avoiding noise from legacy code.

    Args:
        path: Absolute path to the git repository to scan.
        base_ref: Git ref to diff against. Default: 'main'.

    Returns:
        A scorecard dict covering only the changed files.
    """
    from failfast.engine import run_scan_diff
    from failfast.models import AnalysisContext

    context = AnalysisContext(repo_path=path)
    scorecard = run_scan_diff(context, base_ref=base_ref)

    return {
        "verdict": scorecard.verdict.value,
        "summary": scorecard.summary,
        "blocker_count": len(scorecard.blockers),
        "warning_count": len(scorecard.warnings),
        "blockers": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "file": f.file_path,
                "line": f.line,
                "why": f.why,
                "fix": f.fix,
            }
            for f in scorecard.blockers
        ],
        "warnings": [
            {
                "id": f.id,
                "title": f.title,
                "file": f.file_path,
                "line": f.line,
                "fix": f.fix,
            }
            for f in scorecard.warnings
        ],
    }


@mcp.tool()
def check(path: str, category: str) -> dict:  # type: ignore[type-arg]
    """Run a single analysis category against a path.

    Available categories: security, reliability, api_quality, maintainability, dependencies.

    Args:
        path: Absolute path to the repository or directory to scan.
        category: The category to check. One of: security, reliability,
                  api_quality, maintainability, dependencies.

    Returns:
        Results for the specified category only.
    """
    from failfast.engine import run_check
    from failfast.models import AnalysisContext, Category

    try:
        cat = Category(category)
    except ValueError:
        valid = [c.value for c in Category]
        return {"error": f"Unknown category '{category}'. Valid: {valid}"}

    context = AnalysisContext(repo_path=path)
    result = run_check(context, category=cat)

    return {
        "category": result.category.value,
        "verdict": result.verdict.value,
        "finding_count": len(result.findings),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "file": f.file_path,
                "line": f.line,
                "evidence": f.evidence,
                "why": f.why,
                "fix": f.fix,
                "blocking": f.blocking,
            }
            for f in result.findings
        ],
    }


@mcp.tool()
def explain(finding_id: str) -> dict:  # type: ignore[type-arg]
    """Get a detailed explanation for a specific FailFast finding rule.

    Returns the rule definition, why it matters, how to fix it,
    and which industry standards it maps to. No LLM needed — this is
    deterministic and always returns the same explanation.

    Args:
        finding_id: The finding rule ID, e.g. 'FF-RETRY-001'.

    Returns:
        Detailed explanation of the rule including fix guidance and standards.
    """
    from failfast.engine import get_rule_explanation

    explanation = get_rule_explanation(finding_id)
    if explanation is None:
        return {"error": f"Unknown finding ID '{finding_id}'."}

    return explanation


def main() -> None:
    """Entry point for running the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
