"""FailFast analysis engine — orchestrates analyzers and produces scorecards.

The engine is the core of FailFast. It is transport-agnostic: it knows nothing
about MCP, CLI, or any other interface. It takes an AnalysisContext, runs all
relevant analyzers, and produces a Scorecard.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from failfast.analyzers import Analyzer

from failfast.models import (
    AnalysisContext,
    Category,
    CategoryResult,
    Finding,
    Scorecard,
    Verdict,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule catalog — deterministic explanations for every finding ID prefix
# ---------------------------------------------------------------------------

RULE_CATALOG: dict[str, dict[str, object]] = {
    "FF-TIMEOUT": {
        "title": "Missing HTTP Request Timeout",
        "description": (
            "HTTP calls without explicit timeouts can hang indefinitely, "
            "consuming connections and threads. In production, this leads to "
            "cascading failures when downstream services are slow or unresponsive."
        ),
        "why": (
            "A single hung request can exhaust your connection pool, causing "
            "every subsequent request to queue and eventually timeout at the "
            "load balancer level — taking down your entire service."
        ),
        "fix": (
            "Always pass an explicit timeout parameter. For httpx: "
            "`httpx.get(url, timeout=10.0)`. For requests: "
            "`requests.get(url, timeout=(3.05, 27))` (connect, read). "
            "For aiohttp: use `aiohttp.ClientTimeout(total=30)`."
        ),
        "standard_refs": [
            "OWASP API4:2023 - Unrestricted Resource Consumption",
            "AWS Well-Architected: Reliability Pillar",
        ],
        "severity": "high",
        "category": "reliability",
    },
    "FF-RETRY": {
        "title": "Unsafe Retry Pattern",
        "description": (
            "Retry logic without jitter, maximum attempts, or idempotency "
            "awareness can amplify failures instead of recovering from them."
        ),
        "why": (
            "Without jitter, all clients retry at the same time after a failure "
            "(thundering herd). Without max attempts, a retry loop can run forever. "
            "Retrying non-idempotent operations (e.g., POST /payments) can cause "
            "duplicate side effects."
        ),
        "fix": (
            "Use capped exponential backoff with full jitter: "
            "`delay = min(max_delay, base * 2**attempt); sleep(random(0, delay))`. "
            "Always set max_attempts. Only retry transient errors (408, 429, 5xx). "
            "For non-idempotent operations, require an idempotency key."
        ),
        "standard_refs": [
            "AWS Exponential Backoff and Jitter",
            "Google Cloud Retry Strategy",
        ],
        "severity": "high",
        "category": "reliability",
    },
    "FF-COMPLEXITY": {
        "title": "Excessive Cyclomatic Complexity",
        "description": (
            "Functions with high cyclomatic complexity have too many execution "
            "paths to reason about safely. This increases bug density and makes "
            "the code harder to test and review."
        ),
        "why": (
            "Research shows that defect density increases with cyclomatic complexity. "
            "Functions above CC 15 are nearly impossible to fully unit-test and "
            "are a common source of production incidents."
        ),
        "fix": (
            "Extract helper functions, use early returns to reduce nesting, "
            "replace complex conditionals with lookup tables or strategy patterns, "
            "and move validation logic into dedicated validators."
        ),
        "standard_refs": [
            "McCabe Complexity Metric",
            "NIST SSDF PW.5 - Create Source Code by Adhering to Secure Coding Practices",
        ],
        "severity": "high",
        "category": "maintainability",
    },
    "FF-SECURITY": {
        "title": "Security Finding (Bandit)",
        "description": (
            "A security issue detected by Bandit static analysis. This may include "
            "use of unsafe functions, hardcoded credentials, insecure crypto, "
            "or injection vulnerabilities."
        ),
        "why": (
            "Security vulnerabilities in production code can lead to data breaches, "
            "unauthorized access, and compliance violations."
        ),
        "fix": "See the specific finding details for targeted remediation guidance.",
        "standard_refs": [
            "OWASP Secure Coding Practices",
            "OWASP Top 10",
            "OpenSSF Python Secure Coding Guide",
        ],
        "severity": "high",
        "category": "security",
    },
    "FF-LINT": {
        "title": "Code Quality Finding (Ruff)",
        "description": (
            "A code quality or style issue detected by Ruff. While individual "
            "lint findings may seem minor, they often indicate deeper maintainability "
            "problems and inconsistent code standards."
        ),
        "why": (
            "Consistent code style reduces cognitive load during reviews and "
            "on-call debugging. Many lint rules also catch real bugs (unused imports, "
            "unreachable code, shadowed variables)."
        ),
        "fix": "Run `ruff check --fix` to auto-fix where possible.",
        "standard_refs": ["PEP 8", "Ruff Rule Catalog"],
        "severity": "medium",
        "category": "maintainability",
    },
    "FF-AI-RUNAWAY": {
        "title": "Agent Runaway Loop",
        "description": "Agent loop calling LLMs/tool chains without a maximum iteration guard.",
        "why": "Unbounded loops can execute infinitely if the agent hallucinates or loops back, generating large token costs and crashing threads.",
        "fix": "Initialize a counter (e.g. `steps = 0`) before the loop, increment it inside, and break or raise if `steps >= max_steps`.",
        "standard_refs": ["OWASP LLM06:2023 - Excessive Agency", "AWS Well-Architected Reliability"],
        "severity": "high",
        "category": "ai_safety",
    },
    "FF-AI-BEDROCK-GUARD": {
        "title": "Missing Amazon Bedrock Guardrails",
        "description": "Bedrock model invocation call missing guardrailIdentifier or guardrailVersion.",
        "why": "Model requests without explicit guardrails skip corporate filters for PII masking, safety compliance, and poison checks.",
        "fix": "Pass `guardrailIdentifier` and `guardrailVersion` parameters to the Bedrock client call.",
        "standard_refs": ["OWASP LLM02:2023 - Sensitive Information Disclosure", "NIST AI RMF"],
        "severity": "high",
        "category": "ai_safety",
    },
    "FF-AI-VERTEX-SAFETY": {
        "title": "Missing Vertex AI Safety Settings",
        "description": "Vertex AI GenerativeModel instantiation missing explicit safety_settings.",
        "why": "Generative models without safety settings inherit permissive default filters, allowing adversarial queries or harmful content to slip through.",
        "fix": "Pass `safety_settings` keyword to `GenerativeModel` client calls.",
        "standard_refs": ["OWASP LLM01:2023 - Prompt Injection", "GCP Enterprise AI Guidance"],
        "severity": "high",
        "category": "ai_safety",
    },
    "FF-AI-AZURE-VERSION": {
        "title": "Unsafe Azure OpenAI API Version",
        "description": "AzureOpenAI client initialized with deprecated or missing api_version parameter.",
        "why": "Running deprecated API versions faces complete backend service shutdown from Azure model endpoints.",
        "fix": "Specify a stable api_version parameter (e.g., '2024-02-01' or newer).",
        "standard_refs": ["OWASP Top 10 A06:2021-Vulnerable and Outdated Components"],
        "severity": "high",
        "category": "ai_safety",
    },
    "FF-AI-RAWPARSING": {
        "title": "Unsafe LLM Output Parsing",
        "description": "Calling json.loads on a raw LLM output variable without wrapping it in a try-except block.",
        "why": "LLM completions are probabilistic and can output markdown wrappers or invalid text formats, throwing a runtime JSONDecodeError.",
        "fix": "Wrap json.loads calls in a try-except JSONDecodeError block, or use structured output models.",
        "standard_refs": ["OWASP LLM05:2023 - Improper Output Handling"],
        "severity": "high",
        "category": "ai_safety",
    },
}


def _get_all_analyzers() -> list[Analyzer]:
    """Lazily import and instantiate all available analyzers."""
    analyzers: list[Analyzer] = []

    # Import each analyzer — failures are logged but don't crash the engine
    try:
        from failfast.analyzers.ruff import RuffAnalyzer

        analyzers.append(RuffAnalyzer())
    except ImportError:
        logger.warning("RuffAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.bandit import BanditAnalyzer

        analyzers.append(BanditAnalyzer())
    except ImportError:
        logger.warning("BanditAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.complexity import ComplexityAnalyzer

        analyzers.append(ComplexityAnalyzer())
    except ImportError:
        logger.warning("ComplexityAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.timeout import TimeoutAnalyzer

        analyzers.append(TimeoutAnalyzer())
    except ImportError:
        logger.warning("TimeoutAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.retry import RetryAnalyzer

        analyzers.append(RetryAnalyzer())
    except ImportError:
        logger.warning("RetryAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.ai_loops import AgentLoopAnalyzer

        analyzers.append(AgentLoopAnalyzer())
    except ImportError:
        logger.warning("AgentLoopAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.ai_providers import ProviderConfigAnalyzer

        analyzers.append(ProviderConfigAnalyzer())
    except ImportError:
        logger.warning("ProviderConfigAnalyzer not available — skipping.")

    try:
        from failfast.analyzers.ai_parsing import OutputParsingAnalyzer

        analyzers.append(OutputParsingAnalyzer())
    except ImportError:
        logger.warning("OutputParsingAnalyzer not available — skipping.")

    return analyzers


def _categorize_findings(findings: list[Finding]) -> dict[Category, CategoryResult]:
    """Group findings by category and determine per-category verdicts."""
    by_category: dict[Category, list[Finding]] = {cat: [] for cat in Category}

    for finding in findings:
        by_category[finding.category].append(finding)

    results: dict[Category, CategoryResult] = {}
    for category, cat_findings in by_category.items():
        has_blockers = any(f.blocking for f in cat_findings)
        has_warnings = len(cat_findings) > 0

        if has_blockers:
            verdict = Verdict.FAIL
        elif has_warnings:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.PASS

        results[category] = CategoryResult(
            category=category,
            verdict=verdict,
            findings=cat_findings,
        )

    return results


def _determine_verdict(categories: dict[Category, CategoryResult]) -> Verdict:
    """Determine the overall verdict from category results."""
    if any(r.verdict == Verdict.FAIL for r in categories.values()):
        return Verdict.FAIL
    if any(r.verdict == Verdict.WARN for r in categories.values()):
        return Verdict.WARN
    return Verdict.PASS


def _discover_python_files(repo_path: str) -> list[str]:
    """Find all Python files in a directory, respecting common exclusions."""
    excluded_dirs = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".eggs",
    }

    python_files: list[str] = []
    root = Path(repo_path)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded directories in-place
        dirnames[:] = [d for d in dirnames if d not in excluded_dirs]

        for filename in filenames:
            if filename.endswith(".py"):
                full_path = Path(dirpath) / filename
                relative = str(full_path.relative_to(root))
                python_files.append(relative)

    return sorted(python_files)


def run_scan(context: AnalysisContext) -> Scorecard:
    """Run a full production-readiness scan.

    Args:
        context: Analysis context with repo path, file list, and profile.

    Returns:
        A Scorecard with verdict, category results, and all findings.
    """
    repo_path = context.repo_path
    files = context.files

    if os.path.isfile(repo_path):
        files = [os.path.basename(repo_path)]
        repo_path = os.path.dirname(repo_path)
        context = AnalysisContext(
            repo_path=repo_path,
            files=files,
            profile=context.profile,
            max_complexity=context.max_complexity,
        )
    elif not files:
        files = _discover_python_files(repo_path)
        context = AnalysisContext(
            repo_path=repo_path,
            files=files,
            profile=context.profile,
            max_complexity=context.max_complexity,
        )

    logger.info(
        "Starting scan of %s (%d files, profile=%s)",
        context.repo_path,
        len(context.files),
        context.profile,
    )

    # Run all analyzers
    all_findings: list[Finding] = []
    analyzers = _get_all_analyzers()

    for analyzer in analyzers:
        try:
            logger.info("Running %s...", analyzer.name)
            findings = analyzer.analyze(context)
            all_findings.extend(findings)
            logger.info("%s found %d issue(s).", analyzer.name, len(findings))
        except Exception:
            logger.exception("Analyzer %s failed — skipping.", analyzer.name)

    # Build scorecard
    categories = _categorize_findings(all_findings)
    verdict = _determine_verdict(categories)

    return Scorecard(
        verdict=verdict,
        categories=categories,
        scan_path=context.repo_path,
        profile=context.profile,
    )


def run_scan_diff(context: AnalysisContext, base_ref: str = "main") -> Scorecard:
    """Run a scan on only files changed since a git ref.

    Args:
        context: Analysis context with repo path.
        base_ref: Git ref to diff against (branch, tag, or commit SHA).

    Returns:
        A Scorecard covering only the changed files.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", base_ref],
            cwd=context.repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        changed_files = [
            f.strip() for f in result.stdout.strip().split("\n") if f.strip().endswith(".py")
        ]
    except subprocess.CalledProcessError as e:
        logger.error("git diff failed: %s", e.stderr)
        changed_files = []

    if not changed_files:
        return Scorecard(
            verdict=Verdict.PASS,
            categories={},
            scan_path=context.repo_path,
            profile=context.profile,
        )

    diff_context = AnalysisContext(
        repo_path=context.repo_path,
        files=changed_files,
        profile=context.profile,
        max_complexity=context.max_complexity,
    )

    return run_scan(diff_context)


def run_check(context: AnalysisContext, category: Category) -> CategoryResult:
    """Run analysis for a single category only.

    Args:
        context: Analysis context.
        category: The specific category to check.

    Returns:
        CategoryResult for the requested category.
    """
    # Map categories to their relevant analyzers
    category_analyzer_map: dict[Category, list[str]] = {
        Category.SECURITY: ["Bandit"],
        Category.RELIABILITY: ["TimeoutAnalyzer", "RetryAnalyzer"],
        Category.API_QUALITY: [],  # Future: FastAPI-specific analyzers
        Category.MAINTAINABILITY: ["Ruff", "ComplexityAnalyzer"],
        Category.DEPENDENCIES: [],  # Future: pip-audit
        Category.AI_SAFETY: ["AgentLoopAnalyzer", "ProviderConfigAnalyzer", "OutputParsingAnalyzer"],
    }

    relevant_names = category_analyzer_map.get(category, [])
    all_analyzers = _get_all_analyzers()

    # Filter to only relevant analyzers (or run all if no specific mapping)
    if relevant_names:
        analyzers = [a for a in all_analyzers if a.name in relevant_names]
    else:
        analyzers = all_analyzers

    repo_path = context.repo_path
    files = context.files

    if os.path.isfile(repo_path):
        files = [os.path.basename(repo_path)]
        repo_path = os.path.dirname(repo_path)
        context = AnalysisContext(
            repo_path=repo_path,
            files=files,
            profile=context.profile,
            max_complexity=context.max_complexity,
        )
    elif not files:
        files = _discover_python_files(repo_path)
        context = AnalysisContext(
            repo_path=repo_path,
            files=files,
            profile=context.profile,
            max_complexity=context.max_complexity,
        )

    findings: list[Finding] = []
    for analyzer in analyzers:
        try:
            results = analyzer.analyze(context)
            # Only keep findings matching the requested category
            findings.extend(f for f in results if f.category == category)
        except Exception:
            logger.exception("Analyzer %s failed.", analyzer.name)

    has_blockers = any(f.blocking for f in findings)
    has_any = len(findings) > 0

    if has_blockers:
        verdict = Verdict.FAIL
    elif has_any:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.PASS

    return CategoryResult(category=category, verdict=verdict, findings=findings)


def get_rule_explanation(finding_id: str) -> dict[str, object] | None:
    """Look up a deterministic explanation for a finding ID.

    Args:
        finding_id: A finding ID like 'FF-RETRY-001' or prefix like 'FF-RETRY'.

    Returns:
        A dict with title, description, why, fix, standard_refs — or None if unknown.
    """
    # Try exact match first, then prefix match
    if finding_id in RULE_CATALOG:
        return {"id": finding_id, **RULE_CATALOG[finding_id]}

    # Try prefix match (e.g., 'FF-RETRY-001' matches 'FF-RETRY')
    for prefix, explanation in RULE_CATALOG.items():
        if finding_id.startswith(prefix):
            return {"id": finding_id, "matched_rule": prefix, **explanation}

    return None
