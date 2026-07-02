"""Analyzer to detect missing telemetry/observability tracing in LLM applications."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

LLM_LIBRARIES = {"openai", "anthropic", "google.generativeai", "vertexai", "boto3"}
TELEMETRY_LIBRARIES = {
    "langfuse",
    "langsmith",
    "phoenix",
    "opentelemetry",
    "openllmetry",
    "traceloop",
    "datadog",
    "newrelic",
}


class TelemetryAnalyzer:
    """Detects LLM files missing telemetry tracing or observability setups."""

    @property
    def name(self) -> str:
        return "TelemetryAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        repo_root = Path(context.repo_path)

        files = context.files if context.files else self._discover_python_files(repo_root)

        for rel_path in files:
            file_path = repo_root / rel_path
            if not file_path.exists() or file_path.suffix != ".py":
                continue

            try:
                source = file_path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(file_path))
            except (SyntaxError, UnicodeDecodeError) as e:
                logger.debug("Skipping %s: %s", rel_path, e)
                continue

            file_findings = self._analyze_file(tree, source, rel_path)
            findings.extend(file_findings)

        return findings

    def _analyze_file(self, tree: ast.AST, source: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        imports_llm = False
        imports_telemetry = False
        env_has_tracing = False

        # Walk AST to inspect imports and constant environment setups
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name_parts = alias.name.split(".")
                    base_name = name_parts[0]
                    if base_name in LLM_LIBRARIES:
                        imports_llm = True
                    if base_name in TELEMETRY_LIBRARIES:
                        imports_telemetry = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base_module = module.split(".")[0]
                if base_module in LLM_LIBRARIES:
                    imports_llm = True
                if base_module in TELEMETRY_LIBRARIES:
                    imports_telemetry = True
            elif isinstance(node, ast.Assign):
                # Look for tracing configurations in environment variables (e.g. os.environ["LANGFUSE_PUBLIC_KEY"])
                for target in node.targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Attribute)
                        and target.value.attr == "environ"
                    ):
                        if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                            var_name = target.slice.value.upper()
                            if "LANG" in var_name or "TRACE" in var_name or "FUSE" in var_name:
                                env_has_tracing = True

        # If LLM calls are present but no telemetry is set up
        if imports_llm and not (imports_telemetry or env_has_tracing):
            first_line = 1
            evidence = source.splitlines()[0] if source.splitlines() else ""
            findings.append(
                Finding(
                    id="FF-AI-OBSERVABILITY",
                    title="LLM application missing observability telemetry",
                    severity=Severity.MEDIUM,
                    category=Category.AI_SAFETY,
                    file_path=rel_path,
                    line=first_line,
                    evidence=evidence,
                    why=(
                        "Production LLM applications must log model requests, completion tokens, costs, "
                        "and latency using telemetry frameworks (e.g., Langsmith, Langfuse, or OpenLLMetry). "
                        "Without structured tracing, debugging production failures, hallucinations, or billing anomalies is impossible."
                    ),
                    fix=(
                        "Import and configure an LLM tracing client (e.g. Langfuse, Langsmith, or OpenTelemetry), "
                        "or set the standard environment variables (e.g. `os.environ['LANGCHAIN_TRACING_V2'] = 'true'`)."
                    ),
                    standard_refs=["OWASP LLM09:2023 - Overreliance", "Production LLM Observability Guide"],
                    blocking=False,
                )
            )

        return findings

    def _discover_python_files(self, root: Path) -> list[str]:
        excluded = {".git", ".venv", "venv", "__pycache__", "node_modules"}
        files: list[str] = []
        for path in root.rglob("*.py"):
            if not any(part in excluded for part in path.parts):
                try:
                    files.append(str(path.relative_to(root)))
                except ValueError:
                    pass
        return sorted(files)
