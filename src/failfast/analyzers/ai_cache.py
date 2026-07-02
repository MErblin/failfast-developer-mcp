"""Analyzer to detect missing completion caching layers in LLM applications."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

CACHE_INDICATORS = {"gptcache", "redis", "diskcache", "dogpile.cache", "memcache"}


class CacheAnalyzer:
    """Checks for exact or semantic caching in files making repetitive LLM requests."""

    @property
    def name(self) -> str:
        return "CacheAnalyzer"

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
        has_llm_call = False
        has_cache_import = False

        # Inspect imports and LLM calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base_name = alias.name.split(".")[0]
                    if base_name in CACHE_INDICATORS or "cache" in base_name:
                        has_cache_import = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base_module = module.split(".")[0]
                if base_module in CACHE_INDICATORS or "cache" in base_module or "cache" in module:
                    has_cache_import = True

            elif isinstance(node, ast.Call):
                func_name = self._get_method_name(node.func)
                # Check for standard LLM completion methods
                if func_name in ("create", "generate_content", "converse", "invoke_model", "invoke", "parse"):
                    has_llm_call = True
                # Check for Langchain set_llm_cache
                if func_name == "set_llm_cache":
                    has_cache_import = True

        # If LLM calls are present but no cache initialization or caching imports are configured
        if has_llm_call and not has_cache_import:
            # Find the line of the first LLM call to attach the finding to
            llm_line = 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = self._get_method_name(node.func)
                    if func_name in ("create", "generate_content", "converse", "invoke_model", "invoke", "parse"):
                        llm_line = node.lineno
                        break

            evidence = source.splitlines()[llm_line - 1] if source.splitlines() else ""
            findings.append(
                Finding(
                    id="FF-AI-CACHE",
                    title="LLM completion call missing caching layer",
                    severity=Severity.MEDIUM,
                    category=Category.AI_SAFETY,
                    file_path=rel_path,
                    line=llm_line,
                    evidence=evidence,
                    why=(
                        "Repeated or semantically close queries to LLM providers generate redundant API charges "
                        "and slow down user requests. Caching layers (like GPTCache or Redis) significantly "
                        "improve system latency and cost efficiency in production."
                    ),
                    fix=(
                        "Configure a semantic or exact matching caching layer (e.g. GPTCache or a Redis cache) "
                        "to wrap model completions: e.g. `from gptcache.adapter.openai import openai as cached_openai`."
                    ),
                    standard_refs=["AWS Well-Architected Cost Optimization", "Google Enterprise AI Best Practices"],
                    blocking=False,
                )
            )

        return findings

    def _get_method_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

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
