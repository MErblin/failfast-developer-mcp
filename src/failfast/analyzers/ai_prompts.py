"""Analyzer to detect large inline/hardcoded prompts in business logic."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

PROMPT_VAR_KEYWORDS = {"prompt", "instruction", "system_msg", "system_prompt", "sys_prompt"}


class PromptInlineAnalyzer:
    """Detects large inline prompts embedded in code and suggests externalizing them."""

    @property
    def name(self) -> str:
        return "PromptInlineAnalyzer"

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

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    var_name = self._get_var_name(target)
                    if not var_name:
                        continue

                    # Check if variable name matches key prompt indicators
                    if any(keyword in var_name.lower() for keyword in PROMPT_VAR_KEYWORDS):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            prompt_str = node.value.value
                            # Flag if string is long (> 200 chars) and spans multiple lines (> 3 lines)
                            if len(prompt_str) > 200 and len(prompt_str.splitlines()) > 3:
                                evidence = source.splitlines()[node.lineno - 1]
                                findings.append(
                                    Finding(
                                        id="FF-AI-PROMPT-INLINE",
                                        title=f"Large prompt template hardcoded inline in '{var_name}'",
                                        severity=Severity.MEDIUM,
                                        category=Category.AI_SAFETY,
                                        file_path=rel_path,
                                        line=node.lineno,
                                        evidence=evidence,
                                        why=(
                                            "Hardcoding large system prompts, instructions, or few-shot examples "
                                            "directly in Python source code makes iteration and testing difficult. "
                                            "Separation of concerns dictates prompt externalization from logic."
                                        ),
                                        fix=(
                                            "Move the prompt template into an external configuration file (e.g. prompts/system.txt "
                                            "or a YAML config) and load it at runtime using file reading or a template manager."
                                        ),
                                        standard_refs=["LLM Application Architecture Patterns"],
                                        blocking=False,
                                    )
                                )

        return findings

    def _get_var_name(self, target: ast.expr) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
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
