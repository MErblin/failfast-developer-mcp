"""Analyzer to verify content and prompt guardrails or validation layers in LLM files."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

GUARDRAIL_LIBRARIES = {"guardrails", "nemoguardrails", "llama_guard", "guardrails_ai"}


class GuardrailsAnalyzer:
    """Checks for prompt/output validation layers to protect against injection and hallucinations."""

    @property
    def name(self) -> str:
        return "GuardrailsAnalyzer"

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
        has_guard_import = False
        has_pydantic_parsing = False

        # Step 1: Detect LLM calls, imports, and Pydantic parsing
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    base_name = alias.name.split(".")[0]
                    if base_name in GUARDRAIL_LIBRARIES:
                        has_guard_import = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base_module = module.split(".")[0]
                if base_module in GUARDRAIL_LIBRARIES:
                    has_guard_import = True
                if "pydantic" in base_module:
                    has_pydantic_parsing = True

            elif isinstance(node, ast.Call):
                func_name = self._get_method_name(node.func)
                # Check for LLM-like call names
                if func_name in ("create", "generate_content", "converse", "invoke_model", "invoke"):
                    has_llm_call = True
                # Check if calling client.beta.chat.completions.parse (OpenAI Structured Output)
                if func_name == "parse" or "completions.parse" in (self._get_full_call_path(node.func) or ""):
                    has_pydantic_parsing = True
                    has_llm_call = True

        # If LLM calls are present but neither guardrails nor Pydantic parsing is configured
        if has_llm_call and not (has_guard_import or has_pydantic_parsing):
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
                    id="FF-AI-GUARDRAILS",
                    title="Missing model validation or guardrail layers",
                    severity=Severity.MEDIUM,
                    category=Category.AI_SAFETY,
                    file_path=rel_path,
                    line=llm_line,
                    evidence=evidence,
                    why=(
                        "Passing direct inputs to models and returning raw outputs without validation "
                        "exposes applications to prompt injection attacks and unvalidated model hallucinations. "
                        "Production setups require deterministic guardrail firewalls or structured schema validations."
                    ),
                    fix=(
                        "Integrate a guardrail layer (e.g. Guardrails AI, NeMo Guardrails) or enforce "
                        "Structured Outputs using Pydantic validation: e.g. `client.beta.chat.completions.parse("
                        "model='gpt-4o', response_format=MySchema)`."
                    ),
                    standard_refs=["OWASP LLM01:2023 - Prompt Injection", "OWASP LLM05:2023 - Improper Output Handling"],
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

    def _get_full_call_path(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            val_path = self._get_full_call_path(node.value)
            if val_path:
                return f"{val_path}.{node.attr}"
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
