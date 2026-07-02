"""Analyzer to verify structured parsing of LLM outputs."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

# Variable names or attributes that commonly hold raw LLM text/response payloads
LLM_CONTENT_INDICATORS = {
    "content",
    "text",
    "response",
    "completion",
    "output",
    "result",
    "message",
    "choices",
    "llm_output",
    "model_output",
}


class OutputParsingAnalyzer:
    """Checks for unsafe parsing of LLM outputs, e.g. raw json.loads calls on response text without error handling."""

    @property
    def name(self) -> str:
        return "OutputParsingAnalyzer"

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

        # Track if the file imports LLM modules to raise confidence on raw parsing checks
        imports_llm = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("openai", "anthropic", "google.generativeai", "vertexai", "boto3"):
                        imports_llm = True
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if any(lib in module for lib in ("openai", "anthropic", "google.generativeai", "vertexai", "boto3")):
                    imports_llm = True

        # Walk nodes to find json.loads calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name == "json.loads":
                    parsing_finding = self._check_json_loads(node, source, rel_path, imports_llm, tree)
                    if parsing_finding:
                        findings.append(parsing_finding)

        return findings

    def _check_json_loads(
        self,
        node: ast.Call,
        source: str,
        rel_path: str,
        imports_llm: bool,
        tree: ast.AST,
    ) -> Finding | None:
        """Check if json.loads is safely wrapped and if it operates on LLM outputs."""
        if not node.args:
            return None

        target_arg = node.args[0]
        arg_name = self._get_var_name(target_arg)

        # Check if the target argument name or dot-access looks like LLM output
        is_llm_target = False
        if arg_name:
            is_llm_target = any(indicator in arg_name.lower() for indicator in LLM_CONTENT_INDICATORS)

        # If it doesn't look like LLM content and the file doesn't import LLM tools, skip
        if not (is_llm_target or imports_llm):
            return None

        # Verify if this call is wrapped in a Try-Except block that handles decoding errors
        is_safe = self._is_within_safe_try_except(node, tree)

        if not is_safe:
            evidence = source.splitlines()[node.lineno - 1]
            return Finding(
                id="FF-AI-RAWPARSING",
                title="Unsafe JSON parsing of LLM response without error handling",
                severity=Severity.HIGH,
                category=Category.RELIABILITY,
                file_path=rel_path,
                line=node.lineno,
                evidence=evidence,
                why=(
                    "LLMs are probabilistic and can return malformed JSON, system preambles, or markdown "
                    "formatting wrappers (e.g. ```json ... ```). Calling json.loads on a raw model response "
                    "without wrapping it in a try-except block causes direct runtime failures (JSONDecodeError) "
                    "on unexpected or structured response deviations."
                ),
                fix=(
                    "Wrap the json.loads call in a try-except block catching JSONDecodeError:\n"
                    "    try:\n"
                    "        data = json.loads(response_text)\n"
                    "    except json.JSONDecodeError:\n"
                    "        # Handle parsing failure or fallback"
                ),
                standard_refs=["OWASP LLM05:2023 - Improper Output Handling"],
                blocking=True,
            )

        return None

    def _get_call_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return None

    def _get_var_name(self, node: ast.expr) -> str | None:
        """Extract a simplified string representation of the variable name or property."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            val_name = self._get_var_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
            return node.attr
        return None

    def _is_within_safe_try_except(self, target_node: ast.Call, tree: ast.AST) -> bool:
        """Walk up the AST parents of the target call node to check for try-except blocks."""
        # Since standard AST does not have parent pointers, we do a quick top-down search
        # keeping track of the current path of Try blocks.
        return self._search_try_parent(tree, target_node, [])

    def _search_try_parent(self, current: ast.AST, target: ast.Call, active_tries: list[ast.Try]) -> bool:
        if current is target:
            # We found the target node! Check if any of the active try blocks are safe
            for try_node in active_tries:
                if self._has_json_exception_handler(try_node):
                    return True
            return False

        # Recurse child nodes
        for child in ast.iter_child_nodes(current):
            if isinstance(child, ast.Try):
                if self._search_try_parent(child, target, active_tries + [child]):
                    return True
            else:
                if self._search_try_parent(child, target, active_tries):
                    return True

        return False

    def _has_json_exception_handler(self, try_node: ast.Try) -> bool:
        """Check if a try block catches JSONDecodeError, ValueError, or Exception."""
        for handler in try_node.handlers:
            if handler.type is None:
                # Bare except: catches everything
                return True
            
            # Check the exception classes matched
            classes = []
            if isinstance(handler.type, ast.Name):
                classes.append(handler.type.id)
            elif isinstance(handler.type, ast.Attribute):
                classes.append(self._get_var_name(handler.type) or "")
            elif isinstance(handler.type, ast.Tuple):
                for el in handler.type.elts:
                    if isinstance(el, ast.Name):
                        classes.append(el.id)
                    elif isinstance(el, ast.Attribute):
                        classes.append(self._get_var_name(el) or "")

            for name in classes:
                if "JSONDecodeError" in name or "ValueError" in name or "Exception" in name:
                    return True
        return False

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
