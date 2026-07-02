"""Analyzer to verify fallback strategies for high-availability LLM client calls."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

LLM_CALL_METHODS = {"create", "generate_content", "converse", "invoke_model", "invoke", "parse"}


class FallbackAnalyzer:
    """Checks that model API invocations have robust try-except fallback configurations for high availability."""

    @property
    def name(self) -> str:
        return "FallbackAnalyzer"

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
            if isinstance(node, ast.Call):
                func_name = self._get_method_name(node.func)
                if func_name in LLM_CALL_METHODS:
                    # Ignore if the call is within an except handler (as it is the fallback path)
                    if self._is_inside_except_handler(node, tree):
                        continue
                    # Found an LLM call. Verify if it has a fallback try-except setup
                    has_fallback = self._has_valid_fallback(node, tree)
                    if not has_fallback:
                        evidence = source.splitlines()[node.lineno - 1]
                        findings.append(
                            Finding(
                                id="FF-AI-FALLBACK",
                                title=f"LLM call '{func_name}' missing model/provider fallback",
                                severity=Severity.MEDIUM,
                                category=Category.AI_SAFETY,
                                file_path=rel_path,
                                line=node.lineno,
                                evidence=evidence,
                                why=(
                                    "LLM cloud providers experience transient API outages, rate limit limits (429), "
                                    "or regional network timeouts. Call sites must be wrapped in try-except blocks "
                                    "that route to a secondary fallback model or alternative provider (e.g. Anthropic) to maintain availability."
                                ),
                                fix=(
                                    "Wrap the LLM call in a try-except block, and execute a backup/fallback request "
                                    "in the exception handler: \n"
                                    "    try:\n"
                                    "        res = client.chat.completions.create(model='gpt-4o', ...)\n"
                                    "    except Exception:\n"
                                    "        res = backup_client.messages.create(model='claude-3-haiku', ...)"
                                ),
                                standard_refs=["AWS Well-Architected: Reliability Pillar", "Enterprise AI HA Patterns"],
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

    def _has_valid_fallback(self, target_node: ast.Call, tree: ast.AST) -> bool:
        """Verify if the target LLM call is located inside a try-except block with a fallback call."""
        # Top-down search to find if target is inside a Try block's main body,
        # and if that Try block has a fallback call in its handlers.
        return self._search_try_parent(tree, target_node, [])

    def _search_try_parent(self, current: ast.AST, target: ast.Call, active_tries: list[ast.Try]) -> bool:
        if current is target:
            # We found the target LLM call! Let's check if any active try block has a fallback call in its except body
            for try_node in active_tries:
                # Target call must be in the main body (try_node.body), not in the handlers
                if any(self._is_node_in_subtree(target, item) for item in try_node.body):
                    if self._has_llm_call_in_handlers(try_node.handlers):
                        return True
            return False

        # Recurse children
        for child in ast.iter_child_nodes(current):
            if isinstance(child, ast.Try):
                if self._search_try_parent(child, target, active_tries + [child]):
                    return True
            else:
                if self._search_try_parent(child, target, active_tries):
                    return True

        return False

    def _is_node_in_subtree(self, target: ast.AST, root: ast.AST) -> bool:
        """Check if target node exists within the root AST subtree."""
        for child in ast.walk(root):
            if child is target:
                return True
        return False

    def _has_llm_call_in_handlers(self, handlers: list[ast.ExceptHandler]) -> bool:
        """Return True if any of the handlers contain an LLM-like call in their body."""
        for handler in handlers:
            for node in ast.walk(handler):
                if isinstance(node, ast.Call):
                    name = self._get_method_name(node.func)
                    if name in LLM_CALL_METHODS:
                        return True
        return False

    def _is_inside_except_handler(self, target: ast.Call, tree: ast.AST) -> bool:
        """Return True if the target call is located inside an ExceptHandler block."""
        return self._search_except_parent(tree, target)

    def _search_except_parent(self, current: ast.AST, target: ast.Call) -> bool:
        for child in ast.iter_child_nodes(current):
            if isinstance(child, ast.ExceptHandler):
                if self._is_node_in_subtree(target, child):
                    return True
            else:
                if self._search_except_parent(child, target):
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
