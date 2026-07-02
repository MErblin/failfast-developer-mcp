"""Analyzer to detect runaway agent loops (unbounded loops containing LLM calls)."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)

# Method names commonly associated with calling LLMs or agent steps
LLM_CALL_METHODS = {
    "create",              # openai.chat.completions.create
    "generate_content",    # gemini / vertex
    "invoke",              # langchain / semantic kernel
    "invoke_model",        # bedrock
    "converse",            # bedrock
    "run",                 # crewai / autogen / agents
    "chat",                # generic chat agents
    "predict",             # langchain legacy
}


class AgentLoopAnalyzer:
    """Detects loops containing LLM calls that lack maximum step/iteration limits."""

    @property
    def name(self) -> str:
        return "AgentLoopAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Analyze files in the context for runaway agent loops."""
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
        """Search the AST for while/for loops calling LLMs."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                loop_findings = self._check_while_loop(node, source, rel_path)
                findings.extend(loop_findings)

        return findings

    def _check_while_loop(self, node: ast.While, source: str, rel_path: str) -> list[Finding]:
        """Verify that a while loop calling LLM methods has an iteration boundary check."""
        findings: list[Finding] = []

        # Step 1: Check if the loop contains any LLM calls
        llm_calls = self._find_llm_calls(node)
        if not llm_calls:
            return []

        # Step 2: Analyze loop boundary safety
        # If the test is explicitly constant True, or a simple loop variable without checks,
        # we check the body for conditional breaks that check a loop counter.
        is_safe = False

        # Check if the loop test itself checks a limit (e.g., while steps < max_steps:)
        if self._is_loop_condition_safe(node.test):
            is_safe = True

        # Check if any break or return in the loop body is conditionally triggered by a loop counter limit
        if not is_safe and self._has_safe_conditional_break(node.body):
            is_safe = True

        if not is_safe:
            # We found a loop containing LLM calls without a step check
            evidence = source.splitlines()[node.lineno - 1]
            why = (
                "Agent reasoning loops (ReAct/Reflexion patterns) calling LLMs inside a loop "
                "must configure an explicit maximum iteration limit. Without this, the agent "
                "can enter an endless loop (runaway reasoning) due to model hallucinations, "
                "leading to service hangs and massive API usage bills."
            )
            fix = (
                "Introduce a step counter: initialize `steps = 0` outside the loop, "
                "increment `steps += 1` inside, and add a guard condition: "
                "`if steps >= max_steps: raise TimeoutError('Agent reached maximum step limit')` or `break`."
            )

            findings.append(
                Finding(
                    id="FF-AI-RUNAWAY",
                    title="Agent reasoning loop missing maximum iteration limit",
                    severity=Severity.HIGH,
                    category=Category.RELIABILITY,
                    file_path=rel_path,
                    line=node.lineno,
                    evidence=evidence,
                    why=why,
                    fix=fix,
                    standard_refs=["OWASP LLM06:2023 - Excessive Agency", "AWS Well-Architected Reliability"],
                    blocking=True,
                )
            )

        return findings

    def _find_llm_calls(self, node: ast.AST) -> list[ast.Call]:
        """Find all LLM-like call nodes within this AST subtree."""
        calls: list[ast.Call] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                method_name = self._get_method_name(child.func)
                if method_name in LLM_CALL_METHODS:
                    calls.append(child)
        return calls

    def _get_method_name(self, node: ast.expr) -> str | None:
        """Extract the method name from a call function node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _is_loop_condition_safe(self, test: ast.expr) -> bool:
        """Check if the while loop condition is bounded (e.g., checks against a count)."""
        # If the test is `while step < max_steps:`
        if isinstance(test, ast.Compare):
            # Check if one of the operands is compared to a number or a variable containing "limit" or "max"
            for op in [test.left] + test.comparators:
                if isinstance(op, ast.Name) and any(x in op.id.lower() for x in ("step", "count", "iter", "limit", "max")):
                    return True
                if isinstance(op, ast.Constant) and isinstance(op.value, (int, float)):
                    return True
        return False

    def _has_safe_conditional_break(self, body: list[ast.stmt]) -> bool:
        """Walk the loop body to see if there is a conditional break/return based on a counter."""
        for node in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(node, ast.If):
                # Check if the if-condition is checking a loop counter limit
                if self._is_loop_condition_safe(node.test):
                    # Check if the if-body contains a Break or Return statement
                    for child in node.body:
                        if isinstance(child, (ast.Break, ast.Return)):
                            return True
        return False

    def _discover_python_files(self, root: Path) -> list[str]:
        """Discover Python files in a directory."""
        excluded = {".git", ".venv", "venv", "__pycache__", "node_modules"}
        files: list[str] = []
        for path in root.rglob("*.py"):
            if not any(part in excluded for part in path.parts):
                try:
                    files.append(str(path.relative_to(root)))
                except ValueError:
                    pass
        return sorted(files)
