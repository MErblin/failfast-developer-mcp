"""Complexity analyzer — wraps Radon for cyclomatic complexity measurement.

Cyclomatic complexity counts the number of independent execution paths through
a function. High complexity means more branches, more edge cases, and higher
defect density. Functions above CC 15 are nearly impossible to fully test.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from failfast.models import AnalysisContext, Category, Finding, Severity

logger = logging.getLogger(__name__)


class ComplexityAnalyzer:
    """Wraps `radon cc` to detect overly complex functions and methods."""

    @property
    def name(self) -> str:
        return "ComplexityAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run radon cc and flag functions exceeding the complexity threshold."""
        target = context.repo_path
        max_complexity = context.max_complexity

        try:
            result = subprocess.run(
                [
                    "radon",
                    "cc",
                    target,
                    "-j",       # JSON output
                    "-n", "C",  # Show C (complex) and above — filters out simple functions
                    "-s",       # Show complexity score
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=context.repo_path,
            )
        except FileNotFoundError:
            logger.error("radon not found on PATH. Install with: uv pip install radon")
            return []
        except subprocess.TimeoutExpired:
            logger.error("radon timed out after 120 seconds.")
            return []

        output = result.stdout.strip()
        if not output:
            return []

        try:
            radon_output = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse radon JSON output: %s", output[:200])
            return []

        findings: list[Finding] = []
        repo_root = Path(context.repo_path).resolve()

        # radon JSON: { "filepath": [ { "name", "lineno", "complexity", "type", ... } ] }
        for filepath, blocks in radon_output.items():
            # Make path relative
            try:
                rel_path = str(Path(filepath).resolve().relative_to(repo_root))
            except ValueError:
                rel_path = filepath

            # Filter to only files in scope
            if context.files and rel_path not in context.files:
                continue

            for block in blocks:
                name = block.get("name", "unknown")
                lineno = block.get("lineno", 0)
                complexity = block.get("complexity", 0)
                block_type = block.get("type", "function")
                rank = block.get("rank", "?")

                # Only flag functions exceeding our threshold
                if complexity < max_complexity:
                    continue

                # Determine severity based on how far over the threshold
                if complexity >= max_complexity * 2:
                    severity = Severity.CRITICAL
                elif complexity >= max_complexity * 1.5:
                    severity = Severity.HIGH
                else:
                    severity = Severity.HIGH

                findings.append(
                    Finding(
                        id=f"FF-COMPLEXITY-{rank}",
                        title=(
                            f"{block_type.capitalize()} '{name}' has cyclomatic "
                            f"complexity {complexity} (threshold: {max_complexity})"
                        ),
                        severity=severity,
                        category=Category.MAINTAINABILITY,
                        file_path=rel_path,
                        line=lineno,
                        evidence=(
                            f"{block_type} {name} at line {lineno}: "
                            f"CC={complexity} (rank {rank})"
                        ),
                        why=(
                            f"This {block_type} has {complexity} independent execution "
                            f"paths. Functions above CC {max_complexity} are difficult to "
                            f"test exhaustively and have higher defect density. Each "
                            f"untested path is a potential production incident."
                        ),
                        fix=(
                            f"Reduce complexity of '{name}' by: "
                            f"(1) extracting helper functions, "
                            f"(2) using early returns to reduce nesting, "
                            f"(3) replacing complex conditionals with lookup tables, "
                            f"(4) moving validation into dedicated validators."
                        ),
                        standard_refs=[
                            "McCabe Complexity Metric",
                            "NIST SSDF PW.5 - Secure Coding Practices",
                        ],
                        blocking=True,
                    )
                )

        return findings
