"""Ruff analyzer — wraps the Ruff linter for code quality findings.

Ruff covers 900+ lint rules across dozens of Python quality dimensions.
We run it as a subprocess and map its JSON output to FailFast findings.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from failfast.models import AnalysisContext, Category, Finding, Severity

logger = logging.getLogger(__name__)

# Ruff severity mapping: ruff doesn't have severity, so we infer from rule prefix
# Rules that indicate actual bugs get higher severity than style issues
HIGH_SEVERITY_PREFIXES = {"B", "S", "RUF", "F"}  # bugbear, bandit-compat, ruff, pyflakes
MEDIUM_SEVERITY_PREFIXES = {"E", "W", "N", "UP", "SIM"}  # style, naming, simplify


class RuffAnalyzer:
    """Wraps `ruff check` to produce FailFast findings."""

    @property
    def name(self) -> str:
        return "Ruff"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run ruff check and return findings."""
        target = context.repo_path

        try:
            result = subprocess.run(
                [
                    "ruff",
                    "check",
                    "--output-format",
                    "json",
                    "--no-fix",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=context.repo_path,
            )
        except FileNotFoundError:
            logger.error("ruff not found on PATH. Install with: uv pip install ruff")
            return []
        except subprocess.TimeoutExpired:
            logger.error("ruff timed out after 120 seconds.")
            return []

        # ruff exits 1 when it finds issues — that's expected
        output = result.stdout.strip()
        if not output:
            return []

        try:
            ruff_findings = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse ruff JSON output: %s", output[:200])
            return []

        findings: list[Finding] = []
        repo_root = Path(context.repo_path).resolve()

        for item in ruff_findings:
            code = item.get("code", "UNKNOWN")
            message = item.get("message", "")
            filename = item.get("filename", "")
            location = item.get("location", {})
            line = location.get("row", 0)

            # Make path relative to repo root
            try:
                rel_path = str(Path(filename).resolve().relative_to(repo_root))
            except ValueError:
                rel_path = filename

            # Filter to only files in scope
            if context.files and rel_path not in context.files:
                continue

            # Determine severity from rule prefix
            prefix = code[0] if code else ""
            if prefix in HIGH_SEVERITY_PREFIXES:
                severity = Severity.HIGH
                blocking = True
            elif prefix in MEDIUM_SEVERITY_PREFIXES:
                severity = Severity.MEDIUM
                blocking = False
            else:
                severity = Severity.LOW
                blocking = False

            findings.append(
                Finding(
                    id=f"FF-LINT-{code}",
                    title=f"Ruff {code}: {message}",
                    severity=severity,
                    category=Category.MAINTAINABILITY,
                    file_path=rel_path,
                    line=line,
                    evidence=message,
                    why=(
                        "Code quality rules catch real bugs (unused variables, "
                        "unreachable code, shadowed names) and enforce consistency "
                        "that reduces cognitive load during reviews and debugging."
                    ),
                    fix=f"Run `ruff check --fix` to auto-fix, or address {code} manually.",
                    standard_refs=["PEP 8", "Ruff Rule Catalog"],
                    blocking=blocking,
                )
            )

        return findings
