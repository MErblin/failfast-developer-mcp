"""Bandit analyzer — wraps Bandit for Python security scanning.

Bandit finds common security issues in Python code: hardcoded passwords,
use of eval/exec, insecure cryptography, SQL injection patterns, etc.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from failfast.models import AnalysisContext, Category, Finding, Severity

logger = logging.getLogger(__name__)

# Map Bandit severity/confidence to FailFast severity
BANDIT_SEVERITY_MAP = {
    ("HIGH", "HIGH"): Severity.CRITICAL,
    ("HIGH", "MEDIUM"): Severity.HIGH,
    ("HIGH", "LOW"): Severity.MEDIUM,
    ("MEDIUM", "HIGH"): Severity.HIGH,
    ("MEDIUM", "MEDIUM"): Severity.MEDIUM,
    ("MEDIUM", "LOW"): Severity.LOW,
    ("LOW", "HIGH"): Severity.MEDIUM,
    ("LOW", "MEDIUM"): Severity.LOW,
    ("LOW", "LOW"): Severity.INFO,
}

# OWASP mappings for common Bandit test IDs
OWASP_REFS: dict[str, list[str]] = {
    "B101": ["OWASP Secure Coding - Error Handling"],
    "B102": ["OWASP A03:2021 - Injection"],
    "B103": ["OWASP Secure Coding - System Configuration"],
    "B104": ["OWASP A07:2021 - Identification and Authentication Failures"],
    "B105": ["OWASP A07:2021 - Identification and Authentication Failures"],
    "B106": ["OWASP A07:2021 - Identification and Authentication Failures"],
    "B107": ["OWASP A07:2021 - Identification and Authentication Failures"],
    "B108": ["OWASP A01:2021 - Broken Access Control"],
    "B110": ["OWASP Secure Coding - Error Handling"],
    "B112": ["OWASP Secure Coding - Error Handling"],
    "B201": ["OWASP A03:2021 - Injection"],
    "B301": ["OWASP A08:2021 - Software and Data Integrity Failures"],
    "B302": ["OWASP A08:2021 - Software and Data Integrity Failures"],
    "B303": ["OWASP A02:2021 - Cryptographic Failures"],
    "B304": ["OWASP A02:2021 - Cryptographic Failures"],
    "B305": ["OWASP A02:2021 - Cryptographic Failures"],
    "B306": ["OWASP A02:2021 - Cryptographic Failures"],
    "B307": ["OWASP A03:2021 - Injection"],
    "B308": ["OWASP A03:2021 - Injection"],
    "B310": ["OWASP A10:2021 - Server-Side Request Forgery"],
    "B311": ["OWASP A02:2021 - Cryptographic Failures"],
    "B312": ["OWASP A02:2021 - Cryptographic Failures"],
    "B320": ["OWASP A03:2021 - Injection"],
    "B321": ["OWASP A02:2021 - Cryptographic Failures"],
    "B323": ["OWASP A02:2021 - Cryptographic Failures"],
    "B324": ["OWASP A02:2021 - Cryptographic Failures"],
    "B501": ["OWASP A02:2021 - Cryptographic Failures"],
    "B502": ["OWASP A02:2021 - Cryptographic Failures"],
    "B503": ["OWASP A02:2021 - Cryptographic Failures"],
    "B504": ["OWASP A02:2021 - Cryptographic Failures"],
    "B505": ["OWASP A02:2021 - Cryptographic Failures"],
    "B506": ["OWASP A05:2021 - Security Misconfiguration"],
    "B507": ["OWASP A02:2021 - Cryptographic Failures"],
    "B601": ["OWASP A03:2021 - Injection"],
    "B602": ["OWASP A03:2021 - Injection"],
    "B603": ["OWASP A03:2021 - Injection"],
    "B604": ["OWASP A03:2021 - Injection"],
    "B605": ["OWASP A03:2021 - Injection"],
    "B606": ["OWASP A03:2021 - Injection"],
    "B607": ["OWASP A03:2021 - Injection"],
    "B608": ["OWASP A03:2021 - Injection"],
    "B609": ["OWASP A03:2021 - Injection"],
    "B610": ["OWASP A03:2021 - Injection"],
    "B611": ["OWASP A03:2021 - Injection"],
    "B701": ["OWASP A03:2021 - Injection"],
    "B702": ["OWASP A03:2021 - Injection"],
    "B703": ["OWASP A03:2021 - Injection"],
}


class BanditAnalyzer:
    """Wraps `bandit` to produce security-focused FailFast findings."""

    @property
    def name(self) -> str:
        return "Bandit"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run bandit and return security findings."""
        target = context.repo_path

        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-r",
                    target,
                    "-f",
                    "json",
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=context.repo_path,
            )
        except FileNotFoundError:
            logger.error("bandit not found on PATH. Install with: uv pip install bandit")
            return []
        except subprocess.TimeoutExpired:
            logger.error("bandit timed out after 120 seconds.")
            return []

        output = result.stdout.strip()
        if not output:
            return []

        try:
            bandit_output = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse bandit JSON output: %s", output[:200])
            return []

        bandit_results = bandit_output.get("results", [])
        findings: list[Finding] = []
        repo_root = Path(context.repo_path).resolve()

        for item in bandit_results:
            test_id = item.get("test_id", "UNKNOWN")
            test_name = item.get("test_name", "unknown")
            issue_text = item.get("issue_text", "")
            filename = item.get("filename", "")
            line_number = item.get("line_number", 0)
            issue_severity = item.get("issue_severity", "MEDIUM").upper()
            issue_confidence = item.get("issue_confidence", "MEDIUM").upper()
            code_snippet = item.get("code", "")

            # Make path relative
            try:
                rel_path = str(Path(filename).resolve().relative_to(repo_root))
            except ValueError:
                rel_path = filename

            # Filter to only files in scope
            if context.files and rel_path not in context.files:
                continue

            # Map severity
            severity = BANDIT_SEVERITY_MAP.get(
                (issue_severity, issue_confidence), Severity.MEDIUM
            )

            # Blocking if HIGH severity from Bandit
            blocking = issue_severity == "HIGH"

            # Get OWASP references
            standard_refs = OWASP_REFS.get(test_id, ["OWASP Secure Coding Practices"])
            standard_refs = [*standard_refs, "OpenSSF Python Secure Coding Guide"]

            findings.append(
                Finding(
                    id=f"FF-SECURITY-{test_id}",
                    title=f"Bandit {test_id} ({test_name}): {issue_text}",
                    severity=severity,
                    category=Category.SECURITY,
                    file_path=rel_path,
                    line=line_number,
                    evidence=code_snippet.strip() if code_snippet else issue_text,
                    why=(
                        f"Security issue detected with {issue_severity} severity "
                        f"and {issue_confidence} confidence. {issue_text}"
                    ),
                    fix=(
                        f"Address {test_id} ({test_name}). See Bandit documentation: "
                        f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}_{test_name}.html"
                    ),
                    standard_refs=standard_refs,
                    blocking=blocking,
                )
            )

        return findings
