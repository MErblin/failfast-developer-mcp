"""Analyzer to verify configuration safety for AWS Bedrock, Azure OpenAI, and GCP Vertex AI."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from failfast.models import Category, Finding, Severity

if TYPE_CHECKING:
    from failfast.models import AnalysisContext

logger = logging.getLogger(__name__)


class ProviderConfigAnalyzer:
    """Checks model invocation calls for proper guardrails and API safety configurations."""

    @property
    def name(self) -> str:
        return "ProviderConfigAnalyzer"

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
                # 1. AWS Bedrock check
                bedrock_finding = self._check_bedrock(node, source, rel_path)
                if bedrock_finding:
                    findings.append(bedrock_finding)

                # 2. GCP Vertex AI check
                vertex_finding = self._check_vertex(node, source, rel_path)
                if vertex_finding:
                    findings.append(vertex_finding)

                # 3. Azure OpenAI check
                azure_finding = self._check_azure(node, source, rel_path)
                if azure_finding:
                    findings.append(azure_finding)

        return findings

    def _check_bedrock(self, node: ast.Call, source: str, rel_path: str) -> Finding | None:
        """Flag Bedrock invoke_model or converse calls missing guardrail identifiers."""
        method_name = self._get_method_name(node.func)
        if method_name not in ("invoke_model", "invoke_model_with_response_stream", "converse"):
            return None

        # Check if the call is on a client that looks like Bedrock (we scan boto3 calls)
        # Verify if guardrailIdentifier is present in keywords
        has_guardrail_id = any(kw.arg == "guardrailIdentifier" for kw in node.keywords)
        has_guardrail_ver = any(kw.arg == "guardrailVersion" for kw in node.keywords)

        if not (has_guardrail_id and has_guardrail_ver):
            evidence = source.splitlines()[node.lineno - 1]
            return Finding(
                id="FF-AI-BEDROCK-GUARD",
                title="Amazon Bedrock model invocation missing Guardrails",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                file_path=rel_path,
                line=node.lineno,
                evidence=evidence,
                why=(
                    "Amazon Bedrock calls without configured Guardrails skip system-level "
                    "content filtering, PII masking, and safety policies. This violates security "
                    "compliance standards and exposes the application to prompt injection vulnerabilities."
                ),
                fix=(
                    "Pass 'guardrailIdentifier' and 'guardrailVersion' keywords to the Bedrock client call: "
                    "`client.invoke_model(..., guardrailIdentifier='my-id', guardrailVersion='1')`"
                ),
                standard_refs=["OWASP LLM02:2023 - Sensitive Information Disclosure", "NIST AI RMF"],
                blocking=True,
            )
        return None

    def _check_vertex(self, node: ast.Call, source: str, rel_path: str) -> Finding | None:
        """Flag GCP Vertex AI / Gemini model instantiations missing safety settings."""
        func_name = self._get_method_name(node.func)
        if func_name != "GenerativeModel":
            return None

        has_safety = any(kw.arg == "safety_settings" for kw in node.keywords)

        if not has_safety:
            evidence = source.splitlines()[node.lineno - 1]
            return Finding(
                id="FF-AI-VERTEX-SAFETY",
                title="Vertex AI GenerativeModel missing safety_settings",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                file_path=rel_path,
                line=node.lineno,
                evidence=evidence,
                why=(
                    "Vertex AI GenerativeModel instances instantiated without explicit safety_settings "
                    "fall back to default models which may let hate speech, harassment, or dangerous "
                    "content pass unchecked. Explicit configuration secures model behavior against adversarial inputs."
                ),
                fix=(
                    "Define safety configurations and pass them using 'safety_settings': "
                    "`GenerativeModel(model_name='gemini-pro', safety_settings=my_safety_config)`"
                ),
                standard_refs=["OWASP LLM01:2023 - Prompt Injection", "GCP Enterprise AI Guidance"],
                blocking=True,
            )
        return None

    def _check_azure(self, node: ast.Call, source: str, rel_path: str) -> Finding | None:
        """Flag AzureOpenAI client configuration missing or using deprecated api_version."""
        func_name = self._get_method_name(node.func)
        if func_name != "AzureOpenAI":
            return None

        # Check for api_version keyword argument
        api_version_kw = next((kw for kw in node.keywords if kw.arg == "api_version"), None)

        if not api_version_kw:
            evidence = source.splitlines()[node.lineno - 1]
            return Finding(
                id="FF-AI-AZURE-VERSION",
                title="Azure OpenAI client missing api_version parameter",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                file_path=rel_path,
                line=node.lineno,
                evidence=evidence,
                why=(
                    "Initializing AzureOpenAI client without an explicit api_version will either fail "
                    "at runtime or fetch deprecated versions. A specified stable API version "
                    "protects the application against breaking upstream model deprecations."
                ),
                fix="Pass `api_version='2024-02-15-preview'` (or another stable version) to AzureOpenAI.",
                standard_refs=["OWASP Top 10 A06:2021-Vulnerable and Outdated Components"],
                blocking=True,
            )

        # Check if the api_version value is a legacy version (prior to 2023)
        if isinstance(api_version_kw.value, ast.Constant) and isinstance(api_version_kw.value.value, str):
            version_str = api_version_kw.value.value
            # Check if version looks like "YYYY-MM-DD..." and the year is <= 2022
            parts = version_str.split("-")
            if parts and parts[0].isdigit() and int(parts[0]) <= 2022:
                evidence = source.splitlines()[node.lineno - 1]
                return Finding(
                    id="FF-AI-AZURE-VERSION",
                    title=f"Azure OpenAI client using deprecated API version '{version_str}'",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    file_path=rel_path,
                    line=node.lineno,
                    evidence=evidence,
                    why=(
                        f"The API version '{version_str}' is deprecated by Microsoft and scheduled for termination. "
                        "Running deprecated versions will cause complete service outage once the endpoint is deactivated."
                    ),
                    fix="Update api_version to a recent stable version, e.g. `'2024-02-01'` or newer.",
                    standard_refs=["OWASP Top 10 A06:2021-Vulnerable and Outdated Components"],
                    blocking=True,
                )

        return None

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
