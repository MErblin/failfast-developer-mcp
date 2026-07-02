"""SARIF reporter — generates SARIF v2.1.0 output for CI/CD integration.

SARIF (Static Analysis Results Interchange Format) is the standard format
for static analysis tool output. GitHub Code Scanning, Azure DevOps, and
other CI platforms consume SARIF natively.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from failfast import __version__
from failfast.models import Finding, Scorecard, Severity

# Map FailFast severity to SARIF level
SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(scorecard: Scorecard) -> str:
    """Generate a SARIF v2.1.0 JSON string from a Scorecard.

    Args:
        scorecard: The scan result to convert.

    Returns:
        A SARIF-formatted JSON string.
    """
    return json.dumps(to_sarif_dict(scorecard), indent=2)


def to_sarif_dict(scorecard: Scorecard) -> dict[str, Any]:
    """Convert a Scorecard to a SARIF v2.1.0 dict.

    Args:
        scorecard: The scan result to convert.

    Returns:
        A dict conforming to the SARIF v2.1.0 schema.
    """
    # Collect all unique rule IDs for the rules array
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in scorecard.all_findings:
        # Build rule entry (deduplicated by rule ID prefix)
        rule_id = _extract_rule_prefix(finding.id)
        if rule_id not in rules:
            rules[rule_id] = _build_rule(finding, rule_id)

        # Build result entry
        results.append(_build_result(finding, rule_id))

    # Build the SARIF document
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FailFast Developer MCP",
                        "version": __version__,
                        "informationUri": "https://github.com/MErblin/failfast-developer-mcp",
                        "semanticVersion": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "verdict": scorecard.verdict.value,
                            "profile": scorecard.profile,
                            "blockerCount": len(scorecard.blockers),
                            "warningCount": len(scorecard.warnings),
                        },
                    }
                ],
            }
        ],
    }

    return sarif


def _extract_rule_prefix(finding_id: str) -> str:
    """Extract the rule prefix from a finding ID.

    'FF-TIMEOUT-0042' -> 'FF-TIMEOUT'
    'FF-RETRY-NOJITTER-0020' -> 'FF-RETRY-NOJITTER'
    'FF-LINT-E501' -> 'FF-LINT-E501'
    'FF-SECURITY-B303' -> 'FF-SECURITY-B303'
    """
    parts = finding_id.split("-")

    # For IDs ending in a line number (all digits), strip it
    if parts and parts[-1].isdigit() and len(parts[-1]) == 4:
        return "-".join(parts[:-1])

    return finding_id


def _build_rule(finding: Finding, rule_id: str) -> dict[str, Any]:
    """Build a SARIF rule object from a Finding."""
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {
            "text": finding.title,
        },
        "fullDescription": {
            "text": finding.why,
        },
        "help": {
            "text": finding.fix,
            "markdown": f"**How to fix:** {finding.fix}",
        },
        "defaultConfiguration": {
            "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
        },
        "properties": {
            "category": finding.category.value,
            "blocking": finding.blocking,
        },
    }

    # Add help URIs from standard refs
    if finding.standard_refs:
        rule["properties"]["standardRefs"] = finding.standard_refs

    return rule


def _build_result(finding: Finding, rule_id: str) -> dict[str, Any]:
    """Build a SARIF result object from a Finding."""
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": 0,  # Will be set correctly by consumers
        "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
        "message": {
            "text": f"{finding.title}\n\nWhy: {finding.why}\n\nFix: {finding.fix}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.line,
                    },
                },
            }
        ],
    }

    # Add code snippet if we have evidence
    if finding.evidence:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.evidence,
        }

    # Add standard references as related locations metadata
    if finding.standard_refs:
        result["properties"] = {
            "standardRefs": finding.standard_refs,
            "blocking": finding.blocking,
        }

    return result
