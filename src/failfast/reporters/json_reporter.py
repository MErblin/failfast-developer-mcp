"""JSON reporter — serializes Scorecard to structured JSON.

The JSON output is designed for programmatic consumption: CI pipelines,
GitHub Actions, or any tool that needs to parse FailFast results.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from failfast.models import Scorecard


def to_json(scorecard: Scorecard, indent: int = 2) -> str:
    """Serialize a Scorecard to a JSON string.

    Args:
        scorecard: The scan result to serialize.
        indent: JSON indentation level. Use 0 or None for compact output.

    Returns:
        A JSON string representation of the scorecard.
    """
    return json.dumps(to_dict(scorecard), indent=indent)


def to_dict(scorecard: Scorecard) -> dict[str, Any]:
    """Convert a Scorecard to a plain dict suitable for JSON serialization.

    Args:
        scorecard: The scan result to convert.

    Returns:
        A nested dict with all scorecard data.
    """
    return {
        "version": "1.0.0",
        "verdict": scorecard.verdict.value,
        "summary": scorecard.summary,
        "scan_path": scorecard.scan_path,
        "profile": scorecard.profile,
        "stats": {
            "total_findings": len(scorecard.all_findings),
            "blocker_count": len(scorecard.blockers),
            "warning_count": len(scorecard.warnings),
        },
        "categories": {
            cat.value: {
                "verdict": result.verdict.value,
                "blocker_count": result.blocker_count,
                "warning_count": result.warning_count,
                "findings": [
                    _finding_to_dict(f) for f in result.findings
                ],
            }
            for cat, result in scorecard.categories.items()
        },
        "findings": [
            _finding_to_dict(f) for f in scorecard.all_findings
        ],
    }


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Convert a single Finding to a dict."""
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "file": finding.file_path,
        "line": finding.line,
        "evidence": finding.evidence,
        "why": finding.why,
        "fix": finding.fix,
        "standard_refs": finding.standard_refs,
        "blocking": finding.blocking,
    }
