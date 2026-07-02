"""Analyzer protocol and base classes.

Every analyzer in FailFast implements the Analyzer protocol. This keeps
the core engine decoupled from any specific analysis tool (Ruff, Bandit,
custom AST rules, etc.) and makes it trivial to add new analyzers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from failfast.models import AnalysisContext, Finding


@runtime_checkable
class Analyzer(Protocol):
    """Protocol that all analyzers must implement.

    An analyzer takes an AnalysisContext and returns a list of Findings.
    It should be stateless — all configuration comes from the context.
    """

    @property
    def name(self) -> str:
        """Human-readable name of this analyzer, e.g. 'Ruff', 'Bandit'."""
        ...

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run analysis and return findings.

        Args:
            context: The analysis context containing repo path, file list,
                     and profile configuration.

        Returns:
            A list of Finding objects. May be empty if no issues are found.
        """
        ...
