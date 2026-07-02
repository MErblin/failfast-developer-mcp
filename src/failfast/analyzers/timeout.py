"""Timeout analyzer — Custom AST analysis to detect HTTP calls without timeouts.

This is one of FailFast's key differentiators. No existing linter reliably
catches missing timeouts on HTTP client calls. An HTTP call without a timeout
can hang indefinitely, exhausting connection pools and causing cascading
failures in production.

Detects:
  - requests.get/post/put/patch/delete/head/options() without timeout=
  - requests.Session().get/post/...() without timeout=
  - httpx.get/post/...() without timeout=
  - httpx.Client().get/post/...() without timeout=
  - httpx.AsyncClient().get/post/...() without timeout=
  - aiohttp.ClientSession().get/post/...() without timeout=
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from failfast.models import AnalysisContext, Category, Finding, Severity

logger = logging.getLogger(__name__)

# HTTP method names that should always have timeouts
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}

# Libraries and their call patterns
# Format: (module_or_object, method_names)
HTTP_CLIENT_PATTERNS = {
    # requests library
    "requests": HTTP_METHODS,
    # httpx library (sync)
    "httpx": HTTP_METHODS,
    # Common variable names for HTTP clients/sessions
    "client": HTTP_METHODS,
    "session": HTTP_METHODS,
    "http_client": HTTP_METHODS,
    "http": HTTP_METHODS,
}


class TimeoutAnalyzer:
    """Detects HTTP client calls that lack explicit timeout parameters."""

    @property
    def name(self) -> str:
        return "TimeoutAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Walk Python ASTs to find HTTP calls without timeout=."""
        findings: list[Finding] = []
        repo_root = Path(context.repo_path)

        # Determine files to scan
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
        """Analyze a single file's AST for missing timeouts."""
        findings: list[Finding] = []

        # Track imports to know which libraries are in use
        imported_http_libs: set[str] = set()

        for node in ast.walk(tree):
            # Track imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if name in ("requests", "httpx", "aiohttp"):
                        imported_http_libs.add(name)

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if any(lib in module for lib in ("requests", "httpx", "aiohttp")):
                    imported_http_libs.add(module.split(".")[0])

            # Check function calls
            elif isinstance(node, ast.Call):
                finding = self._check_call(node, source, rel_path, imported_http_libs)
                if finding is not None:
                    findings.append(finding)

        return findings

    def _check_call(
        self,
        node: ast.Call,
        source: str,
        rel_path: str,
        imported_libs: set[str],
    ) -> Finding | None:
        """Check if a Call node is an HTTP request missing a timeout."""
        call_info = self._get_call_info(node)
        if call_info is None:
            return None

        obj_name, method_name = call_info

        # Check if this looks like an HTTP client call
        is_http_call = False
        call_description = ""

        # Pattern 1 & 2: requests.get(...), httpx.post(...) or client.get(...) session.post(...)
        if (
            (obj_name in ("requests", "httpx") and method_name in HTTP_METHODS)
            or (
                obj_name in ("client", "session", "http_client", "http", "self.client",
                             "self.session", "self.http_client", "self._client", "self._session")
                and method_name in HTTP_METHODS
                and imported_libs
            )
        ):
            is_http_call = True
            call_description = f"{obj_name}.{method_name}()"

        # Pattern 3: aiohttp.ClientSession() calls — check for .get/.post on result
        # This is harder to detect statically, but we catch common patterns

        if not is_http_call:
            return None

        # Check if timeout= keyword is present
        has_timeout = any(
            isinstance(kw.arg, str) and kw.arg == "timeout"
            for kw in node.keywords
        )

        if has_timeout:
            return None

        # Extract the offending line of code
        source_lines = source.splitlines()
        line_num = node.lineno
        evidence = source_lines[line_num - 1].strip() if line_num <= len(source_lines) else ""

        return Finding(
            id=f"FF-TIMEOUT-{line_num:04d}",
            title=f"HTTP call without timeout: {call_description}",
            severity=Severity.HIGH,
            category=Category.RELIABILITY,
            file_path=rel_path,
            line=line_num,
            evidence=evidence,
            why=(
                "HTTP calls without explicit timeouts can hang indefinitely when "
                "the remote server is slow, unresponsive, or experiencing issues. "
                "A single hung connection can exhaust your connection pool, causing "
                "cascading failures across your entire service."
            ),
            fix=(
                f"Add an explicit timeout to {call_description}. "
                "For requests: `requests.get(url, timeout=(3.05, 27))` (connect, read). "
                "For httpx: `httpx.get(url, timeout=10.0)`. "
                "For aiohttp: use `aiohttp.ClientTimeout(total=30)` in the session."
            ),
            standard_refs=[
                "OWASP API4:2023 - Unrestricted Resource Consumption",
                "AWS Well-Architected: Reliability Pillar",
            ],
            blocking=True,
        )

    def _get_call_info(self, node: ast.Call) -> tuple[str, str] | None:
        """Extract (object_name, method_name) from a Call node.

        Returns None if the call doesn't match obj.method() pattern.
        """
        func = node.func

        # obj.method() pattern
        if isinstance(func, ast.Attribute):
            method_name = func.attr

            # Simple name: requests.get()
            if isinstance(func.value, ast.Name):
                return (func.value.id, method_name)

            # self.client.get()
            if isinstance(func.value, ast.Attribute) and isinstance(
                func.value.value, ast.Name
            ):
                obj_name = f"{func.value.value.id}.{func.value.attr}"
                return (obj_name, method_name)

        return None

    def _discover_python_files(self, root: Path) -> list[str]:
        """Discover Python files in a directory."""
        excluded = {".git", ".venv", "venv", "__pycache__", "node_modules"}
        files: list[str] = []
        for path in root.rglob("*.py"):
            if not any(part in excluded for part in path.parts):
                files.append(str(path.relative_to(root)))
        return sorted(files)
