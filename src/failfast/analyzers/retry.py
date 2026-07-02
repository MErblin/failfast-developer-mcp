"""Retry analyzer — Custom AST analysis to detect unsafe retry patterns.

This is one of FailFast's key differentiators. Existing linters don't check
whether retry logic is production-safe. Unsafe retries cause:
  - Thundering herds (all clients retry simultaneously without jitter)
  - Infinite retry loops (no max_attempts)
  - Duplicate side effects (retrying non-idempotent operations like POST /payments)
  - Amplified outages (retrying non-transient errors)

Detects:
  - while/for loops containing time.sleep() or asyncio.sleep() (manual retries)
  - tenacity @retry decorators without stop= or jitter
  - backoff decorators without jitter
  - Manual retry patterns without jitter (sleep with constant delay)
  - Manual retry patterns without max_attempts (infinite while True loops)
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from failfast.models import AnalysisContext, Category, Finding, Severity

logger = logging.getLogger(__name__)


class RetryAnalyzer:
    """Detects unsafe retry patterns in Python code via AST analysis."""

    @property
    def name(self) -> str:
        return "RetryAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Walk Python ASTs to find unsafe retry patterns."""
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
        """Analyze a single file for retry anti-patterns."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Check 1: Manual retry loops (while/for with sleep)
            if isinstance(node, (ast.While, ast.For)):
                loop_findings = self._check_retry_loop(node, source, rel_path)
                findings.extend(loop_findings)

            # Check 2: Tenacity @retry decorator
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorator_findings = self._check_retry_decorators(node, source, rel_path)
                findings.extend(decorator_findings)

        return findings

    def _check_retry_loop(
        self, node: ast.While | ast.For, source: str, rel_path: str
    ) -> list[Finding]:
        """Check if a loop looks like a manual retry with issues."""
        findings: list[Finding] = []
        source_lines = source.splitlines()

        # Look for sleep calls inside the loop body
        sleep_calls: list[ast.Call] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_full_call_name(child)
                if call_name in (
                    "time.sleep",
                    "asyncio.sleep",
                    "await asyncio.sleep",
                    "sleep",
                ):
                    sleep_calls.append(child)

        if not sleep_calls:
            return findings

        # This loop contains sleep — it's likely a retry loop
        line_num = node.lineno
        evidence = source_lines[line_num - 1].strip() if line_num <= len(source_lines) else ""

        # Check 1: Is there jitter? Look for random.uniform, random.random, etc.
        has_jitter = self._has_jitter(node)

        if not has_jitter:
            findings.append(
                Finding(
                    id=f"FF-RETRY-NOJITTER-{line_num:04d}",
                    title="Retry loop without jitter",
                    severity=Severity.HIGH,
                    category=Category.RELIABILITY,
                    file_path=rel_path,
                    line=line_num,
                    evidence=evidence,
                    why=(
                        "Without jitter, all clients retry at the same time after "
                        "a failure (thundering herd effect). This amplifies the outage "
                        "load and can prevent recovery. Under correlated failure, "
                        "synchronized retries can take down your service."
                    ),
                    fix=(
                        "Add full jitter to retry delay: "
                        "`delay = min(max_delay, base_delay * (2 ** attempt)); "
                        "sleep(random.uniform(0, delay))`. "
                        "Or use a library like tenacity with `wait=wait_random_exponential()`."
                    ),
                    standard_refs=[
                        "AWS Exponential Backoff and Jitter",
                        "Google Cloud Retry Strategy",
                    ],
                    blocking=True,
                )
            )

        # Check 2: For `while True` loops, is there a max attempts counter?
        if isinstance(node, ast.While):
            has_max_attempts = self._has_max_attempts(node)

            if not has_max_attempts:
                findings.append(
                    Finding(
                        id=f"FF-RETRY-NOMAX-{line_num:04d}",
                        title="Retry loop without maximum attempts",
                        severity=Severity.HIGH,
                        category=Category.RELIABILITY,
                        file_path=rel_path,
                        line=line_num,
                        evidence=evidence,
                        why=(
                            "A retry loop without maximum attempts can run forever if "
                            "the failure condition never clears. This wastes resources, "
                            "holds connections, and prevents the caller from failing fast "
                            "and trying an alternative."
                        ),
                        fix=(
                            "Add a maximum attempt counter: "
                            "`for attempt in range(max_retries): ...` or "
                            "`if attempt >= max_retries: raise`. "
                            "A typical production default is 3-5 retries."
                        ),
                        standard_refs=[
                            "AWS Exponential Backoff and Jitter",
                        ],
                        blocking=True,
                    )
                )

        # Check 3: Is there a constant sleep (no exponential backoff)?
        has_exponential = self._has_exponential_backoff(node)
        if not has_exponential and not has_jitter:
            for sleep_call in sleep_calls:
                if self._is_constant_sleep(sleep_call):
                    sleep_line = sleep_call.lineno
                    sleep_evidence = (
                        source_lines[sleep_line - 1].strip()
                        if sleep_line <= len(source_lines)
                        else ""
                    )
                    findings.append(
                        Finding(
                            id=f"FF-RETRY-CONSTANT-{sleep_line:04d}",
                            title="Retry with constant delay (no backoff)",
                            severity=Severity.MEDIUM,
                            category=Category.RELIABILITY,
                            file_path=rel_path,
                            line=sleep_line,
                            evidence=sleep_evidence,
                            why=(
                                "Constant retry delays don't give the failing service "
                                "time to recover. Exponential backoff progressively "
                                "reduces retry pressure, improving recovery chances."
                            ),
                            fix=(
                                "Use exponential backoff: "
                                "`delay = min(max_delay, base_delay * (2 ** attempt))` "
                                "combined with jitter."
                            ),
                            standard_refs=["AWS Exponential Backoff and Jitter"],
                            blocking=False,
                        )
                    )
                    break  # Only report once per loop

        return findings

    def _check_retry_decorators(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        source: str,
        rel_path: str,
    ) -> list[Finding]:
        """Check tenacity @retry and backoff decorators for missing safety."""
        findings: list[Finding] = []
        source_lines = source.splitlines()

        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)

            if dec_name in ("retry", "tenacity.retry"):
                findings.extend(
                    self._check_tenacity_decorator(decorator, source_lines, rel_path)
                )

            elif dec_name and dec_name.startswith("backoff."):
                findings.extend(
                    self._check_backoff_decorator(decorator, source_lines, rel_path)
                )

        return findings

    def _check_tenacity_decorator(
        self, decorator: ast.expr, source_lines: list[str], rel_path: str
    ) -> list[Finding]:
        """Check a tenacity @retry decorator for missing safety parameters."""
        findings: list[Finding] = []
        line_num = decorator.lineno
        evidence = source_lines[line_num - 1].strip() if line_num <= len(source_lines) else ""

        if not isinstance(decorator, ast.Call):
            # Bare @retry with no arguments — no stop, no wait, no jitter
            findings.append(
                Finding(
                    id=f"FF-RETRY-BARE-{line_num:04d}",
                    title="Bare @retry decorator without stop or wait configuration",
                    severity=Severity.HIGH,
                    category=Category.RELIABILITY,
                    file_path=rel_path,
                    line=line_num,
                    evidence=evidence,
                    why=(
                        "A bare @retry decorator retries forever with no backoff. "
                        "This will hang indefinitely on persistent failures."
                    ),
                    fix=(
                        "Configure tenacity with stop and wait: "
                        "`@retry(stop=stop_after_attempt(3), "
                        "wait=wait_random_exponential(multiplier=1, max=60))`"
                    ),
                    standard_refs=["AWS Exponential Backoff and Jitter"],
                    blocking=True,
                )
            )
            return findings

        # It's @retry(...) with arguments — check for stop= and wait=
        keyword_names = {kw.arg for kw in decorator.keywords if kw.arg}

        if "stop" not in keyword_names:
            findings.append(
                Finding(
                    id=f"FF-RETRY-NOSTOP-{line_num:04d}",
                    title="@retry decorator without stop condition",
                    severity=Severity.HIGH,
                    category=Category.RELIABILITY,
                    file_path=rel_path,
                    line=line_num,
                    evidence=evidence,
                    why=(
                        "Without a stop condition, tenacity will retry forever. "
                        "Use stop_after_attempt() or stop_after_delay() to bound retries."
                    ),
                    fix=(
                        "Add a stop condition: "
                        "`@retry(stop=stop_after_attempt(3), ...)`"
                    ),
                    standard_refs=["AWS Exponential Backoff and Jitter"],
                    blocking=True,
                )
            )

        if "wait" not in keyword_names:
            findings.append(
                Finding(
                    id=f"FF-RETRY-NOWAIT-{line_num:04d}",
                    title="@retry decorator without wait/backoff strategy",
                    severity=Severity.MEDIUM,
                    category=Category.RELIABILITY,
                    file_path=rel_path,
                    line=line_num,
                    evidence=evidence,
                    why=(
                        "Without a wait strategy, tenacity retries immediately. "
                        "This hammers the failing service and prevents recovery."
                    ),
                    fix=(
                        "Add a wait strategy with jitter: "
                        "`@retry(wait=wait_random_exponential(multiplier=1, max=60), ...)`"
                    ),
                    standard_refs=["AWS Exponential Backoff and Jitter"],
                    blocking=False,
                )
            )

        return findings

    def _check_backoff_decorator(
        self, decorator: ast.expr, source_lines: list[str], rel_path: str
    ) -> list[Finding]:
        """Check a backoff library decorator for missing jitter."""
        findings: list[Finding] = []

        if not isinstance(decorator, ast.Call):
            return findings

        line_num = decorator.lineno
        evidence = source_lines[line_num - 1].strip() if line_num <= len(source_lines) else ""

        keyword_names = {kw.arg for kw in decorator.keywords if kw.arg}

        if "jitter" not in keyword_names:
            findings.append(
                Finding(
                    id=f"FF-RETRY-BACKOFF-NOJITTER-{line_num:04d}",
                    title="@backoff decorator without explicit jitter",
                    severity=Severity.MEDIUM,
                    category=Category.RELIABILITY,
                    file_path=rel_path,
                    line=line_num,
                    evidence=evidence,
                    why=(
                        "The backoff library defaults may not include sufficient "
                        "jitter to prevent thundering herd on correlated failures."
                    ),
                    fix=(
                        "Add explicit jitter: "
                        "`@backoff.on_exception(backoff.expo, Exception, "
                        "jitter=backoff.full_jitter, max_tries=5)`"
                    ),
                    standard_refs=["AWS Exponential Backoff and Jitter"],
                    blocking=False,
                )
            )

        return findings

    # --- Helper methods ---

    def _has_jitter(self, node: ast.AST) -> bool:
        """Check if a node's subtree contains jitter-related calls."""
        jitter_indicators = {"random", "uniform", "randint", "randrange", "jitter"}
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_full_call_name(child)
                if name and any(indicator in name.lower() for indicator in jitter_indicators):
                    return True
            elif isinstance(child, ast.Name) and child.id.lower() in jitter_indicators:
                return True
        return False

    def _has_max_attempts(self, node: ast.While) -> bool:
        """Check if a while loop has some form of attempt counting."""
        # Check if the test is not just `True` / `1`
        test = node.test
        if isinstance(test, ast.Constant) and test.value in (True, 1):
            # It's `while True:` — look for break conditions with attempt counters
            for child in ast.walk(node):
                if isinstance(child, ast.Compare):
                    # Look for `attempts < max_retries` or similar
                    return True
                if isinstance(child, ast.If):
                    # Look for `if attempt >= max:` break patterns
                    for if_child in ast.walk(child):
                        if isinstance(if_child, ast.Break):
                            return True
            return False

        # The while condition itself is a comparison — likely has bounds
        return True

    def _has_exponential_backoff(self, node: ast.AST) -> bool:
        """Check if a node's subtree contains exponential backoff patterns."""
        for child in ast.walk(node):
            if isinstance(child, ast.BinOp):
                # Look for `** attempt` or `* 2` patterns
                if isinstance(child.op, ast.Pow):
                    return True
                if isinstance(child.op, ast.Mult):
                    # Check for `delay * 2` or `base * (2 ** n)` patterns
                    if isinstance(child.right, ast.Constant) and child.right.value == 2:
                        return True
                    if isinstance(child.left, ast.Constant) and child.left.value == 2:
                        return True
        return False

    def _is_constant_sleep(self, sleep_call: ast.Call) -> bool:
        """Check if a sleep call uses a constant (non-computed) delay."""
        if sleep_call.args:
            arg = sleep_call.args[0]
            # Constant number = fixed delay
            return isinstance(arg, ast.Constant) and isinstance(arg.value, (int, float))
        return False

    def _get_full_call_name(self, node: ast.Call) -> str | None:
        """Get the dotted name of a call, e.g., 'time.sleep'."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
            if isinstance(func.value, ast.Attribute) and isinstance(
                func.value.value, ast.Name
            ):
                return f"{func.value.value.id}.{func.value.attr}.{func.attr}"
        return None

    def _get_decorator_name(self, decorator: ast.expr) -> str | None:
        """Get the name of a decorator."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        if isinstance(decorator, ast.Attribute) and isinstance(decorator.value, ast.Name):
            return f"{decorator.value.id}.{decorator.attr}"
        if isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)  # type: ignore[arg-type]
        return None

    def _discover_python_files(self, root: Path) -> list[str]:
        """Discover Python files in a directory."""
        excluded = {".git", ".venv", "venv", "__pycache__", "node_modules"}
        files: list[str] = []
        for path in root.rglob("*.py"):
            if not any(part in excluded for part in path.parts):
                files.append(str(path.relative_to(root)))
        return sorted(files)
