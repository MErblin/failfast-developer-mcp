# Contributing to FailFast Developer MCP

Thank you for considering contributing! This document covers the development setup, conventions, and workflow for contributing to FailFast.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/MErblin/failfast-developer-mcp.git
cd failfast-developer-mcp

# Install dependencies (requires uv: https://docs.astral.sh/uv/)
uv sync

# Run the test suite
uv run pytest tests/ -v

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type check
uv run mypy src/failfast/ --ignore-missing-imports
```

## Project Structure

```
src/failfast/
├── models.py          # Core data models (Finding, Scorecard, etc.)
├── engine.py          # Analysis orchestrator
├── server.py          # MCP server (thin transport layer)
├── cli.py             # CLI interface (Click + Rich)
├── analyzers/         # Pluggable analyzers
│   ├── ruff.py        # Ruff wrapper
│   ├── bandit.py      # Bandit wrapper
│   ├── complexity.py  # Radon wrapper
│   ├── timeout.py     # Custom AST: missing timeouts
│   └── retry.py       # Custom AST: unsafe retries
├── reporters/         # Output formatters
│   ├── json_reporter.py
│   ├── markdown_reporter.py
│   └── sarif_reporter.py
└── profiles/          # Production-readiness profiles
```

## Adding a New Analyzer

1. Create a new file in `src/failfast/analyzers/` (e.g., `my_analyzer.py`)
2. Implement the `Analyzer` protocol:

```python
from failfast.models import AnalysisContext, Finding

class MyAnalyzer:
    @property
    def name(self) -> str:
        return "MyAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        # Your analysis logic here
        return findings
```

3. Register it in `engine.py` → `_get_all_analyzers()`
4. Add test fixtures in `tests/fixtures/`
5. Write tests in `tests/test_analyzers/`

## Testing

- Every analyzer **must** have test fixtures (deliberately broken Python files)
- Every analyzer **must** have both positive tests (catches bad code) and negative tests (doesn't flag clean code)
- Every finding **must** include: `why` (production impact), `fix` (actionable guidance), `standard_refs` (industry standards)

```bash
# Run all tests
uv run pytest tests/ -v

# Run a specific test file
uv run pytest tests/test_analyzers/test_timeout.py -v

# Run with coverage (if installed)
uv run pytest tests/ --cov=failfast --cov-report=term-missing
```

## Code Style

- We use **Ruff** for linting and formatting
- Line length: 100 characters
- Type hints on all public functions
- Docstrings on all public modules, classes, and functions

## Commit Messages

Use conventional commit format:

```
feat: add FastAPI route discovery analyzer
fix: timeout analyzer false positive on httpx.Client with default timeout
test: add fixtures for SQLAlchemy transaction boundary checks
docs: add architecture diagram to README
```

## Pull Request Checklist

- [ ] Tests pass (`uv run pytest tests/ -v`)
- [ ] Linting passes (`uv run ruff check src/ tests/`)
- [ ] New analyzer has test fixtures and tests
- [ ] Findings include `why`, `fix`, and `standard_refs`
- [ ] No new dependencies without discussion

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
