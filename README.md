# FailFast Developer MCP

**A Python-first production-readiness reviewer for developers and CI/CD pipelines.**

> _FailFast doesn't just lint your code — it tells you whether it's ready to ship._

[![CI](https://github.com/MErblin/failfast-developer-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/MErblin/failfast-developer-mcp/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)

---

## The Problem

Every code scanner answers: _"Here are 247 issues."_

**FailFast answers:** _"This PR is not production-ready because retry logic can cause a thundering herd, two HTTP calls have no timeout, and a function has 21 execution paths. Fix these 5 things first."_

That distinction matters.

## What It Does

FailFast combines **deterministic static analysis** (Ruff, Bandit, Radon) with **custom AST-based production checks** (timeout detection, retry safety analysis) to produce a single verdict: **PASS**, **FAIL**, or **WARN**.

Every finding maps to an industry standard — OWASP, NIST, RFC 9457, AWS Well-Architected — not just an opinion.

| Category | What FailFast Checks | Standards Referenced |
|---|---|---|
| **Security** | Bandit findings mapped to OWASP Top 10 | OWASP Top 10, Secure Coding Practices |
| **Reliability** | HTTP calls without timeouts, unsafe retry patterns (no jitter, no max attempts, thundering herd risk) | AWS Backoff & Jitter, OWASP API4:2023 |
| **Maintainability** | Cyclomatic complexity > 15, Ruff lint violations | McCabe Metric, NIST SSDF PW.5 |
| **API Quality** | _(Roadmap: RFC 9457 error contracts, auth checks)_ | RFC 9457, OWASP ASVS |
| **Dependencies** | _(Roadmap: pip-audit integration)_ | OpenSSF Scorecard |

## Quick Start

### CLI

```bash
# Install
git clone https://github.com/MErblin/failfast-developer-mcp.git
cd failfast-developer-mcp
uv sync

# Scan a project
uv run failfast scan /path/to/your/project

# Scan only changed files (PR mode)
uv run failfast scan /path/to/your/project --diff main

# JSON output for CI
uv run failfast scan /path/to/your/project --format json

# Markdown report for PR comments
uv run failfast scan /path/to/your/project --format markdown

# SARIF output for GitHub Code Scanning
uv run failfast scan /path/to/your/project --format sarif

# Check a single category
uv run failfast check /path/to/your/project --category reliability

# Explain a finding rule
uv run failfast explain FF-RETRY
```

### MCP Server

Connect to any MCP-compatible client (Claude Desktop, Cursor, etc.):

```bash
# Start the MCP dev server
uv run mcp dev src/failfast/server.py
```

Or add to your MCP client config:

```json
{
  "mcpServers": {
    "failfast": {
      "command": "uv",
      "args": ["--directory", "/path/to/failfast-developer-mcp", "run", "mcp", "run", "src/failfast/server.py"]
    }
  }
}
```

**Available MCP Tools:**

| Tool | Description |
|---|---|
| `scan(path, profile)` | Full production-readiness scan |
| `scan_diff(path, base_ref)` | Scan only changed files since a git ref |
| `check(path, category)` | Run a single analysis category |
| `explain(finding_id)` | Get detailed explanation for a finding rule |

### Exit Codes

| Code | Meaning |
|:---:|---|
| `0` | ✅ PASS — Production-ready |
| `1` | ❌ FAIL — Blockers found |
| `2` | ⚠️ WARN — Warnings to review |

## Example Output

```
failfast scan ./my-api-project
```

```
╭──────────────── FailFast Production Readiness ────────────────╮
│ Verdict: FAIL                                                  │
│ Not production-ready. 3 blocker(s), 2 warning(s).             │
│ Path: /home/dev/my-api-project                                │
│ Profile: python-api                                           │
╰────────────────────────────────────────────────────────────────╯

     Category Summary
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┓
┃ Category        ┃ Verdict ┃ Blockers ┃ Warnings ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━┩
│ security        │  PASS   │        0 │        0 │
│ reliability     │  FAIL   │        2 │        1 │
│ maintainability │  FAIL   │        1 │        1 │
│ api_quality     │  PASS   │        0 │        0 │
│ dependencies    │  PASS   │        0 │        0 │
└─────────────────┴─────────┴──────────┴──────────┘

⛔ BLOCKERS

  1. [FF-TIMEOUT-0042] HTTP call without timeout: requests.get()
     src/client.py:42
     Why: HTTP calls without explicit timeouts can hang indefinitely...
     Fix: Add timeout=10 to the requests.get() call.
     Refs: OWASP API4:2023, AWS Well-Architected

  2. [FF-RETRY-NOJITTER-0087] Retry loop without jitter
     src/client.py:87
     Why: Without jitter, all clients retry simultaneously (thundering herd)...
     Fix: Use `delay = min(max_delay, base * 2**attempt); sleep(random.uniform(0, delay))`
     Refs: AWS Exponential Backoff and Jitter

  3. [FF-COMPLEXITY-D] Function 'process_order' has cyclomatic complexity 21
     src/orders.py:15
     Why: 21 execution paths — nearly impossible to test exhaustively...
     Fix: Extract helpers, use early returns, replace conditionals with lookup tables.
     Refs: McCabe Complexity Metric, NIST SSDF PW.5
```

## Architecture

The core engine is **transport-agnostic** — it knows nothing about MCP or CLI. Both are thin adapters over the same engine.

```
failfast-developer-mcp/
├── src/failfast/
│   ├── models.py              # Finding, Scorecard, Verdict, Severity
│   ├── engine.py              # Orchestrator + rule catalog
│   ├── server.py              # MCP server (thin wrapper)
│   ├── cli.py                 # CLI (Click + Rich)
│   ├── analyzers/
│   │   ├── ruff.py            # Ruff linter wrapper
│   │   ├── bandit.py          # Bandit security wrapper + OWASP mapping
│   │   ├── complexity.py      # Radon CC wrapper
│   │   ├── timeout.py    ★    # Custom AST: HTTP calls without timeout
│   │   └── retry.py      ★    # Custom AST: unsafe retry patterns
│   └── reporters/
│       ├── json_reporter.py   # Structured JSON
│       ├── markdown_reporter.py # Human-readable reports
│       └── sarif_reporter.py  # SARIF v2.1.0 for GitHub Code Scanning
└── tests/
    ├── fixtures/              # Deliberately broken Python files
    ├── test_analyzers/        # Analyzer unit tests
    ├── test_engine.py         # Integration tests
    ├── test_models.py         # Data model tests
    └── test_reporters.py      # Reporter tests
```

**★ Custom AST analyzers** — These are the differentiators. Ruff and Bandit don't catch missing HTTP timeouts or unsafe retry patterns (thundering herd, infinite loops, no jitter). FailFast does.

### How Analyzers Work

Every analyzer implements a simple protocol:

```python
class Analyzer(Protocol):
    @property
    def name(self) -> str: ...
    def analyze(self, context: AnalysisContext) -> list[Finding]: ...
```

Adding a new analyzer is one file + tests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Why Not Just Use Ruff/Bandit/SonarQube?

FailFast doesn't replace those tools — it **integrates them** and adds what they're missing:

| Feature | Ruff | Bandit | SonarQube | **FailFast** |
|---|:---:|:---:|:---:|:---:|
| Lint rules | ✅ 900+ | ❌ | ✅ | ✅ via Ruff |
| Security scanning | Partial | ✅ | ✅ | ✅ via Bandit |
| Missing HTTP timeouts | ❌ | ❌ | ❌ | **✅** |
| Unsafe retry detection | ❌ | ❌ | ❌ | **✅** |
| Thundering herd risk | ❌ | ❌ | ❌ | **✅** |
| Standards mapping (OWASP/NIST) | ❌ | Partial | Partial | **✅** |
| Production-readiness verdict | ❌ | ❌ | ✅ | **✅** |
| MCP integration for IDEs/editors | ❌ | ❌ | ✅ | **✅** |
| Free & open source | ✅ | ✅ | Freemium | **✅** |

## Roadmap

- [x] Core engine with pluggable analyzer protocol
- [x] Ruff, Bandit, Radon integration
- [x] Custom AST: timeout detection
- [x] Custom AST: retry safety analysis
- [x] CLI with Rich terminal output
- [x] MCP server with 4 tools
- [x] JSON, Markdown, SARIF reporters
- [ ] pip-audit dependency scanning
- [ ] FastAPI route discovery + auth checks
- [ ] RFC 9457 error contract validation
- [ ] Production profiles (YAML config)
- [ ] GitHub Actions reusable workflow
- [ ] PyPI publication

## Development

```bash
uv sync                          # Install dependencies
uv run pytest tests/ -v          # Run tests
uv run ruff check src/ tests/    # Lint
uv run failfast scan src/        # Dogfood: scan ourselves
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

[MIT](LICENSE)
