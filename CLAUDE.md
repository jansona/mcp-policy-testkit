# CLAUDE.md

This file provides guidance for AI assistants working in this repository.

## Project Overview

`mcp-policy-testkit` is a CI-first security and policy testing toolkit for **MCP (Model Context Protocol) servers**. It scans config files, tool definitions, and source code for policy violations, performs live MCP handshakes, and produces reports in multiple formats for CI integration.

## Repository Structure

```
mcp-policy-testkit/
├── src/mcp_policy_testkit/    # Main package
│   ├── cli.py                 # Entry point: argument parsing, command routing
│   ├── scanner.py             # Core orchestration: parse → handshake → evaluate → report
│   ├── parser.py              # Local file discovery and parsing (JSON/YAML configs)
│   ├── remote.py              # Remote MCP handshake (stdio and HTTP JSON-RPC transports)
│   ├── models.py              # Pydantic data models (ScanTarget, Finding, ScanReport, etc.)
│   ├── utils.py               # Helpers: file discovery, YAML/JSON loading, URL detection
│   ├── rules/                 # Policy rule implementations
│   │   ├── base.py            # Rule ABC: rule_id, title, severity, category, evaluate()
│   │   ├── registry.py        # RuleRegistry: manage, select, and evaluate rules
│   │   ├── config_rules.py    # CFG001–CFG004: secrets, env exposure, paths, commands
│   │   ├── tool_rules.py      # TQL001–TQL005: naming, descriptions, schemas, destructive ops
│   │   ├── shadow_rules.py    # TQL006: tool shadowing/duplication
│   │   └── source_rules.py   # SRC001–SRC004: command injection, dynamic exec, file access, exhaustion
│   └── reporting/             # Output renderers
│       ├── terminal.py        # Human-readable console output
│       ├── markdown.py        # Jinja2-templated Markdown reports
│       ├── json_output.py     # Structured JSON output
│       └── sarif.py           # SARIF format for security scanners
├── tests/                     # Pytest test suite
│   └── fixtures/              # Mock MCP server, remote_tools.json, etc.
├── examples/
│   ├── insecure_server/       # Example with policy violations
│   └── secure_server/         # Example compliant server
├── docs/
│   ├── architecture.md        # Core flow and module overview
│   ├── rule-catalog.md        # Complete rule reference
│   └── custom-rules.md        # Guide for writing custom rules
├── pyproject.toml             # Package config, dependencies, ruff/pytest settings
├── AGENTS.md                  # Working rules for contributors
└── .github/workflows/ci.yml   # CI: lint → test → package smoke test
```

## Development Setup

```bash
python -m pip install -e ".[dev]"   # Install in editable mode with dev deps
pytest                              # Run all tests
ruff check .                        # Lint (also run by CI)
mcp-policy-testkit test examples/insecure_server --verbose  # Manual CLI smoke test
```

**Python version:** 3.11+

**Runtime dependencies:** `jinja2>=3.1`, `pydantic>=2.7`, `PyYAML>=6.0`

**Dev dependencies:** `pytest>=8.2`, `ruff>=0.5.0`

## CLI Commands

The CLI entry point is `mcp_policy_testkit.cli:main` (installed as `mcp-policy-testkit`).

```bash
# Scan config files only (no source/tool analysis)
mcp-policy-testkit lint-config <path> [options]

# Full scan: configs + tools + live MCP handshake
mcp-policy-testkit test <target> [options]

# Convert a saved JSON report to another format
mcp-policy-testkit report --input result.json --format md
```

**Shared options for `lint-config` and `test`:**

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | `terminal`, `json`, `md`, or `sarif` |
| `--fail-on` | `critical` | Severity threshold for non-zero exit: `low`, `medium`, `high`, `critical` |
| `--output` | stdout | Write result to file |
| `--enable-rule ID` | all | Enable specific rule(s) only |
| `--disable-rule ID` | none | Suppress specific rule(s) |
| `--config FILE` | none | YAML project config (`enable_rules`/`disable_rules` keys) |
| `--verbose` | false | Show additional detail |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings present but below `--fail-on` threshold |
| `2` | Findings at or above `--fail-on` threshold |
| `3` | Error (file not found, parse failure, etc.) |

## Data Flow

```
CLI (cli.py)
  └─ scan() (scanner.py)
       ├─ is_url? → fetch_remote_target() (remote.py)  [HTTP JSON-RPC]
       └─ local  → parse_target() (parser.py)          [file discovery]
                    └─ for each runtime_target → fetch_runtime_target() (remote.py)  [stdio]
       └─ RuleRegistry.evaluate(scan_target) (rules/registry.py)
            └─ each Rule.evaluate() → list[Finding]
       └─ ScanReport (models.py)
            └─ render_*(report) (reporting/)
```

## Data Models (models.py)

All models are Pydantic `BaseModel` subclasses.

- **`ScanTarget`** — Normalized input: configs, tools, prompts, commands, source artifacts, runtime targets
- **`Finding`** — Single policy violation with `rule_id`, `severity`, `category`, `message`, `recommendation`, `location`
- **`ToolDefinition`** — Tool metadata extracted from configs or live handshake
- **`ScanReport`** — Final result: `findings`, `score_summary`, `metadata`; exposes `highest_severity()` and `summary_counts()`
- **`Severity`** — `low`, `medium`, `high`, `critical` (ordered via `SEVERITY_ORDER` dict)
- **`Category`** — `config`, `tool_quality`, `safety`, `source`
- **`SourceLocation`** — `path`, optional `pointer`/`line`/`column`/`tool_name`

## Rule Catalog

Rules are grouped by category and identified by stable IDs. Never change a rule ID.

### Configuration Hygiene (`config` category)
| ID | Title | Severity |
|----|-------|----------|
| CFG001 | Hardcoded secret detection | critical |
| CFG002 | Sensitive environment variable exposure | high |
| CFG003 | Unsafe path mapping or wildcard access | high |
| CFG004 | Dangerous command declaration | high |

### Tool Contract Quality (`tool_quality` category)
| ID | Title | Severity |
|----|-------|----------|
| TQL001 | Duplicate tool name | medium |
| TQL002 | Ambiguous tool contract | medium |
| TQL003 | Hidden instruction / tool/prompt poisoning metadata | critical |
| TQL004 | Weak parameter schema | low |
| TQL005 | Destructive tool missing warning | medium |
| TQL006 | Tool shadowing or duplicated signature | high |

### Source and Safety Analysis (`source` category)
| ID | Title | Severity |
|----|-------|----------|
| SRC001 | Command injection pattern | critical |
| SRC002 | Dynamic execution usage | high |
| SRC003 | Possible unsanitized file access | medium |
| SRC004 | Possible resource exhaustion pattern | medium |

### Severity Policy
- **critical** — Immediate security or destructive risk
- **high** — Strong exploitability or major trust boundary failure
- **medium** — Likely misuse, ambiguity, or defense gap
- **low** — Quality issue that should still be fixed for safer operation

## Adding a New Rule

1. Choose the right file under `src/mcp_policy_testkit/rules/` based on category, or create a new file.
2. Subclass `Rule` from `rules/base.py` and set class-level attributes:
   ```python
   class MyNewRule(Rule):
       rule_id = "CFG005"          # Must be stable and unique
       title = "Short descriptive title"
       description = "Full description of what this rule checks."
       severity = Severity.HIGH
       category = Category.CONFIG
       applies_to = ("local", "remote")  # default; restrict if needed

       def evaluate(self, target: ScanTarget) -> list[Finding]:
           findings = []
           # ... inspection logic ...
           return findings
   ```
3. Import and add your rule to `DEFAULT_RULES` in `rules/registry.py`.
4. Add fixture-based tests in `tests/` before changing behavior.
5. Update `docs/rule-catalog.md` with the new rule entry.
6. Do not weaken existing severities without updating docs and tests.

## Testing

Tests use **pytest** with fixture-based patterns.

```bash
pytest                    # Run all tests
pytest tests/test_scanner.py   # Run a specific file
pytest -v                 # Verbose output
```

Test files:
- `test_scanner.py` — End-to-end scanner tests using fixtures
- `test_cli.py` — CLI argument parsing and exit code validation
- `test_remote.py` — MCP handshake and HTTP endpoint tests
- `test_mcp_handshake.py` — Stdio server lifecycle tests
- `test_reporting.py` — Output format rendering tests

Fixtures live in `tests/fixtures/` (mock MCP server, `remote_tools.json`, etc.).

When adding a rule or changing behavior:
- Add or update fixtures under `examples/` and `tests/fixtures/`
- Write tests before changing rule or report behavior
- Keep JSON, Markdown, and SARIF outputs aligned from the same `ScanReport` model

## Code Style

Enforced by **ruff** (line length 100, target Python 3.11):

```toml
select = ["E", "F", "I", "B", "UP", "N"]
ignore = ["UP006", "UP035", "UP042", "UP045"]
```

- Use `from __future__ import annotations` in all source files.
- Use Pydantic models for all data structures — no raw dicts for structured data.
- Rule IDs must be stable. Never rename or reuse a rule ID.
- Keep public docs in English.
- Do not weaken existing severities without updating documentation and tests.

## CI Pipeline

`.github/workflows/ci.yml` runs on every push and pull request:

1. **Lint** — `ruff check .`
2. **Test** — `pytest`
3. **Package smoke test** — `python -m pip install .`

All three steps must pass. Fix lint errors before running tests.

## Output Formats

All four renderers consume the same `ScanReport` model:

| Format | Flag | Use case |
|--------|------|----------|
| Terminal | `--format terminal` | Human-readable console output |
| JSON | `--format json` | Machine-readable, save for later conversion |
| Markdown | `--format md` | PR comments, documentation |
| SARIF | `--format sarif` | GitHub code scanning, security dashboards |

Saved JSON reports can be re-rendered: `mcp-policy-testkit report --input result.json --format md`

## Custom Rules

Subclass `Rule`, implement `evaluate()`, and register with `RuleRegistry`:

```python
from mcp_policy_testkit.models import Category, Finding, Severity, SourceLocation
from mcp_policy_testkit.rules.base import Rule

class MyCustomRule(Rule):
    rule_id = "CUS001"
    title = "My custom policy"
    description = "Describe what is being checked."
    severity = Severity.MEDIUM
    category = Category.CONFIG

    def evaluate(self, target):
        findings = []
        # inspection logic
        return findings
```

Pass custom rules to `RuleRegistry(rules=[...])` or extend the default registry.
