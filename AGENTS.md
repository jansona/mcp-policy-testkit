# Repository Guidance

## Purpose

This repository contains `mcp-policy-testkit`, a CI-first analyzer for MCP server manifests, metadata, and local source artifacts.

## Working Rules

- Keep public docs in English.
- Add new policy checks as isolated rule classes with stable rule IDs.
- Prefer fixture-based tests for every rule addition.
- Do not weaken existing severities without updating documentation and tests.

## Common Commands

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mcp-policy-testkit test examples/insecure_server --verbose
```

## Development Flow

- Add or update fixtures under `examples/` and `tests/fixtures/`.
- Add tests before changing report or rule behavior.
- Keep JSON, Markdown, and SARIF outputs aligned from the same `ScanReport` model.

