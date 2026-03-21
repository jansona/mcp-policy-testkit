# Architecture

## Core flow

1. The CLI accepts a local path or remote URL.
2. Inputs are normalized into a `ScanTarget`.
3. The rule registry evaluates the target and emits `Finding` objects.
4. Findings are aggregated into a `ScanReport`.
5. Renderers produce terminal, JSON, Markdown, or SARIF output.

## Main modules

- `cli.py`: command entrypoints and exit code policy
- `parser.py`: local file discovery and manifest/tool extraction
- `remote.py`: remote metadata retrieval adapter
- `scanner.py`: orchestration and project config handling
- `rules/`: built-in policy checks
- `reporting/`: report renderers

## Data model

- `ScanTarget`: normalized local or remote input
- `ToolDefinition`: name, description, schema, and source info
- `Finding`: stable finding record with remediation and evidence
- `ScanReport`: final result bundle consumed by all output formats

## Remote analysis

Remote targets are expected to expose JSON metadata that includes a `tools` array or an equivalent MCP metadata response. This keeps the scanner usable in CI and test environments without coupling the core rule engine to a single transport layer.

