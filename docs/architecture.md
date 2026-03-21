# Architecture

## Core flow

1. The CLI accepts a local path or remote URL.
2. Inputs are normalized into a `ScanTarget`.
3. If the target exposes a live MCP transport, the scanner performs `initialize`, `notifications/initialized`, `tools/list`, and `prompts/list`.
4. Static and live metadata are merged into a single scan target.
5. The rule registry evaluates the target and emits `Finding` objects.
6. Findings are aggregated into a `ScanReport`.
7. Renderers produce terminal, JSON, Markdown, or SARIF output.

## Main modules

- `cli.py`: command entrypoints and exit code policy
- `parser.py`: local file discovery and manifest/tool extraction
- `remote.py`: MCP handshake and remote metadata retrieval for HTTP and stdio transports
- `scanner.py`: orchestration and project config handling
- `rules/`: built-in policy checks
- `reporting/`: report renderers

## Data model

- `ScanTarget`: normalized local or remote input
- `ToolDefinition`: name, description, schema, and source info
- `Finding`: stable finding record with remediation and evidence
- `ScanReport`: final result bundle consumed by all output formats

## Remote analysis

Remote targets can be analyzed in three ways:

- direct HTTP JSON-RPC MCP endpoint
- stdio-configured MCP server discovered from local config files
- metadata fixture file for tests and offline validation

The live transport path performs a real MCP lifecycle handshake before collecting tools and prompts.
