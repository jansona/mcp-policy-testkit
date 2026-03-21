# mcp-policy-testkit

`mcp-policy-testkit` is a CI-first policy and security testing toolkit for MCP servers. It checks manifests, configuration files, tool metadata, and local source artifacts for common security and quality failures before release.

## Features

- Configuration hygiene checks for secrets, environment exposure, unsafe path mappings, and dangerous commands
- Tool contract analysis for naming clarity, schema quality, destructive disclosures, prompt injection, and tool poisoning
- Source scanning for command injection, dynamic execution, unsafe file access, and resource exhaustion patterns
- Reports in terminal, JSON, Markdown, and SARIF
- Rule registry with enable/disable controls and project-level config
- GitHub Actions examples for CI use

## Installation

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Commands

### Lint configuration only

```bash
mcp-policy-testkit lint-config path/to/mcp.json --format terminal --fail-on high
```

### Run the full policy test suite

```bash
mcp-policy-testkit test path/to/server-or-config --format json --output reports/scan.json
```

### Convert a saved result bundle

```bash
mcp-policy-testkit report --input reports/scan.json --format sarif --output reports/scan.sarif
```

## Rule categories

- `config`: hygiene and manifest safety
- `tool_quality`: tool naming, schema quality, and destructive disclosure
- `safety`: prompt injection, tool poisoning, shadowing, and source-level dangerous patterns

See [docs/rule-catalog.md](/Users/yinbangguo/Projects/mcp_policy_testkit/docs/rule-catalog.md) for the current rule list.

## Project configuration

You can define default rule toggles in a YAML file:

```yaml
enable_rules:
  - CFG001
disable_rules:
  - TQL002
```

Then pass it with:

```bash
mcp-policy-testkit test examples/insecure_server --config .mcp-policy-testkit.yml
```

## Output and exit codes

- Exit `0`: no findings
- Exit `1`: findings exist but do not reach the chosen failure threshold
- Exit `2`: at least one finding meets or exceeds `--fail-on`
- Exit `3`: input, parsing, or remote retrieval failure

## GitHub Actions

The repository ships:

- [ci.yml](/Users/yinbangguo/Projects/mcp_policy_testkit/.github/workflows/ci.yml) for lint, tests, and packaging
- [example-scan.yml](/Users/yinbangguo/Projects/mcp_policy_testkit/.github/workflows/example-scan.yml) for pull request scanning

## Custom rules

The built-in registry lives in [registry.py](/Users/yinbangguo/Projects/mcp_policy_testkit/src/mcp_policy_testkit/rules/registry.py). See [docs/custom-rules.md](/Users/yinbangguo/Projects/mcp_policy_testkit/docs/custom-rules.md) for extension guidance.

## Status

The package is implementation-ready locally. Pushing to GitHub still requires a remote repository URL and authentication.

