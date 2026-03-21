# Rule Catalog

## Configuration hygiene

- `CFG001`: hardcoded secret detection
- `CFG002`: sensitive environment variable exposure
- `CFG003`: unsafe path mapping or wildcard access
- `CFG004`: dangerous command declaration

## Tool contract quality

- `TQL001`: duplicate tool name
- `TQL002`: ambiguous tool contract
- `TQL003`: hidden instruction or tool/prompt poisoning metadata
- `TQL004`: weak parameter schema
- `TQL005`: destructive tool missing warning
- `TQL006`: tool shadowing or duplicated signature

## Source and safety analysis

- `SRC001`: command injection pattern
- `SRC002`: dynamic execution usage
- `SRC003`: possible unsanitized file access
- `SRC004`: possible resource exhaustion pattern

## Severity policy

- `critical`: immediate security or destructive risk
- `high`: strong exploitability or major trust boundary failure
- `medium`: likely misuse, ambiguity, or defense gap
- `low`: quality issue that should still be fixed for safer operation
