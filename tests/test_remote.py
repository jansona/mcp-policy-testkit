from pathlib import Path

from mcp_policy_testkit.scanner import scan

ROOT = Path(__file__).resolve().parents[1]


def test_remote_scan_detects_duplicate_tools():
    payload = (ROOT / "tests" / "fixtures" / "remote_tools.json").resolve()
    report = scan(payload.as_uri())
    rule_ids = {finding.rule_id for finding in report.findings}
    assert "TQL001" in rule_ids
