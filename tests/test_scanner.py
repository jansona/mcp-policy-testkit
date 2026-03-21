from pathlib import Path

from mcp_policy_testkit.scanner import scan

ROOT = Path(__file__).resolve().parents[1]


def test_insecure_fixture_emits_findings():
    report = scan(str(ROOT / "examples" / "insecure_server"))
    rule_ids = {finding.rule_id for finding in report.findings}
    assert "CFG001" in rule_ids
    assert "CFG004" in rule_ids
    assert "TQL003" in rule_ids
    assert "SRC001" in rule_ids
    assert report.score_summary.tool_quality_score < 100


def test_secure_fixture_is_quiet():
    report = scan(str(ROOT / "examples" / "secure_server"))
    assert report.findings == []
    assert report.score_summary.tool_quality_score == 100


def test_lint_config_only_filters_non_config_findings():
    report = scan(str(ROOT / "examples" / "insecure_server"), lint_config_only=True)
    assert report.findings
    assert all(finding.category.value == "config" for finding in report.findings)
