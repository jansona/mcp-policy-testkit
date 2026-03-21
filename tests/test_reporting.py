import json
from pathlib import Path

from mcp_policy_testkit.reporting import render_json, render_markdown, render_sarif
from mcp_policy_testkit.scanner import scan

ROOT = Path(__file__).resolve().parents[1]


def test_report_renderers_produce_expected_shapes():
    report = scan(str(ROOT / "examples" / "insecure_server"))
    rendered_json = render_json(report)
    rendered_markdown = render_markdown(report)
    rendered_sarif = render_sarif(report)

    assert json.loads(rendered_json)["findings"]
    assert "# MCP Policy Test Report" in rendered_markdown
    assert json.loads(rendered_sarif)["runs"][0]["results"]
