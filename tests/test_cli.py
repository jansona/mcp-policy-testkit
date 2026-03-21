import json
from pathlib import Path

from mcp_policy_testkit.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_cli_writes_json_report(tmp_path):
    output = tmp_path / "scan.json"
    exit_code = main(
        [
            "test",
            str(ROOT / "examples" / "insecure_server"),
            "--format",
            "json",
            "--output",
            str(output),
            "--fail-on",
            "critical",
        ]
    )
    assert exit_code == 2
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["findings"]


def test_report_command_converts_to_markdown(tmp_path):
    json_path = tmp_path / "scan.json"
    md_path = tmp_path / "scan.md"
    main(
        [
            "test",
            str(ROOT / "examples" / "insecure_server"),
            "--format",
            "json",
            "--output",
            str(json_path),
        ]
    )
    exit_code = main(
        ["report", "--input", str(json_path), "--format", "md", "--output", str(md_path)]
    )
    assert exit_code == 0
    assert "# MCP Policy Test Report" in md_path.read_text(encoding="utf-8")
