from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_ORDER, ScanReport, Severity
from .reporting import render_json, render_markdown, render_sarif, render_terminal
from .scanner import scan


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", help="Write the result to a file.")
    parser.add_argument("--format", default="terminal", choices=["terminal", "json", "md", "sarif"])
    parser.add_argument("--fail-on", default="critical", choices=[item.value for item in Severity])
    parser.add_argument("--enable-rule", action="append", dest="enable_rules")
    parser.add_argument("--disable-rule", action="append", dest="disable_rules")
    parser.add_argument("--config", help="Reserved for future project-level configuration support.")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-policy-testkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lint_parser = subparsers.add_parser("lint-config")
    lint_parser.add_argument("path")
    _add_common_scan_args(lint_parser)

    test_parser = subparsers.add_parser("test")
    test_parser.add_argument("target")
    _add_common_scan_args(test_parser)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--input", required=True)
    report_parser.add_argument(
        "--format",
        required=True,
        choices=["json", "md", "sarif", "terminal"],
    )
    report_parser.add_argument("--output")
    report_parser.add_argument("--verbose", action="store_true")
    return parser


def _render(report: ScanReport, output_format: str, verbose: bool) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "md":
        return render_markdown(report)
    if output_format == "sarif":
        return render_sarif(report)
    return render_terminal(report, verbose=verbose)


def _write_output(content: str, output: str | None) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        print(content)


def _exit_code(report: ScanReport, fail_on: str) -> int:
    threshold = Severity(fail_on)
    highest = report.highest_severity()
    if highest is None:
        return 0
    if SEVERITY_ORDER[highest] >= SEVERITY_ORDER[threshold]:
        return 2
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "report":
            report = ScanReport.model_validate_json(Path(args.input).read_text(encoding="utf-8"))
            content = _render(report, args.format, args.verbose)
            _write_output(content, args.output)
            return 0

        target = args.path if args.command == "lint-config" else args.target
        report = scan(
            target,
            enabled_rules=args.enable_rules,
            disabled_rules=args.disable_rules,
            lint_config_only=args.command == "lint-config",
            project_config=args.config,
        )
        content = _render(report, args.format, args.verbose)
        _write_output(content, args.output)
        return _exit_code(report, args.fail_on)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except Exception as exc:  # pragma: no cover
        print(f"Error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
