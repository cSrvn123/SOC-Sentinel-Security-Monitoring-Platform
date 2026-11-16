"""CLI for analyzing local JSON event records without network access."""

from __future__ import annotations

import argparse
import math
import sys
from datetime import timedelta
from pathlib import Path

from .analyzer import EventInputError, analyze_json
from .formatting import format_json, format_text


def _positive_int(value: str) -> int:
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if result < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def _positive_seconds(value: str) -> float:
    try:
        result = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive number of seconds") from None
    if not math.isfinite(result) or result <= 0 or result > timedelta.max.total_seconds():
        raise argparse.ArgumentTypeError("must be a positive finite number of seconds")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze supported Windows Security and Sysmon JSON events offline.")
    parser.add_argument("--input", default="-", help="JSON file path; use - or omit to read standard input")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="summary output format")
    parser.add_argument("--failed-logon-threshold", type=_positive_int, default=3,
        help="matching 4625 records required for a repeated-failure observation (default: 3)")
    parser.add_argument("--failed-logon-window-seconds", type=_positive_seconds, default=300,
        help="time window for failed-logon correlation in seconds (default: 300)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        source = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
        report = analyze_json(source, args.failed_logon_threshold,
                              timedelta(seconds=args.failed_logon_window_seconds))
    except OSError:
        print("Unable to read the requested input.", file=sys.stderr)
        return 2
    except EventInputError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(format_json(report) if args.format == "json" else format_text(report))
    return 0 if report.events else 1


if __name__ == "__main__":
    raise SystemExit(main())
