"""Command-line interface for local-first IOC enrichment."""

from __future__ import annotations

import argparse
import sys

from .enrichment import enrich_indicator
from .formatting import format_json, format_text
from .reputation import VirusTotalProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate and enrich one IOC; offline synthetic mode is the default.")
    parser.add_argument("indicator", help="IPv4/IPv6, domain, HTTP(S) URL, MD5, SHA-1, or SHA-256")
    parser.add_argument("--live", action="store_true", help="query VirusTotal metadata (never uploads a sample)")
    parser.add_argument("--allow-indicator-sharing", action="store_true",
        help="acknowledge that a live VirusTotal query discloses the indicator to VirusTotal")
    parser.add_argument("--json", action="store_true", help="print structured JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.live and not args.allow_indicator_sharing:
        print("Live lookup not started: add --allow-indicator-sharing only if this indicator is approved for disclosure to VirusTotal.", file=sys.stderr)
        return 2
    if args.allow_indicator_sharing and not args.live:
        print("--allow-indicator-sharing requires --live.", file=sys.stderr)
        return 2
    result = enrich_indicator(args.indicator, VirusTotalProvider() if args.live else None)
    print(format_json(result) if args.json else format_text(result))
    return 0 if result.validation_status == "valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
