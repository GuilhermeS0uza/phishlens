from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze_url, analyze_many


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="PhishLens - Phishing URL Detector (heuristics + Safe Browsing)",
    )

    parser.add_argument(
        "input",
        help="URL to analyze OR path to a text file containing URLs (one per line).",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        default=None,
        help="Optional path to save results as JSON (single or bulk).",
    )

    args = parser.parse_args()
    raw = (args.input or "").strip()

    p = Path(raw)
    if p.exists() and p.is_file():
        urls = _read_urls_file(p)
        results = analyze_many(urls)

        for r in results:
            _print_result(r)

        if args.json_path:
            _write_json(args.json_path, results)
        return

    result = analyze_url(raw)
    _print_result(result)

    if args.json_path:
        _write_json(args.json_path, [result])


def _read_urls_file(path: Path) -> list[str]:
    urls: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            urls.append(s)
    return urls


def _print_result(result: dict) -> None:
    print(f"[{result['label']}] score={result['score']:>3}  url={result['url']}")
    for reason in result["reasons"]:
        print(f"  - {reason}")


def _write_json(out_path: str, results: list[dict]) -> None:
    import json

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)