"""Command-line interface for migration-paranoid."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Sequence

from . import __version__
from .finding import Finding, Severity
from .scanner import scan_path


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="migration-paranoid",
        description=(
            "Static analyzer for risky database migrations. "
            "Warns about migrations that can lock tables, drop data, or "
            "break rolling deploys."
        ),
    )
    p.add_argument(
        "paths",
        nargs="*",
        default=["db/migrations"],
        help="Files or directories to scan (default: db/migrations).",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--min-severity",
        choices=tuple(s.value for s in Severity),
        default=Severity.LOW.value,
        help="Hide findings below this severity.",
    )
    p.add_argument(
        "--fail-on",
        choices=tuple(s.value for s in Severity),
        default=Severity.MEDIUM.value,
        help="Exit non-zero if any finding has at least this severity (default: medium).",
    )
    p.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"migration-paranoid {__version__}",
    )
    return p


def _filter(findings: List[Finding], min_severity: str) -> List[Finding]:
    threshold = _SEVERITY_RANK[Severity(min_severity)]
    return [f for f in findings if _SEVERITY_RANK[f.severity] >= threshold]


def _group_by_file(findings: List[Finding]) -> "dict[str, list[Finding]]":
    groups: "dict[str, list[Finding]]" = {}
    for f in findings:
        groups.setdefault(f.file, []).append(f)
    for items in groups.values():
        items.sort(key=lambda x: (x.line, x.rule_id))
    return groups


def _render_text(findings: List[Finding]) -> str:
    if not findings:
        return "✅ No risky migrations detected."
    out: List[str] = []
    for file, items in _group_by_file(findings).items():
        try:
            display = os.path.relpath(file)
        except ValueError:
            display = file
        # Highest severity first within each file.
        items_sorted = sorted(
            items, key=lambda x: (-_SEVERITY_RANK[x.severity], x.line)
        )
        header_emoji = items_sorted[0].severity.emoji
        out.append(f"{header_emoji} {display}")
        out.append("")
        for f in items_sorted:
            out.append(f.format())
            out.append("")
    summary = _summarize(findings)
    out.append(summary)
    return "\n".join(out).rstrip() + "\n"


def _summarize(findings: List[Finding]) -> str:
    counts: "dict[Severity, int]" = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [
        f"{counts[s]} {s.value}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if counts.get(s)
    ]
    if not parts:
        return "Summary: 0 findings"
    return f"Summary: {len(findings)} finding(s) — " + ", ".join(parts)


def _render_json(findings: List[Finding]) -> str:
    return json.dumps(
        [
            {
                "file": f.file,
                "line": f.line,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "snippet": f.snippet,
                "risks": f.risks,
                "suggestion": f.suggestion,
            }
            for f in findings
        ],
        indent=2,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    all_findings: List[Finding] = []
    for path in args.paths:
        if not os.path.exists(path):
            print(f"migration-paranoid: path not found: {path}", file=sys.stderr)
            continue
        all_findings.extend(scan_path(path))

    visible = _filter(all_findings, args.min_severity)

    if args.format == "json":
        print(_render_json(visible))
    else:
        print(_render_text(visible), end="")

    fail_threshold = _SEVERITY_RANK[Severity(args.fail_on)]
    has_failure = any(_SEVERITY_RANK[f.severity] >= fail_threshold for f in all_findings)
    return 1 if has_failure else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
