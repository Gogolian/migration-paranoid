"""File scanning: walk a path and analyze each migration file."""

from __future__ import annotations

import os
from typing import Iterable, List, Optional

from .finding import Finding
from .rules import analyze


# Extensions we consider as potential migration files.
_SUPPORTED_EXTS = (
    ".sql",      # PostgreSQL, MySQL, SQLite, Flyway, Prisma migrations
    ".rb",       # Rails
    ".py",       # Django
    ".xml",      # Liquibase
    ".yaml",     # Liquibase
    ".yml",      # Liquibase
    ".json",     # Liquibase
    ".prisma",   # Prisma schema
)


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _is_candidate(path: str) -> bool:
    return path.lower().endswith(_SUPPORTED_EXTS)


def iter_files(path: str) -> Iterable[str]:
    """Yield candidate migration file paths under ``path``.

    If ``path`` is a file, yield it directly (regardless of extension) so a
    user can point the tool at a specific file even with an unusual name.
    """
    if os.path.isfile(path):
        yield path
        return
    if not os.path.isdir(path):
        return
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            full = os.path.join(root, name)
            if _is_candidate(full):
                yield full


def scan_path(path: str) -> List[Finding]:
    """Scan ``path`` (file or directory) and return all findings."""
    findings: List[Finding] = []
    for file in iter_files(path):
        content = _read(file)
        if content is None:
            continue
        findings.extend(analyze(file, content))
    return findings
