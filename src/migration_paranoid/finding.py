"""Data classes for findings produced by the rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    """Severity level for a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "🚨",
            Severity.MEDIUM: "⚠️ ",
            Severity.LOW: "ℹ️ ",
            Severity.INFO: "ℹ️ ",
        }[self]


@dataclass
class Finding:
    """A single risky pattern detected in a migration file."""

    file: str
    line: int
    rule_id: str
    title: str
    severity: Severity
    snippet: str
    risks: List[str] = field(default_factory=list)
    suggestion: str = ""

    def format(self, color: bool = False) -> str:
        """Return a human-readable, multi-line representation of the finding."""
        risks_block = "\n".join(f"- {r}" for r in self.risks) if self.risks else ""

        header = f"{self.severity.emoji} {self.file}:{self.line}  [{self.rule_id}] {self.title}"
        parts = [header, "", f"  {self.snippet.strip()}", ""]
        if risks_block:
            parts.append("Risk:")
            parts.append(risks_block)
        if self.suggestion:
            parts.append("")
            parts.append(f"Suggestion: {self.suggestion}")
        return "\n".join(parts)
