"""Rule engine: scans the textual content of a migration and produces findings.

The rules are intentionally pattern-based (regular expressions over normalized
SQL/code). This is a static, dependency-free analyzer — it favors a high
signal-to-noise ratio for the obviously dangerous patterns over deep parsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional

from .finding import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_HASH_LINE_COMMENT = re.compile(r"(?m)^\s*#[^\n]*$")


def _strip_sql_comments(text: str) -> str:
    """Remove SQL comments while keeping line numbers stable."""
    def _blank(match: re.Match) -> str:
        return "".join("\n" if c == "\n" else " " for c in match.group(0))

    text = _SQL_BLOCK_COMMENT.sub(_blank, text)
    text = _SQL_LINE_COMMENT.sub(lambda m: " " * len(m.group(0)), text)
    return text


def _line_of(text: str, offset: int) -> int:
    """1-based line number for a string offset."""
    return text.count("\n", 0, offset) + 1


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def _statement_around(text: str, offset: int) -> str:
    """Return the SQL statement containing ``offset`` (terminated by ';')."""
    start = text.rfind(";", 0, offset)
    start = 0 if start == -1 else start + 1
    end = text.find(";", offset)
    end = len(text) if end == -1 else end + 1
    return text[start:end].strip()


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------


@dataclass
class Dialect:
    """Light-weight per-dialect hint used by rules to tune messages."""

    name: str  # "postgres", "mysql", "sqlite", "generic"


RuleFn = Callable[[str, str, Dialect], Iterable[Finding]]


# ---------------------------------------------------------------------------
# SQL rules
# ---------------------------------------------------------------------------


_RE_SET_NOT_NULL = re.compile(
    r"\bALTER\s+TABLE\s+(?P<table>[\w\".`]+)\s+ALTER\s+(?:COLUMN\s+)?(?P<col>[\w\".`]+)\s+SET\s+NOT\s+NULL\b",
    re.IGNORECASE,
)

_RE_ADD_COLUMN_NOT_NULL = re.compile(
    r"\bALTER\s+TABLE\s+(?P<table>[\w\".`]+)\s+ADD\s+(?:COLUMN\s+)?"
    r"(?P<col>[\w\".`]+)\s+(?P<rest>[^,;]*?\bNOT\s+NULL\b[^,;]*)",
    re.IGNORECASE,
)

_RE_DROP_COLUMN = re.compile(
    r"\bALTER\s+TABLE\s+(?P<table>[\w\".`]+)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?(?P<col>[\w\".`]+)",
    re.IGNORECASE,
)

_RE_DROP_TABLE = re.compile(
    r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<table>[\w\".`]+)",
    re.IGNORECASE,
)

_RE_CREATE_INDEX = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b(?P<rest>[^;]*)",
    re.IGNORECASE,
)

_RE_ALTER_TYPE = re.compile(
    r"\bALTER\s+TABLE\s+(?P<table>[\w\".`]+)\s+ALTER\s+(?:COLUMN\s+)?"
    r"(?P<col>[\w\".`]+)\s+(?:SET\s+DATA\s+)?TYPE\s+(?P<type>[\w()\s,]+?)(?=,|;|$)",
    re.IGNORECASE,
)

_RE_RENAME_COLUMN = re.compile(
    r"\bALTER\s+TABLE\s+(?P<table>[\w\".`]+)\s+RENAME\s+(?:COLUMN\s+)?"
    r"(?P<old>[\w\".`]+)\s+TO\s+(?P<new>[\w\".`]+)",
    re.IGNORECASE,
)

_RE_RENAME_TABLE = re.compile(
    r"\bALTER\s+TABLE\s+(?P<table>[\w\".`]+)\s+RENAME\s+TO\s+(?P<new>[\w\".`]+)",
    re.IGNORECASE,
)

_RE_UPDATE_NO_WHERE = re.compile(
    r"\bUPDATE\s+(?P<table>[\w\".`]+)\s+SET\b(?P<rest>[^;]*)",
    re.IGNORECASE,
)

_RE_DELETE_NO_WHERE = re.compile(
    r"\bDELETE\s+FROM\s+(?P<table>[\w\".`]+)(?P<rest>[^;]*)",
    re.IGNORECASE,
)

_RE_TRUNCATE = re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?(?P<table>[\w\".`]+)", re.IGNORECASE)


def sql_rules(text: str, file: str, dialect: Dialect) -> List[Finding]:
    """Run SQL pattern rules over ``text`` (already comment-stripped)."""
    findings: List[Finding] = []

    for m in _RE_SET_NOT_NULL.finditer(text):
        line = _line_of(text, m.start())
        risks = [
            "May scan full table.",
            "May fail if existing rows contain NULL.",
            "Unsafe during rolling deploy unless app already writes "
            f"{m.group('col')}.",
        ]
        if dialect.name == "postgres":
            suggestion = (
                "On Postgres 12+: add a CHECK (col IS NOT NULL) NOT VALID, "
                "VALIDATE CONSTRAINT, then ALTER COLUMN SET NOT NULL."
            )
        else:
            suggestion = (
                "Backfill in batches first, ensure the application writes "
                "the column, then set NOT NULL in a follow-up migration."
            )
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL001",
                title=f"SET NOT NULL on {m.group('table')}.{m.group('col')}",
                severity=Severity.HIGH,
                snippet=_statement_around(text, m.start()),
                risks=risks,
                suggestion=suggestion,
            )
        )

    for m in _RE_ADD_COLUMN_NOT_NULL.finditer(text):
        rest = m.group("rest")
        # Skip when an explicit DEFAULT is provided; on Postgres 11+ this is
        # safe (constant default fast path), on older engines it still
        # rewrites the table but is *much* less likely to fail.
        has_default = re.search(r"\bDEFAULT\b", rest, re.IGNORECASE) is not None
        line = _line_of(text, m.start())
        if not has_default:
            findings.append(
                Finding(
                    file=file,
                    line=line,
                    rule_id="SQL002",
                    title=f"ADD COLUMN {m.group('col')} NOT NULL without DEFAULT",
                    severity=Severity.HIGH,
                    snippet=_statement_around(text, m.start()),
                    risks=[
                        "Fails on tables with existing rows.",
                        "Locks the table while rewriting.",
                    ],
                    suggestion=(
                        "Add the column nullable, backfill, then enforce "
                        "NOT NULL in a separate migration."
                    ),
                )
            )

    for m in _RE_DROP_COLUMN.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL003",
                title=f"DROP COLUMN {m.group('table')}.{m.group('col')}",
                severity=Severity.HIGH,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Permanent data loss.",
                    "Breaks rolling deploys if old app code still SELECTs the column.",
                ],
                suggestion=(
                    "Stop reading/writing the column in code first, deploy, "
                    "then drop in a follow-up migration."
                ),
            )
        )

    for m in _RE_DROP_TABLE.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL004",
                title=f"DROP TABLE {m.group('table')}",
                severity=Severity.CRITICAL,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Permanent data loss.",
                    "Breaks any service still referencing the table.",
                ],
                suggestion=(
                    "Rename to a deprecated name and drop in a follow-up "
                    "release after verifying no readers/writers remain."
                ),
            )
        )

    if dialect.name == "postgres":
        for m in _RE_CREATE_INDEX.finditer(text):
            rest = m.group(0)
            if re.search(r"\bCONCURRENTLY\b", rest, re.IGNORECASE):
                continue
            line = _line_of(text, m.start())
            findings.append(
                Finding(
                    file=file,
                    line=line,
                    rule_id="PG001",
                    title="CREATE INDEX without CONCURRENTLY",
                    severity=Severity.HIGH,
                    snippet=_statement_around(text, m.start()),
                    risks=[
                        "Takes an ACCESS EXCLUSIVE lock that blocks writes.",
                        "Can take minutes to hours on large tables.",
                    ],
                    suggestion=(
                        "Use CREATE INDEX CONCURRENTLY (and run outside a "
                        "transaction block)."
                    ),
                )
            )

    for m in _RE_ALTER_TYPE.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL005",
                title=f"ALTER COLUMN TYPE on {m.group('table')}.{m.group('col')}",
                severity=Severity.HIGH,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "May rewrite the entire table.",
                    "May fail to cast existing values.",
                    "Holds an exclusive lock on the table.",
                ],
                suggestion=(
                    "Add a new column with the desired type, backfill in "
                    "batches, switch reads/writes, then drop the old column."
                ),
            )
        )

    for m in _RE_RENAME_COLUMN.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL006",
                title=f"RENAME COLUMN {m.group('table')}.{m.group('old')} -> {m.group('new')}",
                severity=Severity.MEDIUM,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Breaks rolling deploys: old app code still references the old name.",
                ],
                suggestion=(
                    "Add the new column, dual-write, migrate readers, then "
                    "drop the old column."
                ),
            )
        )

    for m in _RE_RENAME_TABLE.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL007",
                title=f"RENAME TABLE {m.group('table')} -> {m.group('new')}",
                severity=Severity.MEDIUM,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Breaks rolling deploys: old app code still references the old name.",
                ],
                suggestion="Use a view alias during the transition.",
            )
        )

    for m in _RE_UPDATE_NO_WHERE.finditer(text):
        rest = m.group("rest")
        if re.search(r"\bWHERE\b", rest, re.IGNORECASE):
            continue
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL008",
                title=f"UPDATE without WHERE on {m.group('table')}",
                severity=Severity.HIGH,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Touches every row — long lock and big WAL/binlog churn.",
                    "Easy way to corrupt data if the SET expression is wrong.",
                ],
                suggestion="Batch updates with WHERE id BETWEEN ... clauses.",
            )
        )

    for m in _RE_DELETE_NO_WHERE.finditer(text):
        rest = m.group("rest")
        if re.search(r"\bWHERE\b", rest, re.IGNORECASE):
            continue
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL009",
                title=f"DELETE without WHERE on {m.group('table')}",
                severity=Severity.CRITICAL,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Removes every row.",
                    "Long lock and large rollback segment.",
                ],
                suggestion="Use TRUNCATE if intentional, or batch with a WHERE clause.",
            )
        )

    for m in _RE_TRUNCATE.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="SQL010",
                title=f"TRUNCATE {m.group('table')}",
                severity=Severity.HIGH,
                snippet=_statement_around(text, m.start()),
                risks=[
                    "Removes every row, often non-transactional.",
                    "Breaks any service still reading the table.",
                ],
                suggestion="Confirm intent and coordinate with deploys.",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Rails rules (ActiveRecord migrations, .rb files)
# ---------------------------------------------------------------------------


_RE_RAILS_REMOVE_COLUMN = re.compile(r"\bremove_column\s*[ (]\s*:?(?P<table>[\w\"]+)\s*,\s*:?(?P<col>[\w\"]+)", re.IGNORECASE)
_RE_RAILS_DROP_TABLE = re.compile(r"\bdrop_table\s*[ (]\s*:?(?P<table>[\w\"]+)", re.IGNORECASE)
_RE_RAILS_CHANGE_COLUMN_NULL = re.compile(
    r"\bchange_column_null\s*[ (]\s*:?(?P<table>[\w\"]+)\s*,\s*:?(?P<col>[\w\"]+)\s*,\s*false",
    re.IGNORECASE,
)
_RE_RAILS_ADD_INDEX = re.compile(r"\badd_index\b(?P<rest>[^\n]*)", re.IGNORECASE)
_RE_RAILS_RENAME_COLUMN = re.compile(r"\brename_column\s*[ (]", re.IGNORECASE)
_RE_RAILS_RENAME_TABLE = re.compile(r"\brename_table\s*[ (]", re.IGNORECASE)
_RE_RAILS_CHANGE_COLUMN = re.compile(r"\bchange_column\s*[ (]\s*:?(?P<table>[\w\"]+)\s*,\s*:?(?P<col>[\w\"]+)", re.IGNORECASE)
_RE_RAILS_ADD_COLUMN_NOT_NULL = re.compile(
    r"\badd_column\s*[ (][^\n]*null:\s*false",
    re.IGNORECASE,
)


def rails_rules(text: str, file: str, _dialect: Dialect) -> List[Finding]:
    findings: List[Finding] = []

    for m in _RE_RAILS_REMOVE_COLUMN.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS001",
                title=f"remove_column :{m.group('table')}, :{m.group('col')}",
                severity=Severity.HIGH,
                snippet=_line_text(text, line),
                risks=[
                    "Permanent data loss.",
                    "Breaks rolling deploys if old code still SELECTs the column.",
                ],
                suggestion="Use ignored_columns first, deploy, then remove.",
            )
        )

    for m in _RE_RAILS_DROP_TABLE.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS002",
                title=f"drop_table :{m.group('table')}",
                severity=Severity.CRITICAL,
                snippet=_line_text(text, line),
                risks=["Permanent data loss."],
                suggestion="Rename and drop in a follow-up release.",
            )
        )

    for m in _RE_RAILS_CHANGE_COLUMN_NULL.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS003",
                title=f"change_column_null :{m.group('table')}, :{m.group('col')}, false",
                severity=Severity.HIGH,
                snippet=_line_text(text, line),
                risks=[
                    "May scan full table.",
                    "Fails if any rows are NULL.",
                    "Unsafe during rolling deploy unless app already writes the column.",
                ],
                suggestion=(
                    "Backfill, deploy code that writes the column, then "
                    "enforce NOT NULL in a follow-up migration."
                ),
            )
        )

    for m in _RE_RAILS_ADD_INDEX.finditer(text):
        rest = m.group("rest")
        if re.search(r"algorithm:\s*:concurrently", rest, re.IGNORECASE):
            continue
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS004",
                title="add_index without algorithm: :concurrently",
                severity=Severity.HIGH,
                snippet=_line_text(text, line),
                risks=["Locks writes for the duration of the index build."],
                suggestion=(
                    "disable_ddl_transaction! and pass "
                    "algorithm: :concurrently."
                ),
            )
        )

    for m in _RE_RAILS_RENAME_COLUMN.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS005",
                title="rename_column",
                severity=Severity.MEDIUM,
                snippet=_line_text(text, line),
                risks=["Breaks rolling deploys: old code references the old name."],
                suggestion="Add new column, dual-write, migrate readers, drop old.",
            )
        )

    for m in _RE_RAILS_RENAME_TABLE.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS006",
                title="rename_table",
                severity=Severity.MEDIUM,
                snippet=_line_text(text, line),
                risks=["Breaks rolling deploys: old code references the old name."],
                suggestion="Use a view alias during the transition.",
            )
        )

    for m in _RE_RAILS_CHANGE_COLUMN.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS007",
                title=f"change_column :{m.group('table')}, :{m.group('col')}",
                severity=Severity.MEDIUM,
                snippet=_line_text(text, line),
                risks=[
                    "May rewrite the entire table.",
                    "May fail to cast existing values.",
                ],
                suggestion="Add new column, backfill, switch reads/writes, drop old.",
            )
        )

    for m in _RE_RAILS_ADD_COLUMN_NOT_NULL.finditer(text):
        rest_line = _line_text(text, _line_of(text, m.start()))
        if re.search(r"default:", rest_line, re.IGNORECASE):
            continue
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="RAILS008",
                title="add_column with null: false and no default",
                severity=Severity.HIGH,
                snippet=rest_line,
                risks=["Fails on tables with existing rows."],
                suggestion="Add nullable, backfill, then set NOT NULL.",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Django rules (.py files)
# ---------------------------------------------------------------------------


_RE_DJANGO_REMOVE_FIELD = re.compile(r"\bmigrations\.RemoveField\s*\(", re.IGNORECASE)
_RE_DJANGO_DELETE_MODEL = re.compile(r"\bmigrations\.DeleteModel\s*\(", re.IGNORECASE)
_RE_DJANGO_RENAME_FIELD = re.compile(r"\bmigrations\.RenameField\s*\(", re.IGNORECASE)
_RE_DJANGO_RENAME_MODEL = re.compile(r"\bmigrations\.RenameModel\s*\(", re.IGNORECASE)
_RE_DJANGO_RUN_SQL = re.compile(r"\bmigrations\.RunSQL\s*\(", re.IGNORECASE)


def django_rules(text: str, file: str, _dialect: Dialect) -> List[Finding]:
    findings: List[Finding] = []

    for m in _RE_DJANGO_REMOVE_FIELD.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="DJANGO001",
                title="migrations.RemoveField",
                severity=Severity.HIGH,
                snippet=_line_text(text, line),
                risks=[
                    "Permanent data loss.",
                    "Breaks rolling deploys if older app code still references the field.",
                ],
                suggestion="Make the field nullable, deploy code that no longer uses it, then remove.",
            )
        )

    for m in _RE_DJANGO_DELETE_MODEL.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="DJANGO002",
                title="migrations.DeleteModel",
                severity=Severity.CRITICAL,
                snippet=_line_text(text, line),
                risks=["Permanent data loss."],
                suggestion="Stage the deletion across releases.",
            )
        )

    for m in _RE_DJANGO_RENAME_FIELD.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="DJANGO003",
                title="migrations.RenameField",
                severity=Severity.MEDIUM,
                snippet=_line_text(text, line),
                risks=["Breaks rolling deploys: older code references the old field."],
                suggestion="Add a new field, dual-write, then drop.",
            )
        )

    for m in _RE_DJANGO_RENAME_MODEL.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="DJANGO004",
                title="migrations.RenameModel",
                severity=Severity.MEDIUM,
                snippet=_line_text(text, line),
                risks=["Breaks rolling deploys: older code references the old name."],
                suggestion="Use a database view aliasing the new table during the transition.",
            )
        )

    for m in _RE_DJANGO_RUN_SQL.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="DJANGO005",
                title="migrations.RunSQL — review SQL with care",
                severity=Severity.LOW,
                snippet=_line_text(text, line),
                risks=["Raw SQL bypasses Django checks; review for the patterns above."],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Liquibase rules (.xml / .yaml / .yml / .json changelogs — pattern-based)
# ---------------------------------------------------------------------------


_RE_LIQUIBASE_DROP_COLUMN = re.compile(r"\bdropColumn\b", re.IGNORECASE)
_RE_LIQUIBASE_DROP_TABLE = re.compile(r"\bdropTable\b", re.IGNORECASE)
_RE_LIQUIBASE_RENAME_COLUMN = re.compile(r"\brenameColumn\b", re.IGNORECASE)
_RE_LIQUIBASE_RENAME_TABLE = re.compile(r"\brenameTable\b", re.IGNORECASE)
_RE_LIQUIBASE_ADD_NOT_NULL = re.compile(r"\baddNotNullConstraint\b", re.IGNORECASE)
_RE_LIQUIBASE_MODIFY_DATA_TYPE = re.compile(r"\bmodifyDataType\b", re.IGNORECASE)


def liquibase_rules(text: str, file: str, _dialect: Dialect) -> List[Finding]:
    findings: List[Finding] = []

    def add(rule_id: str, title: str, sev: Severity, risks: List[str], regex: re.Pattern, suggestion: str = "") -> None:
        for m in regex.finditer(text):
            line = _line_of(text, m.start())
            findings.append(
                Finding(
                    file=file,
                    line=line,
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    snippet=_line_text(text, line),
                    risks=risks,
                    suggestion=suggestion,
                )
            )

    add(
        "LB001",
        "dropColumn",
        Severity.HIGH,
        ["Permanent data loss.", "Breaks rolling deploys."],
        _RE_LIQUIBASE_DROP_COLUMN,
        "Stop using the column in code first, deploy, then drop.",
    )
    add(
        "LB002",
        "dropTable",
        Severity.CRITICAL,
        ["Permanent data loss."],
        _RE_LIQUIBASE_DROP_TABLE,
    )
    add(
        "LB003",
        "renameColumn",
        Severity.MEDIUM,
        ["Breaks rolling deploys."],
        _RE_LIQUIBASE_RENAME_COLUMN,
    )
    add(
        "LB004",
        "renameTable",
        Severity.MEDIUM,
        ["Breaks rolling deploys."],
        _RE_LIQUIBASE_RENAME_TABLE,
    )
    add(
        "LB005",
        "addNotNullConstraint",
        Severity.HIGH,
        [
            "May scan full table.",
            "May fail if existing rows contain NULL.",
            "Unsafe during rolling deploy unless app already writes the column.",
        ],
        _RE_LIQUIBASE_ADD_NOT_NULL,
        "Backfill, deploy writers, then enforce NOT NULL.",
    )
    add(
        "LB006",
        "modifyDataType",
        Severity.HIGH,
        ["May rewrite the entire table.", "May fail to cast existing values."],
        _RE_LIQUIBASE_MODIFY_DATA_TYPE,
    )
    return findings


# ---------------------------------------------------------------------------
# Prisma schema rules (schema.prisma) — supplements SQL rules for prisma diffs.
# ---------------------------------------------------------------------------


_RE_PRISMA_REMOVED_FIELD_HINT = re.compile(r"^\s*///\s*@removed\b", re.IGNORECASE | re.MULTILINE)


def prisma_rules(text: str, file: str, _dialect: Dialect) -> List[Finding]:
    # Prisma migrations themselves are .sql files generated by `prisma migrate
    # dev` — they are handled by the SQL rules. For schema.prisma we just hint
    # that breaking schema changes should be reviewed.
    findings: List[Finding] = []
    for m in _RE_PRISMA_REMOVED_FIELD_HINT.finditer(text):
        line = _line_of(text, m.start())
        findings.append(
            Finding(
                file=file,
                line=line,
                rule_id="PRISMA001",
                title="@removed annotation in schema.prisma",
                severity=Severity.LOW,
                snippet=_line_text(text, line),
                risks=["Resulting migration will drop a column — verify rolling-deploy safety."],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_dialect(filename: str, content: str) -> Dialect:
    """Best-effort dialect detection from filename and content."""
    lower = filename.lower()
    if lower.endswith((".rb",)):
        return Dialect("rails")
    if lower.endswith((".py",)):
        return Dialect("django")
    if lower.endswith((".xml", ".yaml", ".yml", ".json")):
        return Dialect("liquibase")
    if lower.endswith(".prisma"):
        return Dialect("prisma")

    head = content[:4000].lower()
    if "concurrently" in head or "::regclass" in head or "pg_" in head:
        return Dialect("postgres")
    if "auto_increment" in head or "engine=" in head or "`" in head:
        return Dialect("mysql")
    if "without rowid" in head or "pragma" in head:
        return Dialect("sqlite")
    return Dialect("postgres")  # default — strictest set of rules


def analyze(filename: str, content: str) -> List[Finding]:
    """Analyze a single file's contents and return findings."""
    dialect = detect_dialect(filename, content)
    rules: List[RuleFn]
    if dialect.name == "rails":
        rules = [rails_rules]
    elif dialect.name == "django":
        rules = [django_rules]
    elif dialect.name == "liquibase":
        rules = [liquibase_rules]
    elif dialect.name == "prisma":
        rules = [prisma_rules]
    else:
        # SQL-family. Strip comments first so they don't trigger false positives.
        stripped = _strip_sql_comments(content)
        return sql_rules(stripped, filename, dialect)

    findings: List[Finding] = []
    for rule in rules:
        # Strip hash-line comments for rb/py/yaml without disturbing line numbers.
        cleaned = _HASH_LINE_COMMENT.sub(lambda m: " " * len(m.group(0)), content)
        findings.extend(rule(cleaned, filename, dialect))
    return findings
