"""End-to-end tests for migration-paranoid."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

# Make ``src`` importable without an editable install.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from migration_paranoid.cli import main  # noqa: E402
from migration_paranoid.rules import analyze  # noqa: E402
from migration_paranoid.scanner import scan_path  # noqa: E402


FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def _run_cli(args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(args)
    return rc, buf.getvalue()


class TestSqlRules(unittest.TestCase):
    def test_set_not_null_detected(self):
        path = os.path.join(FIXTURES, "202604301200_add_not_null_to_users.sql")
        findings = scan_path(path)
        ids = [f.rule_id for f in findings]
        self.assertIn("SQL001", ids)
        f = next(f for f in findings if f.rule_id == "SQL001")
        self.assertEqual(f.line, 2)
        self.assertIn("users", f.title)
        self.assertIn("email", f.title)
        # Risk text matches the README example.
        joined = "\n".join(f.risks)
        self.assertIn("May scan full table.", joined)
        self.assertIn("NULL", joined)
        self.assertIn("rolling deploy", joined)

    def test_risky_mix_detects_each_pattern(self):
        path = os.path.join(FIXTURES, "risky_mix.sql")
        findings = scan_path(path)
        ids = {f.rule_id for f in findings}
        for rule in ("SQL003", "SQL004", "PG001", "SQL005", "SQL006", "SQL008", "SQL009"):
            self.assertIn(rule, ids, f"missing {rule}")

    def test_safe_sql_has_no_findings(self):
        path = os.path.join(FIXTURES, "safe.sql")
        findings = scan_path(path)
        self.assertEqual(findings, [], f"unexpected findings: {findings}")

    def test_comment_does_not_trigger(self):
        sql = "-- DROP TABLE users;\nSELECT 1;\n"
        findings = analyze("/x.sql", sql)
        self.assertEqual(findings, [])

    def test_block_comment_preserves_line_numbers(self):
        sql = "/* block\ncomment */\nALTER TABLE t ALTER COLUMN c SET NOT NULL;\n"
        findings = analyze("/x.sql", sql)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 3)

    def test_add_column_not_null_without_default(self):
        sql = "ALTER TABLE users ADD COLUMN flag boolean NOT NULL;\n"
        findings = analyze("/x.sql", sql)
        ids = [f.rule_id for f in findings]
        self.assertIn("SQL002", ids)

    def test_add_column_not_null_with_default_is_quiet(self):
        sql = "ALTER TABLE users ADD COLUMN flag boolean NOT NULL DEFAULT false;\n"
        findings = analyze("/x.sql", sql)
        self.assertNotIn("SQL002", [f.rule_id for f in findings])

    def test_update_with_where_is_quiet(self):
        sql = "UPDATE users SET active = true WHERE id = 1;\n"
        findings = analyze("/x.sql", sql)
        self.assertNotIn("SQL008", [f.rule_id for f in findings])

    def test_concurrent_index_is_quiet(self):
        sql = "CREATE INDEX CONCURRENTLY idx_x ON t (c);\n"
        findings = analyze("/x.sql", sql)
        self.assertNotIn("PG001", [f.rule_id for f in findings])


class TestRailsRules(unittest.TestCase):
    def test_rails_findings(self):
        path = os.path.join(FIXTURES, "20260430120000_rails_risky.rb")
        findings = scan_path(path)
        ids = {f.rule_id for f in findings}
        self.assertIn("RAILS001", ids)  # remove_column
        self.assertIn("RAILS003", ids)  # change_column_null false
        self.assertIn("RAILS004", ids)  # add_index without concurrently

    def test_rails_concurrent_index_is_quiet(self):
        rb = "add_index :users, :email, algorithm: :concurrently\n"
        findings = analyze("/m.rb", rb)
        self.assertNotIn("RAILS004", [f.rule_id for f in findings])


class TestDjangoRules(unittest.TestCase):
    def test_django_findings(self):
        path = os.path.join(FIXTURES, "0002_django_risky.py")
        findings = scan_path(path)
        ids = {f.rule_id for f in findings}
        self.assertIn("DJANGO001", ids)
        self.assertIn("DJANGO002", ids)
        self.assertIn("DJANGO003", ids)


class TestLiquibaseRules(unittest.TestCase):
    def test_liquibase_findings(self):
        path = os.path.join(FIXTURES, "changelog.xml")
        findings = scan_path(path)
        ids = {f.rule_id for f in findings}
        self.assertIn("LB001", ids)
        self.assertIn("LB004", ids)
        self.assertIn("LB005", ids)


class TestCli(unittest.TestCase):
    def test_cli_text_output(self):
        rc, out = _run_cli([FIXTURES])
        self.assertEqual(rc, 1)
        self.assertIn("🚨", out)
        self.assertIn("Risk:", out)
        self.assertIn("Summary:", out)

    def test_cli_clean_directory_returns_zero(self):
        only_safe_dir = os.path.join(FIXTURES, "_only_safe")
        os.makedirs(only_safe_dir, exist_ok=True)
        target = os.path.join(only_safe_dir, "safe.sql")
        with open(os.path.join(FIXTURES, "safe.sql")) as src, open(target, "w") as dst:
            dst.write(src.read())
        try:
            rc, out = _run_cli([only_safe_dir])
            self.assertEqual(rc, 0, out)
            self.assertIn("No risky migrations", out)
        finally:
            os.remove(target)
            os.rmdir(only_safe_dir)

    def test_cli_json_output(self):
        rc, out = _run_cli(["--format", "json", FIXTURES])
        self.assertEqual(rc, 1)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertTrue(any(item["rule_id"] == "SQL001" for item in data))
        # Every finding has the required keys.
        for item in data:
            for key in ("file", "line", "rule_id", "title", "severity", "snippet", "risks", "suggestion"):
                self.assertIn(key, item)

    def test_cli_missing_path(self):
        rc, _ = _run_cli(["/no/such/path"])
        # No findings -> exit 0, but stderr message printed.
        self.assertEqual(rc, 0)

    def test_cli_fail_on_threshold(self):
        # Only LOW findings present? Use the prisma file with a single LOW.
        # In fixtures we have HIGH/CRITICAL — use --fail-on=critical to reduce.
        rc, _ = _run_cli(["--fail-on", "critical", FIXTURES])
        # We have at least one CRITICAL (DROP TABLE / DeleteModel) -> exit 1.
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
