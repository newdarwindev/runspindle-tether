"""Focused repository-discipline checks; no GitHub access or generator execution."""

import importlib.util
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parents[1] / "tools/check_repo_hygiene.py"
SPEC = importlib.util.spec_from_file_location("repo_hygiene", SOURCE)
assert SPEC and SPEC.loader
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


def policy() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "accountable_owner": "newdarwindev",
        "required_pr_sections": list(hygiene.SECTIONS),
        "exceptions": [],
    }


def body() -> str:
    return """## Scope
Implement scoped parser; [spec](specs/README.md). No transport changes.
## BDD acceptance
Given a valid document, When parsing, Then return its typed fields.
## Tests and evidence
[Tests](tests/test_parser.py): python3 -m unittest; local pass.
## Provenance
[Record](provenance.json): original implementation; no imports.
## Generated files
N/A because no generated outputs changed.
## Owner and exceptions
@newdarwindev; exceptions: none.
"""


class RepoHygieneTests(unittest.TestCase):
    def test_valid_policy(self) -> None:
        self.assertEqual([], hygiene.validate_policy(policy(), date(2026, 11, 14)))

    def test_expired_exception(self) -> None:
        value = policy()
        value["exceptions"] = [
            {
                "id": "E1",
                "owner": "newdarwindev",
                "scope": "docs",
                "reason": "bounded debt",
                "issue": "https://github.com/newdarwindev/runspindle/issues/44",
                "expires_utc": "2026-11-14",
            }
        ]
        self.assertIn(
            "exception expired (expiry date is exclusive, UTC)",
            hygiene.validate_policy(value, date(2026, 11, 14)),
        )

    def test_incomplete_exception(self) -> None:
        value = policy()
        value["exceptions"] = [{"id": "E1"}]
        self.assertGreaterEqual(
            len(hygiene.validate_policy(value, date(2026, 11, 14))), 4
        )

    def test_valid_body(self) -> None:
        self.assertEqual([], hygiene.check_pr_body(body(), policy()))

    def test_template_comments_do_not_count(self) -> None:
        self.assertTrue(
            hygiene.check_pr_body(hygiene.render_template("newdarwindev"), policy())
        )

    def test_missing_link_and_bdd(self) -> None:
        value = (
            body()
            .replace("[Tests](tests/test_parser.py)", "tests ran")
            .replace("Then", "and")
        )
        errors = hygiene.check_pr_body(value, policy())
        self.assertTrue(any("Given/When/Then" in error for error in errors))
        self.assertTrue(any("Tests and evidence" in error for error in errors))

    def test_undeclared_exception(self) -> None:
        self.assertTrue(
            hygiene.check_pr_body(body().replace("none.", "E99."), policy())
        )

    def test_template_drift_and_missing_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / ".github").mkdir()
            (root / "repository-hygiene.json").write_text(json.dumps(policy()))
            (root / ".github/PULL_REQUEST_TEMPLATE.md").write_text(
                hygiene.render_template("newdarwindev")
            )
            (root / "provenance.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "new_files": "original",
                        "license_status": "retain notices",
                    }
                )
            )
            self.assertEqual([], hygiene.check(root))
            (root / ".github/PULL_REQUEST_TEMPLATE.md").write_text("drift")
            self.assertTrue(any("drift" in error for error in hygiene.check(root)))
            (root / "provenance.json").unlink()
            self.assertTrue(any("unreadable" in error for error in hygiene.check(root)))


if __name__ == "__main__":
    unittest.main()
