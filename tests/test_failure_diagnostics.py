"""Bounded reported diagnostics are hints, never verified causes or status."""

import json
import tempfile
import unittest
from pathlib import Path

from tools import hygiene


class FailureDiagnosticTests(unittest.TestCase):
    def envelope(self, **changes: object) -> str:
        value: dict[str, object] = {
            "type": "verification_diagnostic",
            "version": 1,
            "stage": "target_preparation",
            "code": "missing_seed",
        }
        return json.dumps({**value, **changes})

    def test_envelope_is_strict_and_bounded(self) -> None:
        valid = hygiene.reported_failure(self.envelope())
        self.assertEqual(valid["stage"], "target_preparation")
        self.assertEqual(valid["code"], "missing_seed")
        self.assertEqual(valid["provenance"], "child_output_unverified")
        for bad in (
            self.envelope(secret="SECRET_CANARY"),
            self.envelope(stage="SECRET_CANARY"),
            self.envelope(code="SECRET_CANARY"),
            self.envelope(version=True),
            self.envelope(stage=[]),
            self.envelope(code={}),
            self.envelope().replace('"version": 1', '"version": 1, "version": 1'),
            self.envelope() + " trailing",
            "[1,2]",
            "{" * 500,
            " " * 513 + self.envelope(),
            self.envelope() + "\n" + self.envelope(code="failed"),
        ):
            with self.subTest(bad=bad[:30]):
                observed = hygiene.reported_failure(bad)
                self.assertEqual(observed["category"], "unclassified")
                self.assertNotIn("SECRET_CANARY", json.dumps(observed))
        self.assertEqual(
            hygiene.reported_failure(self.envelope() + "\nnoise" * 70)["category"],
            "unclassified",
        )

    def test_exception_categories_never_retain_message_or_path(self) -> None:
        for name, category in (
            ("FileNotFoundError", "missing_file"),
            ("PermissionError", "permission_denied"),
            ("ModuleNotFoundError", "missing_module"),
            ("AssertionError", "assertion_failure"),
            ("subprocess.CalledProcessError", "subprocess_failure"),
        ):
            result = hygiene.reported_failure(
                f"{name}: /private/SECRET_CANARY token=SECRET_CANARY"
            )
            self.assertEqual(result["category"], category)
            self.assertNotIn("SECRET_CANARY", json.dumps(result))
        self.assertEqual(
            hygiene.reported_failure("SecretError: SECRET_CANARY")["category"],
            "unclassified",
        )
        self.assertEqual(
            hygiene.reported_failure("error: could not compile `SECRET_CANARY`")[
                "category"
            ],
            "compiler_failure",
        )

    def test_real_missing_seed_has_safe_report_in_all_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "missing.py"
            script.write_text(
                "from pathlib import Path\nPath('SECRET_CANARY/local/linux-target').read_bytes()\n"
            )
            entry = hygiene.run_entry(
                root, {"id": "mutation", "command": ["python3", str(script)]}
            )
            self.assertEqual(entry["status"], "failed")
            self.assertEqual(entry["exit_code"], 1)
            self.assertEqual(entry["reported_diagnostic"]["category"], "missing_file")
            result = {"status": "failed", "checks": [entry]}
            hygiene.write_reports(root / "report", result)
            artifacts = (
                json.dumps(entry)
                + (root / "report/evidence.json").read_text()
                + (root / "report/report.md").read_text()
                + "\n".join(hygiene.failure_summary(result))
            )
            self.assertIn("reported=missing_file (unverified)", artifacts)
            self.assertNotIn("SECRET_CANARY", artifacts)
            self.assertNotIn(directory, artifacts)

    def test_forged_valid_report_cannot_change_exit_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for code in (0, 7):
                script = root / "forged.py"
                script.write_text(
                    f"print({self.envelope()!r})\nraise SystemExit({code})\n"
                )
                entry = hygiene.run_entry(
                    root, {"id": "forged", "command": ["python3", str(script)]}
                )
                self.assertEqual(entry["exit_code"], code)
                self.assertEqual(entry["status"], "failed" if code else "passed")
                if code:
                    self.assertEqual(
                        entry["reported_diagnostic"]["provenance"],
                        "child_output_unverified",
                    )
                else:
                    self.assertNotIn("reported_diagnostic", entry)

    def test_renderer_rejects_tampered_report_fields(self) -> None:
        for diagnostic in (
            {"category": "SECRET_CANARY", "provenance": "child_output_unverified"},
            {
                "category": "checker_report",
                "provenance": "child_output_unverified",
                "stage": "mutation",
                "code": "SECRET_CANARY",
            },
            {
                "category": "missing_file",
                "provenance": "child_output_unverified",
                "message": "SECRET_CANARY",
            },
        ):
            summary = hygiene.diagnostic_summary({"reported_diagnostic": diagnostic})
            self.assertEqual(summary, "reported=unclassified (unverified)")


if __name__ == "__main__":
    unittest.main()
