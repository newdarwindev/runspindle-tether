"""Behavioral tests for the shared verification harness."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

SPEC = importlib.util.spec_from_file_location(
    "hygiene", Path(__file__).resolve().parents[1] / "tools/hygiene.py"
)
assert SPEC is not None and SPEC.loader is not None
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class HygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Synthetic")
        (self.root / "lock").write_text("pinned\n")
        self.git("add", "lock")
        self.git("commit", "-qm", "initial")

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], text=True
        ).strip()

    def manifest(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "checks": [{"id": "test", "command": ["python3", "-c", "pass"]}],
            "lockfiles": ["lock"],
            "profiling": {"not_applicable": "no workload"},
        }

    def test_missing_and_invalid_inventory(self) -> None:
        for invalid in ({}, {"schema_version": 1, "checks": []}):
            with self.assertRaises(ValueError):
                hygiene.validate_manifest(invalid)
        value = self.manifest()
        value["checks"] *= 2
        with self.assertRaises(ValueError):
            hygiene.validate_manifest(value)

    def test_missing_checker_and_tool_fail(self) -> None:
        entry = {
            "id": "missing",
            "command": ["python3", "absent.py"],
            "required_files": ["absent.py"],
        }
        self.assertEqual(
            hygiene.run_entry(self.root, entry)["reason"], "required_file_missing"
        )
        entry = {"id": "missing", "command": ["runspindle-nonexistent-tool"]}
        self.assertEqual(
            hygiene.run_entry(self.root, entry)["reason"], "required_tool_missing"
        )

    def test_explicit_na_requires_reason(self) -> None:
        with self.assertRaises(ValueError):
            hygiene.validate_entry({"id": "test", "not_applicable": ""})
        receipt = hygiene.run_entry(
            self.root, {"id": "test", "not_applicable": "no build"}
        )
        self.assertEqual(receipt["status"], "not_applicable")

    def test_failure_output_and_arguments_not_copied(self) -> None:
        entry = {
            "id": "test",
            "command": [
                "python3",
                "-c",
                "print('PRIVATE_CANARY'); raise SystemExit(3)",
            ],
        }
        receipt = hygiene.run_entry(self.root, entry)
        self.assertEqual(receipt["exit_code"], 3)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(receipt))

    def test_timeout_fails(self) -> None:
        receipt = hygiene.run_entry(
            self.root,
            {
                "id": "test",
                "command": ["python3", "-c", "import time; time.sleep(10)"],
                "timeout_seconds": 0.05,
            },
        )
        self.assertEqual(receipt["reason"], "timeout")

    def test_lock_drift_missing_untracked_and_staged_change(self) -> None:
        self.assertEqual(
            hygiene.preflight(self.root, self.manifest())["status"], "passed"
        )
        (self.root / "lock").write_text("changed")
        self.assertIn(
            "lockfile_drift", hygiene.preflight(self.root, self.manifest())["problems"]
        )
        self.git("add", "lock")
        self.assertEqual(
            hygiene.preflight(self.root, self.manifest())["status"], "passed"
        )
        (self.root / "lock").unlink()
        self.assertIn(
            "required_lockfile_missing",
            hygiene.preflight(self.root, self.manifest())["problems"],
        )
        (self.root / "extra").write_text("x")
        value = self.manifest()
        value["lockfiles"] = ["extra"]
        self.assertIn(
            "lockfile_untracked_or_unsafe",
            hygiene.preflight(self.root, value)["problems"],
        )

    def test_workflow_pins(self) -> None:
        folder = self.root / ".github/workflows"
        folder.mkdir(parents=True)
        path = folder / "check.yml"
        path.write_text("steps:\n  - uses: actions/checkout@main\n")
        self.assertIn(
            "workflow_action_not_pinned",
            hygiene.preflight(self.root, self.manifest())["problems"],
        )
        path.write_text("steps:\n  - uses: actions/checkout@" + "a" * 40 + "\n")
        self.assertEqual(
            hygiene.preflight(self.root, self.manifest())["status"], "passed"
        )

    def test_composition_gitlink_mismatch(self) -> None:
        sha = self.git("rev-parse", "HEAD")
        self.git(
            "update-index",
            "--add",
            "--cacheinfo",
            "160000," + sha + ",components/example",
        )
        path = self.root / "composition.lock.json"
        path.write_text(
            json.dumps({"components": [{"path": "components/example", "commit": sha}]})
        )
        self.assertEqual(
            hygiene.preflight(self.root, self.manifest())["status"], "passed"
        )
        path.write_text(
            json.dumps(
                {"components": [{"path": "components/example", "commit": "a" * 40}]}
            )
        )
        self.assertIn(
            "composition_gitlink_mismatch",
            hygiene.preflight(self.root, self.manifest())["problems"],
        )

    def test_paths_cannot_escape(self) -> None:
        with self.assertRaises(ValueError):
            hygiene.contained(self.root, "../private")
        receipt = hygiene.run_entry(
            self.root,
            {"id": "test", "command": ["python3"], "required_files": ["../private"]},
        )
        self.assertEqual(receipt["status"], "failed")

    def test_evidence_retains_failures_and_report_only_profile(self) -> None:
        value = self.manifest()
        value["checks"].append(
            {"id": "bad", "command": ["python3", "-c", "raise SystemExit(1)"]}
        )
        value["profiling"] = {
            "workloads": [
                {
                    "id": "bench",
                    "kind": "validation",
                    "command": ["python3", "-c", "pass"],
                }
            ]
        }
        result = hygiene.evidence(self.root, value)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["profiles"][0]["enforcement"], "report_only")
        hygiene.write_reports(self.root / "reports", result)
        self.assertTrue((self.root / "reports/report.md").is_file())
        self.assertEqual(
            json.loads((self.root / "reports/evidence.json").read_text())["status"],
            "failed",
        )

    def test_mutation_during_checks_fails(self) -> None:
        value = self.manifest()
        value["checks"] = [
            {
                "id": "mutate",
                "command": [
                    "python3",
                    "-c",
                    "from pathlib import Path; Path('lock').write_text('changed')",
                ],
            }
        ]
        result = hygiene.evidence(self.root, value)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            next(
                c["reason"] for c in result["checks"] if c["id"] == "lockfile-stability"
            ),
            "lockfile_changed_during_verification",
        )

    def test_source_and_head_races_invalidate_clean_receipt(self) -> None:
        for code in (
            "from pathlib import Path; Path('source.py').write_text('changed')",
            "import subprocess; subprocess.run(['git','commit','--allow-empty','-qm','advance'],check=True)",
            "import subprocess; from pathlib import Path; Path('source.py').write_text('staged'); subprocess.run(['git','add','source.py'],check=True)",
        ):
            with self.subTest(code=code):
                self.git("reset", "--hard", "-q")
                self.git("clean", "-fdq")
                value = self.manifest()
                value["checks"] = [{"id": "mutate", "command": ["python3", "-c", code]}]
                result = hygiene.evidence(self.root, value)
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["source_worktree_dirty"])
                self.assertIn(
                    "source_changed_during_verification",
                    [c.get("reason") for c in result["checks"]],
                )

    def test_already_dirty_bytes_and_symlink_races_are_detected(self) -> None:
        (self.root / "source.py").write_text("initial dirty bytes")
        (self.root / "link").symlink_to("source.py")
        value = self.manifest()
        value["checks"] = [
            {
                "id": "mutate",
                "command": [
                    "python3",
                    "-c",
                    "from pathlib import Path; Path('source.py').write_text('new dirty bytes'); Path('link').unlink(); Path('link').symlink_to('missing')",
                ],
            }
        ]
        result = hygiene.evidence(self.root, value)
        self.assertEqual(result["status"], "failed")
        self.assertIn(
            "source_changed_during_verification",
            [c.get("reason") for c in result["checks"]],
        )

    def test_unittest_summary_records_skips_without_names(self) -> None:
        (self.root / "test_sample.py").write_text(
            "import unittest\nclass T(unittest.TestCase):\n @unittest.skip('PRIVATE_REASON')\n def test_case(self) -> None: pass\n"
        )
        result = hygiene.run_entry(
            self.root,
            {
                "id": "tests",
                "command": ["python3", "-m", "unittest", "discover", "-s", "."],
            },
        )
        self.assertEqual(result["tests_run"], 1)
        self.assertEqual(result["tests_skipped"], 1)
        self.assertNotIn("PRIVATE_REASON", json.dumps(result))

    def test_node_summary_records_only_numeric_counts(self) -> None:
        executable = self.root / "npm"
        executable.write_text(
            "#!/usr/bin/env python3\nprint('PRIVATE_TEST_NAME')\nprint('ℹ tests 14')\nprint('ℹ skipped 2')\n"
        )
        executable.chmod(0o755)
        result = hygiene.run_entry(
            self.root, {"id": "node-tests", "command": ["./npm"]}
        )
        self.assertEqual(result["tests_run"], 14)
        self.assertEqual(result["tests_skipped"], 2)
        self.assertNotIn("PRIVATE_TEST_NAME", json.dumps(result))

    def test_untracked_source_is_not_clean_commit_evidence(self) -> None:
        (self.root / "new_checker.py").write_text("pass\n")
        result = hygiene.evidence(self.root, self.manifest(), preflight_only=True)
        self.assertFalse(result["tracked_worktree_dirty"])
        self.assertTrue(result["source_worktree_dirty"])
        self.assertEqual(result["untracked_file_count"], 1)
        self.assertNotIn("new_checker.py", json.dumps(result))

    def test_nonstring_check_id_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            hygiene.validate_entry({"id": 3, "command": ["python3"]})

    def test_preflight_does_not_claim_checks_ran(self) -> None:
        result = hygiene.evidence(self.root, self.manifest(), preflight_only=True)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["checks"][1]["status"], "not_run")


if __name__ == "__main__":
    unittest.main()
