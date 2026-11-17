"""Independent exact-source and dependency admission checks; no browser execution."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import progress_visual_provenance as audit


class ProvenanceTests(unittest.TestCase):
    def test_parent_map_covers_every_state_and_reuses_existing_siblings(self) -> None:
        mapping = json.loads(
            (audit.ROOT / "visual/parent-criterion-map.json").read_text()
        )
        scenarios = json.loads((audit.ROOT / "visual/scenarios.json").read_text())[
            "scenarios"
        ]
        self.assertEqual(
            [x["id"] for x in mapping["scenarios"]], [x["id"] for x in scenarios]
        )
        self.assertEqual(
            mapping["reused_h01"], "https://github.com/newdarwindev/runspindle/issues/8"
        )
        self.assertEqual(
            mapping["reused_h07"],
            "https://github.com/newdarwindev/runspindle/issues/14",
        )
        self.assertEqual(
            mapping["separate_live_h01"],
            "https://github.com/newdarwindev/runspindle/issues/22",
        )
        for row, scenario in zip(mapping["scenarios"], scenarios):
            self.assertEqual(row["actual_slack"], "not_run")
            self.assertEqual(row["expected_outcome"], scenario["outcome"])
            self.assertTrue(row["parent_criteria"])
            self.assertTrue(
                (audit.ROOT / "docs/visual-reference" / row["reference_png"]).is_file()
            )

    def test_launcher_and_unpinned_dependencies_reject_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "synthetic-browser"
            binary.write_bytes(b"#!/bin/sh\n")
            with patch("subprocess.check_output") as execute:
                with self.assertRaisesRegex(ValueError, "actual ELF"):
                    audit.provenance(binary)
                execute.assert_not_called()
            binary.write_bytes(b"\x7fELFsynthetic-nonexecutable")
            with (
                patch("importlib.metadata.version", return_value="wrong"),
                patch("subprocess.check_output") as execute,
            ):
                with self.assertRaisesRegex(ValueError, "version mismatch"):
                    audit.provenance(binary)
                execute.assert_not_called()

    def test_dependency_inventory_mutation_changes_evidence_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "synthetic-browser"
            binary.write_bytes(b"\x7fELFsynthetic-nonexecutable")
            package = root / "module.py"
            package.write_text("synthetic = 1\n")
            versions = dict(
                line.split("==")
                for line in (audit.ROOT / "requirements-visual.txt")
                .read_text()
                .splitlines()
            )
            dist = SimpleNamespace(
                files=[Path("module.py")], locate_file=lambda _: package
            )
            with (
                patch("importlib.metadata.version", side_effect=versions.__getitem__),
                patch("importlib.metadata.distribution", return_value=dist),
                patch("subprocess.check_output", return_value="Synthetic browser 1"),
            ):
                before = audit.provenance(binary)
                package.write_text("synthetic = 2\n")
                after = audit.provenance(binary)
            self.assertNotEqual(before["packages"], after["packages"])
            self.assertEqual(before["source_sha256"], after["source_sha256"])
            self.assertIn("tether/sanitization.py", before["source_sha256"])
            self.assertIn("requirements-visual.txt", before["source_sha256"])
            self.assertEqual(before["actual_slack"], "not_run")

    def test_missing_distribution_file_rejects_incomplete_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "synthetic-browser"
            binary.write_bytes(b"\x7fELFsynthetic-nonexecutable")
            versions = dict(
                line.split("==")
                for line in (audit.ROOT / "requirements-visual.txt")
                .read_text()
                .splitlines()
            )
            dist = SimpleNamespace(
                files=[Path("missing.py")],
                locate_file=lambda _: Path(tmp) / "missing.py",
            )
            with (
                patch("importlib.metadata.version", side_effect=versions.__getitem__),
                patch("importlib.metadata.distribution", return_value=dist),
                patch("subprocess.check_output") as execute,
            ):
                with self.assertRaisesRegex(
                    ValueError, "missing installed distribution file"
                ):
                    audit.provenance(binary)
                execute.assert_not_called()
