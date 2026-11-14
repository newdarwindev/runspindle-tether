"""Artifact completeness and truthfulness mutations, no private source or network."""

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tools.check_mirroring_audit import (
    EVIDENCE_FILES,
    ROOT,
    privacy,
    reference,
    validate,
)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def refresh_hashes(root: Path) -> None:
    """Remove hash failures as a confounder when testing semantic rejection."""
    path = root / "docs/mirroring-audit-evidence.json"
    data = json.loads(path.read_text())
    data["sha256"] = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in sorted(EVIDENCE_FILES)
    }
    write_json(path, data)
    path = root / "docs/evidence-artifacts.json"
    data = json.loads(path.read_text())
    for row in data["artifacts"]:
        row["sha256"] = hashlib.sha256((root / row["path"]).read_bytes()).hexdigest()
    write_json(path, data)


class MirroringAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in ("docs", "specs", "tests", "tether", "tools"):
            shutil.copytree(
                ROOT / name,
                self.root / name,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        for name in (
            "STATUS.json",
            "provenance.json",
            "hygiene.json",
            "validation-partitions.json",
            "requirements-quality.txt",
        ):
            shutil.copy2(ROOT / name, self.root / name)

    def test_current_register_matches_runtime_and_retained_evidence(self) -> None:
        self.assertEqual(validate()["disposition_units"], 19)
        self.assertEqual(validate(self.root)["adapter_rows"], 8)

    def test_reference_checks_paths_anchors_and_actual_test_functions(self) -> None:
        for value in (
            "../missing",
            "/not-a-repository-file",
            "https://example.invalid/source",
            "tests/test_native_source.py#test_invented",
            "STATUS.json#invented",
            "docs/MIRRORING_ACCEPTANCE.md#invented",
            "docs/LICENSE-SRC-014.txt#invented",
            str(ROOT / "STATUS.json"),
            "docs/../STATUS.json",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                reference(ROOT, value)
        reference(
            ROOT,
            "tests/test_native_source.py#test_capability_modes_never_invent_event_coverage",
        )

    def test_privacy_guards_reject_synthetic_sensitive_forms(self) -> None:
        for value in (
            "/home/fixture/private.txt",
            "file:///fixture",
            "person@example.invalid",
            "https://name:password@example.invalid/",
            "audit-private-device.invalid",
            "xoxb-" + "a" * 24,
            "-----BEGIN PRIVATE KEY-----",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                privacy(value)
        privacy("SRC-014 synthetic task-1: live acceptance not_run")

    def test_incomplete_promoted_and_broken_register_mutations_fail(self) -> None:
        path = self.root / "docs/mirroring-coverage.json"
        original = json.loads(path.read_text())
        mutations: list[tuple[str, dict[str, Any]]] = []

        def add(category: str, edit: Callable[[dict[str, Any]], object]) -> None:
            data = copy.deepcopy(original)
            edit(data)
            mutations.append((category, data))

        add("disposition completeness", lambda d: d["dispositions"].pop())
        add(
            "duplicate source_item",
            lambda d: d["dispositions"].append(d["dispositions"][0]),
        )
        add(
            "snapshot exclusion",
            lambda d: d["dispositions"][1].update(disposition="adapted"),
        )
        add("sections", lambda d: d["source_sections"].pop())
        add("adapter completeness", lambda d: d["adapter_matrix"].pop())
        add(
            "actual capability mismatch",
            lambda d: d["adapter_matrix"][1]["events"].update(
                tool_start="synthetic_supported"
            ),
        )
        add(
            "hidden reasoning",
            lambda d: d["adapter_matrix"][0]["events"].update(
                hidden_reasoning="synthetic_supported"
            ),
        )
        add(
            "historical executable claim",
            lambda d: d["adapter_matrix"][4].update(
                implementation="tether/native_testing.py"
            ),
        )
        add(
            "adapter authority/live status",
            lambda d: d["adapter_matrix"][0].update(live_coverage="passed"),
        )
        add(
            "adapter authority/live status",
            lambda d: d["adapter_matrix"][0].update(control=True),
        )
        add(
            "wire evidence promotion",
            lambda d: d["component_matrix"][3].update(readback="confirmed"),
        )
        add(
            "component source evidence",
            lambda d: d["component_matrix"][0].update(classification="live_provider"),
        )
        add(
            "component source evidence",
            lambda d: d["component_matrix"][1].update(durability="production_outbox"),
        )
        add(
            "component source evidence",
            lambda d: d["component_matrix"][2].update(
                classification="universal_secret_discovery"
            ),
        )
        add(
            "wire source evidence",
            lambda d: d["component_matrix"][3].update(implementation=None),
        )
        add(
            "live provider claim",
            lambda d: d["component_matrix"][4].update(
                implementation="tether/testing.py"
            ),
        )
        add("failure completeness", lambda d: d["failure_matrix"].pop())
        add(
            "test reference",
            lambda d: d["failure_matrix"][0].update(
                evidence=["tests/test_native_source.py#missing_test"]
            ),
        )
        add(
            "fabricated live evidence",
            lambda d: d["live_evidence_template"]["values"].update(
                independent_destination_receipts="passed"
            ),
        )
        add("closure scope", lambda d: d["runtime_issues_remaining_open"].remove(9))
        for category, data in mutations:
            write_json(path, data)
            refresh_hashes(self.root)
            with (
                self.subTest(category=category),
                self.assertRaisesRegex(ValueError, category),
            ):
                validate(self.root)
        write_json(path, original)
        refresh_hashes(self.root)
        self.assertEqual(validate(self.root)["status"], "passed")

    def test_status_and_provenance_promotions_fail_even_with_updated_hashes(
        self,
    ) -> None:
        mutations: list[tuple[str, str, Callable[[dict[str, Any]], object]]] = [
            (
                "STATUS.json",
                "product status",
                lambda d: d.update(live_acceptance="passed"),
            ),
            (
                "STATUS.json",
                "product status",
                lambda d: d.update(selected_source_migration="complete"),
            ),
            (
                "STATUS.json",
                "artifact runtime promotion",
                lambda d: d["src014_artifact_lift"].update(runtime_completion=True),
            ),
            (
                "STATUS.json",
                "wire source status",
                lambda d: d["slack_wire_protocol"].update(live_transport="passed"),
            ),
            (
                "provenance.json",
                "provenance classification",
                lambda d: d["sources"][0].update(executable_implementation="imported"),
            ),
            (
                "provenance.json",
                "provenance classification",
                lambda d: d["sources"][0].update(historical_reference="published"),
            ),
        ]
        for name, category, edit in mutations:
            path = self.root / name
            original = json.loads(path.read_text())
            data = copy.deepcopy(original)
            edit(data)
            write_json(path, data)
            refresh_hashes(self.root)
            with (
                self.subTest(category=category),
                self.assertRaisesRegex(ValueError, category),
            ):
                validate(self.root)
            write_json(path, original)
        refresh_hashes(self.root)
        self.assertEqual(validate(self.root)["status"], "passed")

    def test_changed_bytes_and_missing_hash_inventory_fail(self) -> None:
        path = self.root / "docs/MIRRORING_COVERAGE.md"
        path.write_text(path.read_text() + "\nChanged content.\n")
        with self.assertRaisesRegex(ValueError, "current evidence hash"):
            validate(self.root)
        refresh_hashes(self.root)
        self.assertEqual(validate(self.root)["status"], "passed")
        path = self.root / "docs/mirroring-audit-evidence.json"
        data = json.loads(path.read_text())
        data["sha256"].pop("docs/mirroring-coverage.json")
        write_json(path, data)
        with self.assertRaisesRegex(ValueError, "evidence hash inventory"):
            validate(self.root)

    def test_manifest_inventory_and_hash_guard_are_explicit(self) -> None:
        path = self.root / "docs/evidence-artifacts.json"
        data = json.loads(path.read_text())
        data["artifacts"][0]["sha256"] = "0" * 64
        write_json(path, data)
        with self.assertRaisesRegex(ValueError, "manifest artifact hash"):
            validate(self.root)
        refresh_hashes(self.root)
        data = json.loads(path.read_text())
        data["artifacts"].pop()
        write_json(path, data)
        with self.assertRaisesRegex(ValueError, "manifest inventory"):
            validate(self.root)

    def test_notice_and_private_form_cannot_be_blessed_by_rehash(self) -> None:
        path = self.root / "docs/LICENSE-SRC-014.txt"
        original = path.read_bytes()
        path.write_bytes(original + b"\nChanged notice.\n")
        refresh_hashes(self.root)
        with self.assertRaisesRegex(ValueError, "notice integrity"):
            validate(self.root)
        path.write_bytes(original)
        path = self.root / "docs/MIRRORING_COVERAGE.md"
        path.write_text(path.read_text() + "\naudit-private-device.invalid\n")
        refresh_hashes(self.root)
        with self.assertRaisesRegex(ValueError, "unsafe publication form"):
            validate(self.root)

    def test_optimized_checker_rejects_real_semantic_and_hash_mutations(self) -> None:
        command = [sys.executable, "-O", "tools/check_mirroring_audit.py"]
        good = subprocess.run(
            command, cwd=self.root, capture_output=True, text=True, check=False
        )
        self.assertEqual(good.returncode, 0, good.stderr)
        path = self.root / "docs/mirroring-coverage.json"
        original = path.read_text()
        data = json.loads(original)
        data["dispositions"].pop()
        write_json(path, data)
        refresh_hashes(self.root)
        bad = subprocess.run(
            command, cwd=self.root, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("mirroring audit: disposition completeness", bad.stderr)
        path.write_text(original)
        refresh_hashes(self.root)
        path = self.root / "docs/evidence-artifacts.json"
        data = json.loads(path.read_text())
        data["artifacts"][0]["sha256"] = "0" * 64
        write_json(path, data)
        bad = subprocess.run(
            command, cwd=self.root, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("mirroring audit: manifest artifact hash", bad.stderr)

    def test_original_evidence_cannot_be_rehashed_as_current_validation(self) -> None:
        path = self.root / "docs/mirroring-audit-original-evidence.json"
        original = path.read_bytes()
        data = json.loads(path.read_text())
        data["validation_results"]["normal_tests"] = 999
        write_json(path, data)
        refresh_hashes(self.root)
        with self.assertRaisesRegex(ValueError, "historical validation integrity"):
            validate(self.root)
        path.write_bytes(original)
        refresh_hashes(self.root)
        path = self.root / "docs/evidence-artifacts.json"
        data = json.loads(path.read_text())
        row = next(
            item
            for item in data["artifacts"]
            if item["path"] == "docs/mirroring-audit-original-evidence.json"
        )
        row["historical_original"] = False
        write_json(path, data)
        with self.assertRaisesRegex(ValueError, "historical manifest classification"):
            validate(self.root)

    def test_audit_is_mandatory_in_exactly_one_component_partition(self) -> None:
        inventory = json.loads((ROOT / "hygiene.json").read_text())
        manifest = json.loads((ROOT / "validation-partitions.json").read_text())
        checks = [c for c in inventory["checks"] if c["id"] == "check-mirroring-audit"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(
            checks[0]["command"], ["python3", "tools/check_mirroring_audit.py"]
        )
        self.assertNotIn("not_applicable", checks[0])
        self.assertIn(
            "docs/mirroring-audit-original-evidence.json", checks[0]["required_files"]
        )
        assignments = [
            name
            for name, items in manifest["partitions"].items()
            for item in items
            if item == "check-mirroring-audit"
        ]
        self.assertEqual(assignments, ["component"])
