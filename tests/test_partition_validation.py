"""Negative tests for exact-source aggregate CI receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import hygiene  # noqa: E402
from tools import partition_validation as gate  # noqa: E402


class AggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, self.inventory, self.manifest_sha, self.hygiene_sha = (
            gate.manifests()
        )
        self.image_sha = self.manifest["image"]["sha256"]
        self.head = "a" * 40
        self.run_id = "12345"
        by_id = {x["id"]: x for x in self.inventory["checks"]}
        self.receipts = {}
        for partition in gate.PARTITIONS:
            checks = []
            for identity in self.manifest["partitions"][partition]:
                entry = by_id[identity]
                if "not_applicable" in entry:
                    checks.append(
                        {
                            "id": identity,
                            "status": "not_applicable",
                            "reason": entry["not_applicable"],
                        }
                    )
                else:
                    checks.append(
                        {
                            "id": identity,
                            "status": "passed",
                            "exit_code": 0,
                            "command_sha256": hashlib.sha256(
                                json.dumps(entry["command"]).encode()
                            ).hexdigest(),
                        }
                    )
            self.receipts[partition] = {
                "schema_version": 1,
                "partition": partition,
                "run_id": self.run_id,
                "source_sha": self.head,
                "manifest_sha256": self.manifest_sha,
                "hygiene_sha256": self.hygiene_sha,
                "image_sha256": self.image_sha,
                "binding": {
                    "image_source_sha": self.manifest["image"]["source_sha"],
                    **{
                        k: self.manifest["image"][k]
                        for k in (
                            "controller_sha256",
                            "recipe_sha256",
                            "tool_closure_sha256",
                        )
                    },
                },
                "source_fingerprint": "b" * 64,
                "preflight": {
                    "id": "reproducible-inputs",
                    "status": "passed",
                    "problems": [],
                }
                if partition == "quality"
                else None,
                "checks": checks,
                "status": "passed",
            }
        self.results = {x: "success" for x in gate.PARTITIONS}

    def check(
        self,
        receipts: dict[str, dict[str, Any]] | None = None,
        results: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return gate.aggregate(
            receipts if receipts is not None else self.receipts,
            results if results is not None else self.results,
            self.manifest,
            self.inventory,
            self.manifest_sha,
            self.hygiene_sha,
            self.image_sha,
            self.head,
            self.run_id,
        )

    def test_complete_receipts(self) -> None:
        self.assertEqual(self.check()["status"], "passed")

    def test_missing_cancelled_and_stale(self) -> None:
        for field, value in [
            ("source_sha", "c" * 40),
            ("image_sha256", "d" * 64),
            ("manifest_sha256", "e" * 64),
            ("run_id", "999"),
        ]:
            receipts = copy.deepcopy(self.receipts)
            receipts["quality"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(receipts)
        results = self.results | {"rust": "cancelled"}
        with self.assertRaises(ValueError):
            self.check(results=results)
        receipts = copy.deepcopy(self.receipts)
        del receipts["mutation_4"]
        with self.assertRaises(ValueError):
            self.check(receipts)

    def test_duplicate_missing_and_forged_checks(self) -> None:
        name = next(x for x in gate.PARTITIONS if self.receipts[x]["checks"])
        for change in ("missing", "duplicate", "forged"):
            receipts = copy.deepcopy(self.receipts)
            if change == "missing":
                receipts[name]["checks"].pop()
            elif change == "duplicate":
                receipts[name]["checks"].append(receipts[name]["checks"][0])
            else:
                check = next(
                    (x for x in receipts[name]["checks"] if x["status"] == "passed"),
                    None,
                )
                if check is None:
                    continue
                check["command_sha256"] = "0" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(receipts)

    def test_preflight_required(self) -> None:
        receipts = copy.deepcopy(self.receipts)
        receipts["quality"]["preflight"]["status"] = "failed"
        with self.assertRaises(ValueError):
            self.check(receipts)

    def test_partition_source_fingerprints_must_match(self) -> None:
        receipts = copy.deepcopy(self.receipts)
        receipts["rust"]["source_fingerprint"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "source bytes differ"):
            self.check(receipts)

    def test_guest_binding_requires_observed_recipe_and_controller(self) -> None:
        image = self.manifest["image"]
        observed = {
            "image_sha256": image["sha256"],
            "image_source_sha": image["source_sha"],
            "controller_sha256": image["controller_sha256"],
            "recipe_sha256": image["recipe_sha256"],
            "tool_closure_sha256": image["tool_closure_sha256"],
        }
        gate.validate_instance_binding(observed, image)
        observed["recipe_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binding"):
            gate.validate_instance_binding(observed, image)
        observed["recipe_sha256"] = image["recipe_sha256"]
        observed["image_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binding"):
            gate.validate_instance_binding(observed, image)

    def test_failure_summary_is_bounded_and_sanitized(self) -> None:
        lines = hygiene.failure_summary(
            {"checks": [{"id": "rust-test", "status": "failed", "exit_code": 2}]}
        )
        self.assertEqual(lines, ["hygiene failure: check=rust-test exit=2"])

    def test_manifest_missing_partition_and_duplicate_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hygiene.json").write_bytes(
                (gate.ROOT / "hygiene.json").read_bytes()
            )
            manifest = copy.deepcopy(self.manifest)
            del manifest["partitions"]["mutation_4"]
            (root / "validation-partitions.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "partition manifest"):
                gate.manifests(root)
            manifest = copy.deepcopy(self.manifest)
            identity = next(x for x in gate.PARTITIONS if manifest["partitions"][x])
            manifest["partitions"][identity].append(manifest["partitions"][identity][0])
            (root / "validation-partitions.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "duplicate mandatory"):
                gate.manifests(root)


if __name__ == "__main__":
    unittest.main()
