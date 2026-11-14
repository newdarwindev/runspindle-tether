"""Negative tests for exact-source aggregate CI receipts."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import partition_validation as gate


class AggregateTests(unittest.TestCase):
    def setUp(self):
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
                    k: self.manifest["image"][k]
                    for k in (
                        "controller_sha256",
                        "recipe_sha256",
                        "tool_closure_sha256",
                    )
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

    def check(self, receipts=None, results=None):
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

    def test_complete_receipts(self):
        self.assertEqual(self.check()["status"], "passed")

    def test_missing_cancelled_and_stale(self):
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
        del receipts["mutation"]
        with self.assertRaises(ValueError):
            self.check(receipts)

    def test_duplicate_missing_and_forged_checks(self):
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

    def test_preflight_required(self):
        receipts = copy.deepcopy(self.receipts)
        receipts["quality"]["preflight"]["status"] = "failed"
        with self.assertRaises(ValueError):
            self.check(receipts)

    def test_manifest_missing_partition_and_duplicate_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hygiene.json").write_bytes(
                (gate.ROOT / "hygiene.json").read_bytes()
            )
            manifest = copy.deepcopy(self.manifest)
            del manifest["partitions"]["mutation"]
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
