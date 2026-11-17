"""Synthetic comparator admission tests, not native rendering evidence."""

from __future__ import annotations

import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

from tools.check_native_progress_reference import compare, sha


@unittest.skipUnless(
    importlib.util.find_spec("PIL"),
    "optional Pillow required for native image comparison",
)
class NativeReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        from PIL import Image

        self.Image = Image
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reference, self.actual = self.root / "reference", self.root / "actual"
        for root in (self.reference, self.actual):
            root.mkdir()
            self.Image.new("RGB", (4, 4), "white").save(root / "sample.png")
            self.write_evidence(root)
        self.review = self.root / "review.json"
        self.approve()

    def write_evidence(self, root: Path) -> None:
        (root / "evidence.json").write_text(
            json.dumps(
                {
                    "status": "generated_candidate",
                    "source_sha256": {"synthetic.py": "a" * 64},
                    "environment": {"synthetic": True},
                    "repeat_pixel_tolerance": 0,
                    "sha256": {"sample.png": sha(root / "sample.png")},
                }
            )
        )

    def approve(self) -> None:
        self.review.write_text(
            json.dumps(
                {
                    "schema": "tether.native-zoom-review.v1",
                    "disposition": "approved_synthetic_reference",
                    "pixel_tolerance": 0,
                    "evidence_sha256": sha(self.reference / "evidence.json"),
                    "artifact_sha256": json.loads(
                        (self.reference / "evidence.json").read_text()
                    )["sha256"],
                }
            )
        )

    def test_exact_reviewed_images_pass_without_writes(self) -> None:
        before = {str(p): sha(p) for p in self.root.rglob("*") if p.is_file()}
        result = compare(self.reference, self.actual, self.review)
        self.assertEqual(result["images"], 1)
        self.assertEqual(result["actual_slack"], "not_run")
        self.assertEqual(
            before, {str(p): sha(p) for p in self.root.rglob("*") if p.is_file()}
        )

    def test_pixel_mutation_with_rehashed_manifest_still_fails(self) -> None:
        path = self.actual / "sample.png"
        with self.Image.open(path) as original:
            image = original.copy()
        image.putpixel((1, 1), (0, 0, 0))
        image.save(path)
        self.write_evidence(self.actual)
        with self.assertRaisesRegex(ValueError, "pixel difference"):
            compare(self.reference, self.actual, self.review)

    def test_missing_candidate_or_stale_review_fails(self) -> None:
        data = json.loads(self.review.read_text())
        for key, value in [
            ("disposition", "candidate_not_approved"),
            ("pixel_tolerance", False),
            ("evidence_sha256", "0" * 64),
        ]:
            self.review.write_text(json.dumps({**data, key: value}))
            with self.assertRaises(ValueError):
                compare(self.reference, self.actual, self.review)
        self.review.unlink()
        with self.assertRaises(ValueError):
            compare(self.reference, self.actual, self.review)

    def test_changed_environment_and_incomplete_artifacts_fail(self) -> None:
        path = self.actual / "evidence.json"
        original = json.loads(path.read_text())
        path.write_text(json.dumps({**original, "environment": {"synthetic": False}}))
        with self.assertRaisesRegex(ValueError, "environment mismatch"):
            compare(self.reference, self.actual, self.review)
        path.write_text(json.dumps(original))
        (self.actual / "sample.png").unlink()
        with self.assertRaisesRegex(ValueError, "regular artifact"):
            compare(self.reference, self.actual, self.review)

    def test_alpha_mutation_is_not_ignored(self) -> None:
        path = self.actual / "sample.png"
        with self.Image.open(path) as original:
            image = original.convert("RGBA")
        image.putpixel((1, 1), (255, 255, 255, 0))
        image.save(path)
        self.write_evidence(self.actual)
        with self.assertRaisesRegex(ValueError, "pixel difference"):
            compare(self.reference, self.actual, self.review)
