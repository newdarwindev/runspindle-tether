"""Committed local references retain exact provenance; never assert Slack parity."""

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.check_progress_visual import compare, verify_manifest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "docs/visual-reference"


class ProgressVisualArtifactsTests(unittest.TestCase):
    def test_committed_inputs_and_artifacts_match_manifest(self) -> None:
        evidence = verify_manifest(REFERENCE)
        self.assertEqual(evidence["actual_slack"], "not_run")
        self.assertEqual(len(evidence["mapping"]["scenarios"]), 12)
        self.assertEqual(evidence["repeat_render_hashes"], "identical")
        self.assertEqual(evidence["pixel_comparison_threshold"], 0)
        self.assertEqual(
            evidence["mutants"],
            {
                "missing_label": "detected",
                "clipping": "detected",
                "split_header": "detected",
            },
        )
        for value in evidence["computed_minimum_contrast"].values():
            self.assertGreaterEqual(value, 4.5)
        for width in (320, 390, 768, 1440):
            self.assertIn(f"progress-{width}.png", evidence["sha256"])
            self.assertIn(f"progress-{width}.aria.txt", evidence["sha256"])
        self.assertIn("zoom-long-content.png", evidence["sha256"])
        self.assertIn("keyboard-expanded.png", evidence["sha256"])

    def test_guard_never_silently_rewrites_changed_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            shutil.copytree(REFERENCE, target, dirs_exist_ok=True)
            changed = target / "admitted.png"
            changed.write_bytes(changed.read_bytes() + b"deliberate mutation")
            before = changed.read_bytes()
            with self.assertRaises(ValueError):
                verify_manifest(target)
            self.assertEqual(changed.read_bytes(), before)

    @unittest.skipUnless(
        importlib.util.find_spec("PIL"), "pinned visual dependencies required"
    )
    def test_exact_pixel_oracle_and_deliberate_one_pixel_mutation(self) -> None:
        from PIL import Image

        self.assertEqual(compare(REFERENCE, REFERENCE)["pixel_threshold"], 0)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            shutil.copytree(REFERENCE, target, dirs_exist_ok=True)
            changed = target / "admitted.png"
            with Image.open(changed) as image:
                mutated = image.convert("RGB")
                mutated.putpixel((0, 0), (255, 0, 255))
                mutated.save(changed)
            evidence = json.loads((target / "evidence.json").read_text())
            evidence["sha256"][changed.name] = hashlib.sha256(
                changed.read_bytes()
            ).hexdigest()
            (target / "evidence.json").write_text(json.dumps(evidence))
            with self.assertRaisesRegex(ValueError, "nonzero pixel difference"):
                compare(REFERENCE, target)
