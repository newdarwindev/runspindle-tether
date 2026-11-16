"""Source contracts only; these tests cannot establish browser rendering/a11y."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.render_progress_fixtures import ARTIFACT, CANARY, build

ROOT = Path(__file__).resolve().parents[1]


class ProgressVisualSourceTests(unittest.TestCase):
    def test_state_inventory_and_accessible_field_mapping(self) -> None:
        source, text, mapping = build()
        states = {row["id"] for row in mapping["scenarios"]}
        self.assertEqual(
            states,
            {
                "admitted", "running", "blocked", "cancel-requested", "terminal",
                "unknown", "unsupported", "stale", "edited", "delivered",
                "failed", "long-content",
            },
        )
        for row in mapping["scenarios"]:
            self.assertIn(row["accessible_heading"], text)
            self.assertIn('aria-labelledby="heading-' + row["id"] + '"', source)
            self.assertIn(row["plain_text_label"], source)
        self.assertIn("LOCAL RENDER APPROXIMATION", source)
        self.assertIn("Actual Slack rendering: NOT RUN", source)
        self.assertIn("not approved baselines", source)

    def test_untrusted_projection_is_inert_and_canary_absent(self) -> None:
        source, text, _ = build()
        for value in (source, text):
            self.assertNotIn(CANARY, value)
            self.assertNotIn("?token=", value)
        self.assertNotIn("<script>", source)
        self.assertIn("&lt;script&gt;", source)
        self.assertNotIn('href="https:', source)
        self.assertIn("default-src 'none'", source)

    def test_accepted_bytes_and_plaintext_are_deterministic(self) -> None:
        first = build()
        self.assertEqual(first, build())
        self.assertEqual(first[2]["artifact_sha256"], hashlib.sha256(ARTIFACT).hexdigest())
        self.assertIn('href="accepted-artifact.txt" download', first[0])
        self.assertIn("Preview unavailable", first[0])
        manifest = json.loads((ROOT / "visual/scenarios.json").read_text())
        self.assertEqual(manifest["review_status"], "candidate_not_approved_baseline")
        self.assertEqual(manifest["actual_slack"], "not_run")

    def test_palette_text_contrast(self) -> None:
        def luminance(value: str) -> float:
            channels = [int(value[i : i + 2], 16) / 255 for i in (0, 2, 4)]
            linear = [
                value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
                for value in channels
            ]
            return sum(a * b for a, b in zip(linear, (0.2126, 0.7152, 0.0722)))

        for foreground, background in (
            ("172b42", "ffffff"), ("ffffff", "172b42"), ("38516b", "eef2f6"),
            ("714b00", "fff5d6"), ("9a2534", "fff0f1"), ("155f45", "eaf8f0"),
            ("52657a", "ffffff"), ("124e82", "ffffff"),
        ):
            low, high = sorted((luminance(foreground), luminance(background)))
            self.assertGreaterEqual((high + 0.05) / (low + 0.05), 4.5)

    def test_source_only_cli_never_imports_browser_or_network_and_refuses_overwrite(self) -> None:
        script = """
import builtins
import runpy
import socket
import sys
from unittest.mock import patch
original = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.split('.')[0] in ('playwright', 'PIL'):
        raise AssertionError('render dependency imported in source-only mode')
    return original(name, *args, **kwargs)
sys.argv = ['render_progress_fixtures.py', '--source-only', '--output', sys.argv[1]]
with patch.object(builtins, '__import__', guarded_import):
    with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')) as network:
        runpy.run_path('tools/render_progress_fixtures.py', run_name='__main__')
        network.assert_not_called()
"""
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "source"
            command = [sys.executable, "-O", "-c", script, str(output)]
            result = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "source_only_not_rendered")
            source, text, mapping = build()
            self.assertEqual((output / "index.html").read_text(), source)
            self.assertEqual((output / "plain-text.txt").read_text(), text)
            self.assertEqual((output / "accepted-artifact.txt").read_bytes(), ARTIFACT)
            self.assertEqual(json.loads((output / "field-map.json").read_text()), mapping)
            before = {file.name: file.read_bytes() for file in output.iterdir()}
            repeated = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=30
            )
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("Refusing to overwrite", repeated.stderr)
            self.assertEqual(before, {file.name: file.read_bytes() for file in output.iterdir()})
