"""The baseline never turns new violations or missing tools green."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "static_quality", Path(__file__).resolve().parents[1] / "tools/static_quality.py"
)
assert SPEC is not None and SPEC.loader is not None
quality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(quality)


class StaticQualityTests(unittest.TestCase):
    def test_new_diagnostic_fails_without_mutating_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            baseline = root / "tools/quality-baseline.json"
            payload = json.dumps({"schema_version": 1, "diagnostics": {"old": 1}})
            baseline.write_text(payload)
            with (
                patch.object(quality, "ROOT", root),
                patch.object(quality.os, "chdir"),
                patch.object(quality, "inputs", return_value=[]),
                patch.object(quality, "collect", return_value=(["old", "new"], {})),
                patch("sys.argv", ["quality"]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(quality.main(), 1)
            self.assertEqual(baseline.read_text(), payload)

    def test_duplicate_existing_diagnostic_is_new_debt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            (root / "tools/quality-baseline.json").write_text(
                json.dumps({"schema_version": 1, "diagnostics": {"old": 1}})
            )
            with (
                patch.object(quality, "ROOT", root),
                patch.object(quality.os, "chdir"),
                patch.object(quality, "inputs", return_value=[]),
                patch.object(quality, "collect", return_value=(["old", "old"], {})),
                patch("sys.argv", ["quality"]),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(quality.main(), 1)

    def test_missing_pinned_tool_fails(self) -> None:
        with patch.object(
            quality.metadata,
            "version",
            side_effect=quality.metadata.PackageNotFoundError("ruff"),
        ):
            with self.assertRaises(quality.metadata.PackageNotFoundError):
                quality.collect([])

    def test_wrong_tool_version_fails(self) -> None:
        with patch.object(quality.metadata, "version", return_value="0.0.0"):
            with self.assertRaisesRegex(RuntimeError, "version mismatch"):
                quality.collect([])

    def test_missing_executable_is_not_a_skip(self) -> None:
        with patch.object(
            quality.subprocess, "run", side_effect=FileNotFoundError("missing")
        ):
            with self.assertRaises(FileNotFoundError):
                quality.command(["missing"])

    def test_stderr_only_failure_is_not_clean(self) -> None:
        result = quality.subprocess.CompletedProcess(
            ["fake"], 1, stdout="", stderr="fatal"
        )
        with patch.object(quality.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "checker failed"):
                quality.command(["fake"])

    def test_invalid_checker_exit_fails(self) -> None:
        result = quality.subprocess.CompletedProcess(
            ["fake"], 127, stdout="", stderr=""
        )
        with patch.object(quality.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "checker failed"):
                quality.command(["fake"])


if __name__ == "__main__":
    unittest.main()
