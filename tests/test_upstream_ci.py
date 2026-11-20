"""Dependency admission rejects missing or drifted upstream environments."""

from __future__ import annotations

import importlib.metadata
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import check_upstream_ci as ci


class DependencyTests(unittest.TestCase):
    def test_exact_versions_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("# comment\nsqlmodel==0.0.27\n")
            with patch.object(importlib.metadata, "version", return_value="0.0.27"):
                ci.verify_dependencies(path)
            with patch.object(importlib.metadata, "version", return_value="0.0.28"):
                with self.assertRaises(ValueError):
                    ci.verify_dependencies(path)
            with patch.object(
                importlib.metadata,
                "version",
                side_effect=importlib.metadata.PackageNotFoundError,
            ):
                with self.assertRaises(importlib.metadata.PackageNotFoundError):
                    ci.verify_dependencies(path)

    def test_unpinned_dependency_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("sqlmodel>=0.0.27\n")
            with patch.object(importlib.metadata, "version") as version:
                with self.assertRaises(ValueError):
                    ci.verify_dependencies(path)
            version.assert_not_called()


class OutcomeTests(unittest.TestCase):
    def test_empty_or_skipped_upstream_suite_is_failure(self) -> None:
        from tools.check_upstream_sidecar import accepted

        result = unittest.TestResult()
        self.assertFalse(accepted(result))
        result.testsRun = 1
        self.assertTrue(accepted(result))
        result.skipped.append(
            (unittest.FunctionTestCase(lambda: None), "missing prerequisite")
        )
        self.assertFalse(accepted(result))
