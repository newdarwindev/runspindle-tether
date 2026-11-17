"""Additive exact provenance for trusted local visual qualification, not approval."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "visual/scenarios.json",
    "visual/progress.css",
    "visual/parent-criterion-map.json",
    "tools/render_progress_fixtures.py",
    "tools/check_progress_visual.py",
    "tools/progress_visual_provenance.py",
    "tether/sanitization.py",
    "tether/__init__.py",
    "requirements-visual.txt",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance(browser_binary: Path) -> dict[str, Any]:
    """Hash supplied executable, never guess the binary behind a shell launcher."""
    binary = browser_binary.resolve(strict=True)
    if binary.read_bytes()[:4] != b"\x7fELF":
        raise ValueError("supply the actual ELF browser binary, not a launcher")
    requirements = {}
    for line in (ROOT / "requirements-visual.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, version = line.split("==")
        actual = importlib.metadata.version(name)
        if actual != version:
            raise ValueError("visual dependency version mismatch: " + name)
        dist = importlib.metadata.distribution(name)
        files = dist.files
        if not files:
            raise ValueError("missing installed distribution inventory: " + name)
        hashes = {}
        for entry in files:
            path = Path(str(dist.locate_file(entry)))
            if not path.is_file():
                raise ValueError("missing installed distribution file: " + str(entry))
            hashes[str(entry)] = digest(path)
        if not hashes:
            raise ValueError("empty distribution inventory")
        requirements[name] = {"version": actual, "files": hashes}
    mapping = json.loads((ROOT / "visual/parent-criterion-map.json").read_text())
    scenarios = json.loads((ROOT / "visual/scenarios.json").read_text())["scenarios"]
    if [row["id"] for row in mapping["scenarios"]] != [row["id"] for row in scenarios]:
        raise ValueError("parent mapping is incomplete")
    return {
        "schema": "tether.visual-provenance.v1",
        "evidence_class": "toolchain_and_source_inventory_not_render_approval",
        "source_sha256": {name: digest(ROOT / name) for name in SOURCES},
        "browser_binary_sha256": digest(binary),
        "browser_binary": str(binary),
        "browser_version": subprocess.check_output(
            [str(binary), "--version"], text=True, timeout=10
        ).strip(),
        "python_binary_sha256": digest(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "packages": requirements,
        "bytecode_scope": "all_distribution_listed_files_including_caches; not proof of executed bytes",
        "actual_slack": "not_run",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser-binary", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(provenance(args.browser_binary), indent=2, sort_keys=True))
