#!/usr/bin/env python3
"""Mandatory actual-upstream suite: exact sources/dependencies, no fallback."""

from __future__ import annotations

import importlib.metadata
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify_dependencies(requirements: Path) -> None:
    for raw in requirements.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", line)
        if match is None:
            raise ValueError("Unpinned upstream dependency")
        name, version = match.groups()
        if importlib.metadata.version(name) != version:
            raise ValueError("Wrong upstream dependency version")


def main() -> int:
    verify_dependencies(ROOT / "upstream/requirements.txt")
    runner_temp = os.environ.get("RUNNER_TEMP")
    dependency_args = []
    if runner_temp:
        dependencies = (Path(runner_temp) / "tether-upstream").resolve(strict=True)
        dependency_args = ["--dependencies", str(dependencies)]
    return subprocess.run(
        [
            sys.executable,
            "-B",
            *(["-O"] if sys.flags.optimize else []),
            str(ROOT / "tools/check_upstream_sidecar.py"),
            str(ROOT / ".upstream-tether"),
            str(ROOT / ".upstream-agent-tether"),
            *dependency_args,
        ],
        timeout=90,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
