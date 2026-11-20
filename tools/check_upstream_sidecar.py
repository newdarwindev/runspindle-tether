#!/usr/bin/env python3
"""Isolated original-upstream adapter tests; never activates chat or model clients."""

import argparse
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def accepted(result: unittest.TestResult) -> bool:
    return result.testsRun > 0 and not result.skipped and result.wasSuccessful()


def main() -> int:
    from runspindle_tether.source_gate import verify

    parser = argparse.ArgumentParser()
    parser.add_argument("tether", type=Path)
    parser.add_argument("agent_tether", type=Path)
    parser.add_argument("--dependencies", type=Path)
    args = parser.parse_args()
    roots = [args.agent_tether.resolve() / "src", args.tether.resolve() / "agent", ROOT]
    if args.dependencies is not None:
        dependencies = args.dependencies.resolve(strict=True)
        if not dependencies.is_dir():
            raise ValueError("Upstream dependency path must be a directory")
        roots.append(dependencies)
    for name, path in [("tether", args.tether), ("agent-tether", args.agent_tether)]:
        verify(path.resolve(), name, ROOT / "upstream/pins.json")
    code = (
        "import sys,unittest; sys.path[:0]="
        + repr([str(p) for p in roots])
        + "; suite=unittest.defaultTestLoader.discover("
        + repr(str(ROOT / "upstream/tests"))
        + "); result=unittest.TextTestRunner(verbosity=2).run(suite); from tools.check_upstream_sidecar import accepted; sys.exit(not accepted(result))"
    )
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            *(["-O"] if sys.flags.optimize else []),
            "-c",
            code,
        ],
        env=env,
        timeout=60,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
