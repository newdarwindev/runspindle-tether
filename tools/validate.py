#!/usr/bin/env python3
"""Run the declared checks without implicit installs or file-existence skips."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.hygiene import main

if __name__ == "__main__":
    prepared = Path("/opt/runspindle-temporal")
    if prepared.is_dir():
        os.environ.setdefault("RUNSPINDLE_TEMPORAL_PREPARED", str(prepared))
    raise SystemExit(main())
