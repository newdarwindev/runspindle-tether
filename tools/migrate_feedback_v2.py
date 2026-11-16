#!/usr/bin/env python3
"""Explicit local feedback migration. Stop all store clients before invoking."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tether.feedback_schema import migrate_feedback_v1_to_v2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    parser.add_argument("--clients-quiesced", action="store_true", required=True)
    args = parser.parse_args()
    failed = False
    try:
        migrate_feedback_v1_to_v2(args.path)
    except Exception:
        failed = True
    if failed:
        print("feedback migration rejected")
        return 1
    print("feedback schema migrated to v2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
