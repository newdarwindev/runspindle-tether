#!/usr/bin/env python3
"""Read-only, exact-pixel comparison; never rewrites a visual baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify_manifest(directory: Path) -> dict:
    evidence = json.loads((directory / "evidence.json").read_text())
    for name, expected in evidence["sha256"].items():
        if Path(name).name != name:
            raise ValueError("invalid artifact name")
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError("artifact digest mismatch: " + name)
    for name, expected in evidence["source_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError("source digest mismatch: " + name)
    return evidence


def compare(reference: Path, actual: Path) -> dict:
    from PIL import Image, ImageChops

    baseline, observed = verify_manifest(reference), verify_manifest(actual)
    if baseline["baseline_approval"] != "approved_synthetic_reference":
        raise ValueError("reference baseline is not approved")
    pins = (
        "chromium",
        "python",
        "platform",
        "playwright",
        "pillow",
        "fonts",
        "locale",
        "timezone",
        "device_pixel_ratio",
        "clock",
        "seed",
        "animations",
    )
    if any(baseline[key] != observed[key] for key in pins):
        raise ValueError("render environment mismatch")
    names = sorted(name for name in baseline["sha256"] if name.endswith(".png"))
    if names != sorted(name for name in observed["sha256"] if name.endswith(".png")):
        raise ValueError("image inventory mismatch")
    for name in names:
        with Image.open(reference / name) as before, Image.open(actual / name) as after:
            if (
                before.size != after.size
                or ImageChops.difference(
                    before.convert("RGB"), after.convert("RGB")
                ).getbbox()
                is not None
            ):
                raise ValueError("nonzero pixel difference: " + name)
    return {
        "status": "passed",
        "images": len(names),
        "pixel_threshold": 0,
        "evidence_class": "local_render_approximation",
        "actual_slack": "not_run",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=Path)
    parser.add_argument("actual", type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.reference, args.actual), sort_keys=True))


if __name__ == "__main__":
    main()
