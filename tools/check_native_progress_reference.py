"""Read-only comparison against an explicitly reviewed native-zoom reference."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> dict[str, Any]:
    evidence_path = root / "evidence.json"
    if evidence_path.is_symlink() or not evidence_path.is_file():
        raise ValueError("missing regular evidence")
    evidence: dict[str, Any] = json.loads(evidence_path.read_text())
    files = evidence["sha256"]
    if not isinstance(files, dict) or not files:
        raise ValueError("empty artifact inventory")
    for name, expected in files.items():
        relative = Path(name)
        path = root / relative
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != name
        ):
            raise ValueError("unsafe artifact path")
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(root.resolve())
        ):
            raise ValueError("missing regular artifact")
        if sha(path) != expected:
            raise ValueError("artifact hash mismatch")
    present = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if present - {"evidence.json", "review.json"} != set(files):
        raise ValueError("unlisted artifact inventory")
    return evidence


def compare(reference: Path, actual: Path, review_path: Path) -> dict[str, Any]:
    from PIL import Image, ImageChops

    baseline, observed = inventory(reference), inventory(actual)
    if review_path.is_symlink() or not review_path.is_file():
        raise ValueError("missing trusted review")
    review = json.loads(review_path.read_text())
    if (
        review.get("schema") != "tether.native-zoom-review.v1"
        or review.get("disposition") != "approved_synthetic_reference"
        or type(review.get("pixel_tolerance")) is not int
        or review["pixel_tolerance"] != 0
        or review.get("evidence_sha256") != sha(reference / "evidence.json")
        or review.get("artifact_sha256") != baseline["sha256"]
    ):
        raise ValueError("reference lacks exact zero-tolerance review")
    for field in ("status", "source_sha256", "environment", "repeat_pixel_tolerance"):
        if field not in baseline or baseline[field] != observed.get(field):
            raise ValueError("source/render environment mismatch")
    if (
        type(baseline["repeat_pixel_tolerance"]) is not int
        or baseline["repeat_pixel_tolerance"] != 0
    ):
        raise ValueError("nonzero repeat tolerance")
    if set(baseline["sha256"]) != set(observed["sha256"]):
        raise ValueError("artifact inventory mismatch")
    names = sorted(name for name in baseline["sha256"] if name.endswith(".png"))
    if not names:
        raise ValueError("no reference images")
    for name in names:
        with Image.open(reference / name) as before, Image.open(actual / name) as after:
            if before.size != after.size or any(
                band.getbbox() is not None
                for band in ImageChops.difference(
                    before.convert("RGBA"), after.convert("RGBA")
                ).split()
            ):
                raise ValueError("nonzero native-reference pixel difference: " + name)
    return {
        "status": "passed",
        "images": len(names),
        "pixel_tolerance": 0,
        "evidence_class": "reviewed_native_zoom_image_comparison_only",
        "actual_slack": "not_run",
        "runtime_qualification": "not_run",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=Path)
    parser.add_argument("actual", type=Path)
    parser.add_argument("--review", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.reference, args.actual, args.review), sort_keys=True))
