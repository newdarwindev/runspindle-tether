#!/usr/bin/env python3
"""Run manifest partitions and reject incomplete, stale, or mismatched CI receipts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import hygiene  # noqa: E402

PARTITIONS = (
    "quality",
    "component",
    "rust",
    "mutation_1",
    "mutation_2",
    "mutation_3",
    "mutation_4",
)
SHA = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")


class Stage(str, Enum):
    MANIFEST = "manifest"
    INSTANCE_METADATA = "instance_metadata"
    IMAGE_METADATA = "image_metadata"
    IMAGE_BINDING = "image_binding"
    RUST_CLOSURE = "rust_closure"
    BUILDER_ARCHIVE = "builder_archive"
    QUALITY_CLOSURE = "quality_closure"
    SOURCE_IDENTITY = "source_identity"
    RUN_IDENTITY = "run_identity"
    CHECK_EXECUTION = "check_execution"
    AGGREGATE_INPUT = "aggregate_input"
    AGGREGATE_VALIDATION = "aggregate_validation"
    RECEIPT_OUTPUT = "receipt_output"


def failure_category(error: BaseException) -> str:
    # Closed vocabulary only: no exception text, paths, metadata or dynamic names.
    if isinstance(error, json.JSONDecodeError):
        return "invalid_json"
    if isinstance(error, UnicodeError):
        return "invalid_encoding"
    if isinstance(error, FileNotFoundError):
        return "missing_file"
    if isinstance(error, PermissionError):
        return "file_access_denied"
    if isinstance(error, subprocess.CalledProcessError):
        return "command_failed"
    if isinstance(error, KeyError):
        return "missing_field"
    if isinstance(error, OSError):
        return "io_error"
    return "invalid_value"


class PartitionFailure(ValueError):
    def __init__(self, stage: Stage, error: BaseException) -> None:
        super().__init__("partition validation failed")
        self.stage = stage
        self.category = failure_category(error)


@contextmanager
def diagnostic_stage(stage: Stage) -> Iterator[None]:
    try:
        yield
    except PartitionFailure:
        raise
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise PartitionFailure(stage, error) from None


def digest(path: Path | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifests(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    root = Path(root)
    raw = (root / "validation-partitions.json").read_bytes()
    manifest = json.loads(raw)
    inventory = hygiene.validate_manifest(
        json.loads((root / "hygiene.json").read_text())
    )
    partitions = manifest.get("partitions")
    if (
        manifest.get("schema_version") != 1
        or not isinstance(partitions, dict)
        or set(partitions) != set(PARTITIONS)
    ):
        raise ValueError("invalid partition manifest")
    observed = []
    for name in PARTITIONS:
        ids = partitions[name]
        if not isinstance(ids, list) or any(not isinstance(x, str) for x in ids):
            raise ValueError("invalid partition inventory")
        observed.extend(ids)
    expected = [item["id"] for item in inventory["checks"]]
    if len(observed) != len(set(observed)) or set(observed) != set(expected):
        raise ValueError("missing or duplicate mandatory check coverage")
    image = manifest.get("image", {})
    required = (
        "sha256",
        "controller_sha256",
        "recipe_sha256",
        "tool_closure_sha256",
        "quality_closure_sha256",
        "rust_closure_sha256",
        "builder_archive_sha256",
    )
    if any(
        not isinstance(image.get(k), str) or not SHA.fullmatch(image[k])
        for k in required
    ):
        raise ValueError("incomplete qualified image pin")
    if not isinstance(image.get("source_sha"), str) or not SOURCE_SHA.fullmatch(
        image["source_sha"]
    ):
        raise ValueError("missing exact image source revision")
    return (
        manifest,
        inventory,
        hashlib.sha256(raw).hexdigest(),
        digest(root / "hygiene.json"),
    )


def validate_instance_binding(instance: dict[str, Any], image: dict[str, str]) -> None:
    expected = {
        "image_sha256": image["sha256"],
        "image_source_sha": image["source_sha"],
        "controller_sha256": image["controller_sha256"],
        "recipe_sha256": image["recipe_sha256"],
        "tool_closure_sha256": image["tool_closure_sha256"],
    }
    if any(instance.get(key) != value for key, value in expected.items()):
        raise ValueError("wrong or missing qualified image binding")


def guest_identity(image: dict[str, str]) -> dict[str, Any]:
    with diagnostic_stage(Stage.INSTANCE_METADATA):
        instance = json.loads(Path("/etc/runspindle-instance.json").read_text())
    with diagnostic_stage(Stage.IMAGE_METADATA):
        guest = json.loads(Path("/etc/runspindle-image.json").read_text())
    with diagnostic_stage(Stage.IMAGE_BINDING):
        validate_instance_binding(instance, image)
    with diagnostic_stage(Stage.RUST_CLOSURE):
        if guest.get("rust_closure_sha256") != image["rust_closure_sha256"]:
            raise ValueError("wrong Rust closure")
    with diagnostic_stage(Stage.BUILDER_ARCHIVE):
        if (
            guest.get("runtime_builder", {}).get("archive_sha256")
            != image["builder_archive_sha256"]
        ):
            raise ValueError("wrong runtime builder archive")
    with diagnostic_stage(Stage.QUALITY_CLOSURE):
        if (
            digest("/opt/runspindle-image-tools/fleet/quality-closure.json")
            != image["quality_closure_sha256"]
        ):
            raise ValueError("wrong quality closure")
    return cast(dict[str, Any], instance)


def source_sha(root: Path = ROOT) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()


def receipt(
    name: str,
    manifest: dict[str, Any],
    inventory: dict[str, Any],
    manifest_sha: str,
    hygiene_sha: str,
    instance: dict[str, Any],
    head_sha: str,
    run_id: str,
) -> dict[str, Any]:
    by_id = {item["id"]: item for item in inventory["checks"]}
    before = hygiene.source_fingerprint(ROOT)
    preflight = hygiene.preflight(ROOT, inventory) if name == "quality" else None
    checks = [
        hygiene.run_entry(ROOT, by_id[identity])
        for identity in manifest["partitions"][name]
    ]
    after = hygiene.source_fingerprint(ROOT)
    if before != after or (preflight and preflight["status"] != "passed"):
        checks.append(
            {
                "id": "partition-integrity",
                "status": "failed",
                "reason": "input_drift_or_preflight",
            }
        )
    return {
        "schema_version": 1,
        "partition": name,
        "run_id": run_id,
        "source_sha": head_sha,
        "manifest_sha256": manifest_sha,
        "hygiene_sha256": hygiene_sha,
        "image_sha256": instance["image_sha256"],
        "binding": {
            k: instance[k]
            for k in (
                "image_source_sha",
                "controller_sha256",
                "recipe_sha256",
                "tool_closure_sha256",
            )
        },
        "preflight": preflight,
        "source_fingerprint": before,
        "checks": checks,
        "status": "passed"
        if all(c["status"] in ("passed", "not_applicable") for c in checks)
        else "failed",
    }


def aggregate(
    receipts: dict[str, dict[str, Any]],
    job_results: dict[str, str],
    manifest: dict[str, Any],
    inventory: dict[str, Any],
    manifest_sha: str,
    hygiene_sha: str,
    image_sha: str,
    head_sha: str,
    run_id: str,
) -> dict[str, Any]:
    if set(receipts) != set(PARTITIONS) or set(job_results) != set(PARTITIONS):
        raise ValueError("missing partition result")
    if any(job_results[name] != "success" for name in PARTITIONS):
        raise ValueError("failed, cancelled, or skipped partition")
    by_id = {item["id"]: item for item in inventory["checks"]}
    covered = []
    fingerprints = set()
    for name in PARTITIONS:
        value = receipts[name]
        expected = {
            "schema_version": 1,
            "partition": name,
            "run_id": run_id,
            "source_sha": head_sha,
            "manifest_sha256": manifest_sha,
            "hygiene_sha256": hygiene_sha,
            "image_sha256": image_sha,
            "binding": {
                "image_source_sha": manifest["image"]["source_sha"],
                **{
                    k: manifest["image"][k]
                    for k in (
                        "controller_sha256",
                        "recipe_sha256",
                        "tool_closure_sha256",
                    )
                },
            },
        }
        if (
            any(value.get(k) != v for k, v in expected.items())
            or value.get("status") != "passed"
        ):
            raise ValueError("stale or mismatched partition receipt")
        if not isinstance(value.get("source_fingerprint"), str) or not SHA.fullmatch(
            value["source_fingerprint"]
        ):
            raise ValueError("source fingerprint missing")
        fingerprints.add(value["source_fingerprint"])
        preflight = value.get("preflight")
        if name == "quality":
            if (
                not isinstance(preflight, dict)
                or preflight.get("id") != "reproducible-inputs"
                or preflight.get("status") != "passed"
                or preflight.get("problems") != []
            ):
                raise ValueError("reproducible inputs preflight missing")
        elif preflight is not None:
            raise ValueError("unexpected preflight receipt")
        checks = value.get("checks")
        if (
            not isinstance(checks, list)
            or [c.get("id") for c in checks] != manifest["partitions"][name]
        ):
            raise ValueError("partition check coverage mismatch")
        for check in checks:
            entry = by_id[check["id"]]
            if "not_applicable" in entry:
                if (
                    check.get("status") != "not_applicable"
                    or check.get("reason") != entry["not_applicable"]
                ):
                    raise ValueError("invalid N/A check receipt")
            else:
                command_sha = hashlib.sha256(
                    json.dumps(entry["command"]).encode()
                ).hexdigest()
                if (
                    check.get("status") != "passed"
                    or check.get("exit_code") != 0
                    or check.get("command_sha256") != command_sha
                ):
                    raise ValueError("failed or forged mandatory check receipt")
            covered.append(check["id"])
    if len(covered) != len(set(covered)) or set(covered) != set(by_id):
        raise ValueError("missing or duplicate mandatory check")
    if len(fingerprints) != 1:
        raise ValueError("partition source bytes differ")
    return {
        "status": "passed",
        "source_sha": head_sha,
        "image_sha256": image_sha,
        "manifest_sha256": manifest_sha,
        "checks": len(covered),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=(*PARTITIONS, "aggregate"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with diagnostic_stage(Stage.MANIFEST):
        manifest, inventory, manifest_sha, hygiene_sha = manifests()
    instance = guest_identity(manifest["image"])
    image_sha = cast(str, instance["image_sha256"])
    with diagnostic_stage(Stage.SOURCE_IDENTITY):
        head_sha = source_sha()
    with diagnostic_stage(Stage.RUN_IDENTITY):
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        if os.environ.get("GITHUB_SHA") != head_sha or not run_id.isdecimal():
            raise ValueError("missing or mismatched GitHub run source identity")
    if args.action == "aggregate":
        with diagnostic_stage(Stage.AGGREGATE_INPUT):
            receipts = {}
            results = {}
            for name in PARTITIONS:
                encoded = os.environ.get("RECEIPT_" + name.upper(), "")
                results[name] = os.environ.get("RESULT_" + name.upper(), "")
                if not encoded or len(encoded) > 100000:
                    raise ValueError("missing or oversized partition receipt")
                receipts[name] = json.loads(base64.b64decode(encoded, validate=True))
        with diagnostic_stage(Stage.AGGREGATE_VALIDATION):
            print(
                json.dumps(
                    aggregate(
                        receipts,
                        results,
                        manifest,
                        inventory,
                        manifest_sha,
                        hygiene_sha,
                        image_sha,
                        head_sha,
                        run_id,
                    ),
                    sort_keys=True,
                )
            )
        return 0
    with diagnostic_stage(Stage.CHECK_EXECUTION):
        value = receipt(
            args.action,
            manifest,
            inventory,
            manifest_sha,
            hygiene_sha,
            instance,
            head_sha,
            run_id,
        )
    with diagnostic_stage(Stage.RECEIPT_OUTPUT):
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        if args.output:
            with args.output.open("a") as stream:
                stream.write("receipt=" + encoded + "\n")
        else:
            print(json.dumps(value, sort_keys=True))
    if value["status"] != "passed":
        for line in hygiene.failure_summary({"checks": value["checks"]}):
            print(line, flush=True)
    return 0 if value["status"] == "passed" else 1


def failure_record(error: BaseException) -> dict[str, str]:
    # Validate again at the final output boundary. Exception attributes are
    # mutable and must not be treated as already-sanitized diagnostic evidence.
    result = {
        "status": "failed",
        "reason": "validation_error",
        "stage": "unclassified",
        "category": "unclassified",
    }
    if type(error) is not PartitionFailure:
        return result
    attributes = object.__getattribute__(error, "__dict__")
    if type(attributes) is not dict:
        return result
    stage, category = attributes.get("stage"), attributes.get("category")
    stages = {
        Stage.MANIFEST: "manifest",
        Stage.INSTANCE_METADATA: "instance_metadata",
        Stage.IMAGE_METADATA: "image_metadata",
        Stage.IMAGE_BINDING: "image_binding",
        Stage.RUST_CLOSURE: "rust_closure",
        Stage.BUILDER_ARCHIVE: "builder_archive",
        Stage.QUALITY_CLOSURE: "quality_closure",
        Stage.SOURCE_IDENTITY: "source_identity",
        Stage.RUN_IDENTITY: "run_identity",
        Stage.CHECK_EXECUTION: "check_execution",
        Stage.AGGREGATE_INPUT: "aggregate_input",
        Stage.AGGREGATE_VALIDATION: "aggregate_validation",
        Stage.RECEIPT_OUTPUT: "receipt_output",
    }
    categories = {
        "invalid_json",
        "invalid_encoding",
        "missing_file",
        "file_access_denied",
        "command_failed",
        "missing_field",
        "io_error",
        "invalid_value",
    }
    if (
        type(stage) is not Stage
        or type(category) is not str
        or category not in categories
    ):
        return result
    # Do not read stage.value: even an enum member's attribute can be mutated.
    stage_name = next(
        (name for member, name in stages.items() if stage is member), None
    )
    if stage_name is None:
        return result
    result.update(stage=stage_name, category=category)
    return result


def cli() -> int:
    try:
        return main()
    except PartitionFailure as error:
        print(json.dumps(failure_record(error)))
        return 2
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        # Unexpected caught failures remain failures, with no unbounded detail.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason": "validation_error",
                    "stage": "unclassified",
                    "category": "unclassified",
                }
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(cli())
