"""Provisional synthetic contracts; no runtime authority or upstream compatibility."""

from __future__ import annotations

import hashlib
import json
import random
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, NoReturn

VERSION = "runspindle.fixture.v1"
MAX_BYTES = 65536
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
STATUSES = {"not-run", "passed", "failed", "blocked", "unknown"}


class ContractError(ValueError):
    pass


def reject(code: str) -> NoReturn:
    raise ContractError(code)


def load_json(path: str | Path) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        reject("size")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                reject("duplicate-key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def _keys(value: Any, required: list[str], optional: tuple[str, ...] = ()) -> None:
    if type(value) is not dict or not set(required) <= value.keys():
        reject("required-keys")
    if value.keys() - set(required) - set(optional):
        reject("unknown-key")


def _field(value: Any, rule: str) -> None:
    valid: Any
    if rule == "id":
        valid = type(value) is str and ID.fullmatch(value)
    elif rule == "digest":
        valid = type(value) is str and DIGEST.fullmatch(value)
    elif rule == "positive":
        valid = type(value) is int and 0 < value <= 2**53 - 1
    elif rule == "counter":
        valid = type(value) is int and 0 <= value <= 2**53 - 1
    elif rule == "origin":
        valid = type(value) is str and re.fullmatch(
            r"https://[a-z0-9-]+\.example", value
        )
    elif rule == "timestamp":
        valid = False
        if type(value) is str and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
        ):
            try:
                datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
                valid = True
            except ValueError:
                pass
    else:
        reject("contract-rule")
    if not valid:
        reject("field-type-or-bound")


def validate(envelope: Any, contract: Any = None) -> Any:
    """Validate syntax only. A valid envelope is never proof of an effect."""
    try:
        encoded = json.dumps(envelope, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
        reject("serialization")
    if len(encoded) > MAX_BYTES:
        reject("size")
    contract = contract or load_json(Path(__file__).with_name("contract.json"))
    _keys(
        envelope,
        [
            "schema",
            "kind",
            "identity",
            "state",
            "status",
            "observed_at",
            "evidence_class",
            "detail",
        ],
    )
    if envelope["schema"] != VERSION:
        reject("schema-version")
    kind = envelope["kind"]
    if type(kind) is not str or kind not in contract["kinds"]:
        reject("unknown-event")
    spec = contract["kinds"][kind]
    if envelope["evidence_class"] != "synthetic_fixture":
        reject("evidence-class")
    if type(envelope["status"]) is not str or envelope["status"] not in STATUSES:
        reject("status")
    if type(envelope["state"]) is not str or envelope["state"] not in spec["states"]:
        reject("state")
    if (
        envelope["state"] in ["unknown", "blocked", "not-run"]
        and envelope["status"] == "passed"
    ):
        reject("uncertainty-is-not-success")
    _field(envelope["observed_at"], "timestamp")
    identity = envelope["identity"]
    required = contract["common_identity"] + spec["identity"]
    _keys(identity, required)
    for name, value in identity.items():
        _field(value, contract["identity_fields"][name])
    _keys(envelope["detail"], spec["detail"])
    for name, rule in spec["detail"].items():
        _field(envelope["detail"][name], rule)
    return envelope


def assert_conforms(
    envelope: Any, expected_identity: Any, expected_state: Any, observations: Any = None
) -> bool:
    """Test oracle: bind to independent request/spy observations, never event flags.

    The caller supplies synthetic observations recorded outside the adapter under
    test. These are not authenticated runtime receipts or an authorization API.
    """
    validate(envelope)
    validate(dict(envelope, identity=expected_identity))
    if envelope["identity"] != expected_identity:
        reject("identity-mismatch")
    if envelope["state"] != expected_state or envelope["status"] != "passed":
        reject("outcome-mismatch")
    observations = observations or {}
    if envelope["state"] in ["delivered", "persisted", "serving"]:
        receipt = observations.get(envelope["state"])
        if receipt != {"identity": expected_identity, "detail": envelope["detail"]}:
            reject("missing-independent-receipt")
        validate(dict(envelope, identity=receipt["identity"]))
    if envelope["kind"] == "artifact.observed" and envelope["state"] == "delivered":
        if observations.get("accepted_digest") != expected_identity.get(
            "artifact_digest"
        ):
            reject("unaccepted-bytes")
    if envelope["state"] == "serving":
        if observations.get("approved_digest") != expected_identity.get(
            "candidate_digest"
        ):
            reject("unapproved-candidate")
    return True


def aggregate(statuses: Any) -> str:
    """No empty or incomplete required lane may become a successful aggregate."""
    statuses = list(statuses)
    if not statuses or any(type(s) is not str or s not in STATUSES for s in statuses):
        reject("status")
    return "passed" if all(s == "passed" for s in statuses) else "blocked"


def verify_bundle(directory: str | Path) -> Any:
    root = Path(directory).resolve()
    manifest = load_json(root / "manifest.json")
    if manifest["schema"] != VERSION:
        reject("schema-version")
    expected_files = set(manifest["files"]) | {"manifest.json"}
    actual_files = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    if actual_files != expected_files:
        reject("bundle-inventory")
    for name, digest in manifest["files"].items():
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            reject("bundle-path")
        _field(digest, "digest")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            reject("bundle-digest")
    fixtures = load_json(root / "golden.json")
    contract = load_json(root / "contract.json")
    for fixture in fixtures:
        validate(fixture, contract)
        if "artifact_digest" in fixture["identity"]:
            if (
                fixture["identity"]["artifact_digest"]
                != hashlib.sha256((root / "artifact.txt").read_bytes()).hexdigest()
            ):
                reject("artifact-digest")
    return manifest


def export_bundle(component: str, destination: str | Path) -> dict[str, Any]:
    """Export a verified, standalone component subset; destination must be new."""
    root = Path(__file__).resolve().parent
    manifest = verify_bundle(root)
    components = manifest["components"]
    if component not in components:
        reject("component")
    destination = Path(destination)
    destination.mkdir(parents=False, exist_ok=False)
    try:
        for name in ["fixturekit.py", "contract.json", "artifact.txt", "faults.json"]:
            shutil.copyfile(root / name, destination / name)
        fixtures = [
            x
            for x in load_json(root / "golden.json")
            if x["kind"] in components[component]
        ]
        (destination / "golden.json").write_text(
            json.dumps(fixtures, indent=2, sort_keys=True) + "\n"
        )
        vectors = [
            x
            for x in load_json(root / "vectors.json")
            if x["kind"] in components[component]
        ]
        (destination / "vectors.json").write_text(
            json.dumps(vectors, indent=2, sort_keys=True) + "\n"
        )
        result = {
            "schema": VERSION,
            "component": component,
            "origin_manifest_sha256": hashlib.sha256(
                (root / "manifest.json").read_bytes()
            ).hexdigest(),
            "files": {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(destination.iterdir())
            },
        }
        (destination / "manifest.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        verify_bundle(destination)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return result


def assert_fault_trace(case_id: str, trace: Any) -> bool:
    """Check independent synthetic observations, never claim durable recovery."""
    cases = load_json(Path(__file__).with_name("faults.json"))["cases"]
    case = next((row for row in cases if row["id"] == case_id), None)
    if case is None:
        reject("unknown-fault")
    _keys(
        trace,
        [
            "case",
            "classification",
            "effect_calls",
            "observation",
            "identity",
            "steps",
            "calls",
        ],
    )
    if (
        trace["case"] != case_id
        or trace["classification"] != "model_schedule_not_runtime_recovery"
    ):
        reject("fault-scope")
    _field(trace["effect_calls"], "counter")
    _keys(trace["identity"], ["task_id", "operation_id"])
    for value in trace["identity"].values():
        _field(value, "id")
    if type(trace["steps"]) is not list or type(trace["calls"]) is not list:
        reject("fault-trace")
    for step in trace["steps"]:
        _keys(step, ["input", "state", "effect_calls", "attempt", "sequence"])
        for name in ("effect_calls", "sequence"):
            _field(step[name], "counter")
        _field(step["attempt"], "positive")
    for call in trace["calls"]:
        _keys(call, ["operation", "attempt", "identity"])
        _keys(call["identity"], ["task_id", "operation_id"])
        for value in call["identity"].values():
            _field(value, "id")
        _field(call["attempt"], "positive")
    if (
        trace["steps"] != case["expected_steps"]
        or trace["calls"] != case["expected_calls"]
    ):
        reject("fault-transition-or-call-order")
    if len(trace["calls"]) != trace["effect_calls"]:
        reject("fault-call-count")
    if trace["identity"] != {
        "task_id": "synthetic-task",
        "operation_id": "synthetic-operation",
    }:
        reject("fault-identity")
    if (
        trace["effect_calls"] != case["expected_effect_calls"]
        or trace["observation"] != case["required_observation"]
    ):
        reject("fault-outcome")
    return True


class Spy:
    """Default-deny fake transport; only explicit synthetic calls are allowed."""

    def __init__(self, allowed: tuple[str, ...] | list[str] = ()) -> None:
        self.allowed = set(allowed)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, operation: str, identity: dict[str, Any]) -> None:
        self.calls.append((operation, dict(identity)))
        if operation not in self.allowed:
            reject("forbidden-call")


class Clock:
    def __init__(self, seconds: int = 0) -> None:
        self.seconds = seconds

    def advance(self, seconds: int) -> None:
        if type(seconds) is not int or seconds < 0:
            reject("clock")
        self.seconds += seconds


class Ids:
    def __init__(self, seed: int) -> None:
        self.random = random.Random(seed)

    def next(self) -> str:
        return "synthetic-" + format(self.random.getrandbits(64), "016x")


@contextmanager
def temporary_store() -> Iterator[Path]:
    """Disposable fixture directory; this helper makes no durability guarantee."""
    with tempfile.TemporaryDirectory(prefix="runspindle-fixture-") as directory:
        yield Path(directory)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "export":
            export_bundle(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 1:
            verify_bundle(Path(__file__).resolve().parent)
        else:
            reject("usage: fixturekit.py [export COMPONENT NEW_DIRECTORY]")
        print(
            json.dumps(
                {
                    "status": "passed",
                    "evidence_class": "synthetic_fixture_integrity",
                    "integration": "not-run",
                    "live_acceptance": "not-run",
                }
            )
        )
    except (ContractError, OSError, KeyError, ValueError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
