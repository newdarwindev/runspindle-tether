"""Pinned synthetic fixture upgrade; no runtime/integration qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "fixtures/shared-v1"
pin_raw = (ROOT / "fixtures/shared-v1.pin.json").read_bytes()
if (
    hashlib.sha256(pin_raw).hexdigest()
    != "9c924c346608c3361cb158567539b9ec397aefd0ae580518a6cfc643a6291369"
):
    raise RuntimeError("unreviewed fixture pin")
pin = json.loads(pin_raw)
raw = (BUNDLE / "manifest.json").read_bytes()
if hashlib.sha256(raw).hexdigest() != pin["subset_manifest_sha256"]:
    raise RuntimeError("unverified fixture manifest")
manifest = json.loads(raw)
raw = (BUNDLE / "fixturekit.py").read_bytes()
if hashlib.sha256(raw).hexdigest() != manifest["files"]["fixturekit.py"]:
    raise RuntimeError("unverified fixture source")
kit: Any = types.ModuleType("verified_upgrade_fixturekit")
kit.__file__ = str(BUNDLE / "fixturekit.py")
with (
    patch("socket.socket", side_effect=AssertionError("forbidden import network")),
    patch(
        "socket.create_connection",
        side_effect=AssertionError("forbidden import network"),
    ),
    patch("socket.getaddrinfo", side_effect=AssertionError("forbidden import network")),
    patch("subprocess.Popen", side_effect=AssertionError("forbidden import process")),
):
    exec(compile(raw, kit.__file__, "exec"), kit.__dict__)
    kit.verify_bundle(BUNDLE)


class FixtureUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        for target in (
            "socket.socket",
            "socket.create_connection",
            "socket.getaddrinfo",
        ):
            guard = patch(target, side_effect=AssertionError("forbidden network"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_malformed_expected_and_receipt_identity_rejected(self) -> None:
        for item in kit.load_json(BUNDLE / "golden.json"):
            identity = copy.deepcopy(item["identity"])
            observations = {
                item["state"]: {
                    "identity": copy.deepcopy(identity),
                    "detail": item["detail"],
                },
                "accepted_digest": identity.get("artifact_digest"),
                "approved_digest": identity.get("candidate_digest"),
            }
            identity["intent_revision"] = float(identity["intent_revision"])
            with self.assertRaises(kit.ContractError):
                kit.assert_conforms(item, identity, item["state"], observations)
            if item["state"] in ("delivered", "persisted", "serving"):
                observations[item["state"]]["identity"]["sequence"] = float(
                    item["identity"]["sequence"]
                )
                with self.assertRaises(kit.ContractError):
                    kit.assert_conforms(
                        item, item["identity"], item["state"], observations
                    )

    def test_fault_traces_from_separate_model_effect_spy(self) -> None:
        # Executes a deliberately small in-memory model. No durable recovery claim.
        cases = kit.load_json(BUNDLE / "faults.json")["cases"]
        labels = {
            "duplicate": "same-task-and-operation",
            "reorder": "older-observation-cannot-replace-newer",
            "timeout": "unknown-no-blind-retry",
            "partial-response": "unknown-no-delivered-state",
            "retry": "new-attempt-same-operation",
            "restart": "blocked-until-real-durable-adapter",
            "uncertain-effect": "unknown-no-resubmit",
        }
        for case in cases:
            for defect in (
                None,
                "extra-effect",
                "wrong-order",
                "regress-sequence",
                "unauthorized-retry",
                "wrong-effect-identity",
            ):
                spy = kit.Spy(["send", "commit"])
                identity = {
                    "task_id": "synthetic-task",
                    "operation_id": "synthetic-operation",
                }
                calls: list[dict[str, Any]] = []
                steps: list[dict[str, Any]] = []
                state, attempt, sequence = "new", 1, 0
                seen: set[str] = set()

                def effect(operation: str) -> None:
                    actual_identity = (
                        {**identity, "operation_id": "wrong-operation"}
                        if defect == "wrong-effect-identity"
                        else identity
                    )
                    spy.call(operation, actual_identity)
                    observed_operation, observed_identity = spy.calls[-1]
                    calls.append(
                        {
                            "operation": observed_operation,
                            "attempt": attempt,
                            "identity": observed_identity,
                        }
                    )

                for instruction in case["schedule"]:
                    if instruction.startswith("deliver:"):
                        if instruction not in seen or defect == "extra-effect":
                            effect("send")
                            seen.add(instruction)
                        state = "admitted"
                    elif instruction.startswith("sequence:"):
                        value = int(instruction.split(":")[1])
                        sequence = (
                            value
                            if defect == "regress-sequence"
                            else max(sequence, value)
                        )
                        state = "observed"
                    elif instruction == "send":
                        effect("send")
                        state = "sent"
                    elif instruction == "explicit-rejection":
                        state = "rejected"
                        if defect == "unauthorized-retry":
                            effect("send")
                    elif instruction == "retry-authorized":
                        self.assertEqual(state, "rejected")
                        attempt += 1
                        effect("send")
                        state = "sent"
                    elif instruction == "commit":
                        effect("commit")
                        state = "committed"
                    elif instruction == "stop":
                        state = "stopped"
                    elif instruction == "fresh-process-read":
                        state = "blocked"  # Model has no durable recovery adapter.
                    else:
                        state = "unknown"
                    steps.append(
                        {
                            "input": instruction,
                            "state": state,
                            "effect_calls": len(spy.calls),
                            "attempt": attempt,
                            "sequence": sequence,
                        }
                    )
                order_changed = steps != list(reversed(steps))
                if defect == "wrong-order":
                    steps.reverse()
                trace: dict[str, Any] = {
                    "case": case["id"],
                    "classification": "model_schedule_not_runtime_recovery",
                    "effect_calls": len(spy.calls),
                    "observation": labels[case["id"]],
                    "identity": identity,
                    "steps": steps,
                    "calls": calls,
                }
                relevant = (
                    (defect == "wrong-effect-identity" and bool(calls))
                    or (defect == "wrong-order" and order_changed)
                    or (
                        defect,
                        case["id"],
                    )
                    in {
                        ("extra-effect", "duplicate"),
                        ("regress-sequence", "reorder"),
                        ("unauthorized-retry", "retry"),
                    }
                )
                if relevant:
                    with self.assertRaises(kit.ContractError):
                        kit.assert_fault_trace(case["id"], trace)
                else:
                    self.assertTrue(kit.assert_fault_trace(case["id"], trace))
                    for field, malformed in (
                        ("effect_calls", True),
                        ("classification", "runtime_passed"),
                    ):
                        with self.assertRaises(kit.ContractError):
                            kit.assert_fault_trace(
                                case["id"], {**trace, field: malformed}
                            )
                    wrong = copy.deepcopy(trace)
                    wrong["identity"]["operation_id"] = "other-operation"
                    with self.assertRaises(kit.ContractError):
                        kit.assert_fault_trace(case["id"], wrong)
