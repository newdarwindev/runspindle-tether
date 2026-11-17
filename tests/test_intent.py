"""Independent semantic projection expectations; no provider or issuer is invoked."""

import copy
import hashlib
import json
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

from tether.admission import Rejected, canonical
from tether.intent import build_intent, decode_intent, expected_task_id


def event(
    revision: int = 1, kind: str = "create", text: str = "synthetic café"
) -> dict[str, Any]:
    return {
        "version": "runspindle.tether.ingress.v1",
        "event_id": f"Ev{revision}",
        "message_id": "1700000000.000001",
        "actor_id": "Utest",
        "workspace_id": "Wtest",
        "channel_id": "Ctest",
        "thread_id": "1700000000.000000",
        "revision": revision,
        "kind": kind,
        "text": text,
        "mirrored": False,
    }


def options(revision: int = 1) -> dict[str, Any]:
    return dict(
        app_id="Atest",
        account_id="acct-test",
        delivery_namespace="slack-test",
        delivery_operation_id=f"delivery-{revision}",
        grant_ref=f"v3-grant-{revision}",
        binding=dict(
            task_id="tether-task:"
            + hashlib.sha256(
                b'["Atest","acct-test","Wtest","Ctest","1700000000.000000","1700000000.000001"]'
            ).hexdigest(),
            revision=revision,
            operation_id=f"operation-{revision}",
            policy_revision="policy-1",
            host_id="host-test",
            workspace_id="Wtest",
            lease_epoch=1,
        ),
    )


def produce(
    revision: int = 1,
    kind: str = "create",
    text: str = "synthetic café",
    previous: bytes | None = None,
) -> bytes:
    return build_intent(
        canonical(event(revision, kind, text)),
        **options(revision),
        previous_wire=previous,
    )


def independent_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


class IntentTest(unittest.TestCase):
    def test_independent_create_vector_no_effects(self) -> None:
        with (
            patch("socket.socket", side_effect=AssertionError("forbidden network")),
            patch("sqlite3.connect", side_effect=AssertionError("forbidden store")),
        ):
            raw = produce()
        obj = json.loads(raw)
        source = {
            "app_id": "Atest",
            "account_id": "acct-test",
            "actor_id": "Utest",
            "workspace_id": "Wtest",
            "channel_id": "Ctest",
            "thread_id": "1700000000.000000",
            "message_id": "1700000000.000001",
        }
        semantic = dict(
            event_id="Ev1",
            source=source,
            revision=1,
            kind="create",
            content_sha256=hashlib.sha256("synthetic café".encode()).hexdigest(),
            previous=None,
        )
        expected = {
            "version": "runspindle.intent-admission.v1",
            "event": semantic,
            "scoped": {
                "version": "runspindle.scoped-admission.v1",
                "request": {
                    "version": "runspindle.envelope.v1",
                    "message_type": "admission_request",
                    "message_id": "Ev1",
                    "binding": options()["binding"],
                    "payload": {
                        "delivery_namespace": "slack-test",
                        "delivery_id": "Ev1",
                        "predecessor_revision": None,
                        "normalized_digest": hashlib.sha256(
                            independent_bytes(semantic)
                        ).hexdigest(),
                        "grant_ref": "v3-grant-1",
                    },
                },
                "destination": {
                    "account_id": "acct-test",
                    "destination_id": "tether:"
                    + hashlib.sha256(
                        b'["Atest","acct-test","Wtest","Ctest","1700000000.000000"]'
                    ).hexdigest(),
                    "delivery_operation_id": "delivery-1",
                },
            },
        }
        self.assertEqual(raw, independent_bytes(expected))
        self.assertEqual(decode_intent(raw), obj)
        self.assertNotIn(b"synthetic", raw)
        self.assertNotIn("text", obj["event"])

    def test_edit_delete_chain(self) -> None:
        first = produce()
        second = produce(2, "edit", "replacement", first)
        third = produce(3, "delete", "", second)
        for raw, previous in ((second, first), (third, second)):
            obj = json.loads(raw)
            self.assertEqual(
                obj["event"]["previous"]["wire_sha256"],
                hashlib.sha256(previous).hexdigest(),
            )
            self.assertEqual(
                obj["event"]["previous"]["request"],
                json.loads(previous)["scoped"]["request"],
            )
        self.assertEqual(
            json.loads(third)["event"]["content_sha256"],
            hashlib.sha256(b"").hexdigest(),
        )
        with self.assertRaises(Rejected):
            produce(4, "edit", "resurrect", third)

    def test_no_mutation_of_caller_binding(self) -> None:
        args = options()
        before = copy.deepcopy(args)
        build_intent(canonical(event()), **args)
        self.assertEqual(args, before)

    def test_wrong_source_prior(self) -> None:
        first = produce()
        for key in (
            "actor_id",
            "workspace_id",
            "channel_id",
            "thread_id",
            "message_id",
        ):
            e = event(2, "edit")
            e[key] = "different"
            with self.subTest(key=key), self.assertRaises(Rejected):
                build_intent(canonical(e), **options(2), previous_wire=first)
        for key in ("app_id", "account_id"):
            args = options(2)
            args[key] = "different"
            with self.subTest(key=key), self.assertRaises(Rejected):
                build_intent(canonical(event(2, "edit")), **args, previous_wire=first)

    def test_order_task_operation_and_destination(self) -> None:
        first = produce()
        for key, value in (
            ("task_id", "other"),
            ("operation_id", "operation-1"),
            ("revision", 3),
            ("workspace_id", "other"),
            ("lease_epoch", True),
        ):
            args = options(2)
            args["binding"][key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                build_intent(canonical(event(2, "edit")), **args, previous_wire=first)
        with self.assertRaises(Rejected):
            produce(2, "edit")
        with self.assertRaises(Rejected):
            produce(previous=first)
        args = options()
        args["delivery_operation_id"] = "operation-1"
        with self.assertRaises(Rejected):
            build_intent(canonical(event()), **args)

    def test_mirror_and_delete_content(self) -> None:
        e = event()
        e["mirrored"] = True
        with self.assertRaises(Rejected):
            build_intent(canonical(e), **options())
        with self.assertRaises(Rejected):
            produce(2, "delete", "not empty", produce())

    def test_strict_nested_fields_and_bindings(self) -> None:
        base = json.loads(produce())
        paths = [
            (),
            ("event",),
            ("event", "source"),
            ("scoped",),
            ("scoped", "request"),
            ("scoped", "request", "payload"),
            ("scoped", "request", "binding"),
            ("scoped", "destination"),
        ]
        for path in paths:
            modified = copy.deepcopy(base)
            target = modified
            for key in path:
                target = target[key]
            target["unknown"] = True
            with self.subTest(path=path), self.assertRaises(Rejected):
                decode_intent(canonical(modified))
        for path, value in [
            (("event", "revision"), True),
            (("event", "content_sha256"), "A" * 64),
            (("scoped", "request", "message_id"), "wrong"),
            (("scoped", "destination", "account_id"), "wrong"),
            (("scoped", "destination", "destination_id"), "wrong"),
        ]:
            modified = copy.deepcopy(base)
            target = modified
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(Rejected):
                decode_intent(canonical(modified))

    def test_noncanonical_duplicate_and_limits(self) -> None:
        raw = produce()
        for bad in (
            b" " + raw,
            raw.replace(b'{"event":', b'{"version":"duplicate","event":', 1),
            b"[]",
            b"null",
            b"\xff",
            b"x" * 1_048_577,
            b'{"x":NaN}',
        ):
            with self.subTest(bad=bad[:40]), self.assertRaises(Rejected):
                decode_intent(bad)
        for key in ("revision", "lease_epoch"):
            args = options()
            args["binding"][key] = 2**64
            with self.assertRaises(Rejected):
                build_intent(canonical(event()), **args)

    def test_legacy_grant_is_not_an_input(self) -> None:
        with self.assertRaises(TypeError):
            build_intent(canonical(event()), **{**options(), "grant": object()})

    def test_source_owned_task_identity_excludes_actor(self) -> None:
        raw = produce()
        source = json.loads(raw)["event"]["source"]
        expected = (
            "tether-task:"
            + hashlib.sha256(
                b'["Atest","acct-test","Wtest","Ctest","1700000000.000000","1700000000.000001"]'
            ).hexdigest()
        )
        self.assertEqual(expected_task_id(source), expected)
        changed_actor = dict(source, actor_id="Uother")
        self.assertEqual(expected_task_id(changed_actor), expected)
        for key in (
            "app_id",
            "account_id",
            "workspace_id",
            "channel_id",
            "thread_id",
            "message_id",
        ):
            self.assertNotEqual(
                expected_task_id(dict(source, **{key: "other"})), expected
            )
        for task in ("arbitrary-task", "tether-task:" + "0" * 64):
            args = options()
            args["binding"]["task_id"] = task
            with self.assertRaises(Rejected):
                build_intent(canonical(event()), **args)
            value = json.loads(raw)
            value["scoped"]["request"]["binding"]["task_id"] = task
            with self.assertRaises(Rejected):
                decode_intent(independent_bytes(value))
        # A different actor cannot address a parallel workflow for this source.
        altered = event()
        altered["actor_id"] = "Uother"
        candidate = build_intent(canonical(altered), **options())
        self.assertEqual(
            json.loads(candidate)["scoped"]["request"]["binding"]["task_id"], expected
        )
        # This is only addressing; Core must reject changed actor against its history.

    def test_pinned_independent_vectors(self) -> None:
        path = (
            Path(__file__).resolve().parents[1] / "conformance/intent-v1/vectors.json"
        )
        fixture = json.loads(path.read_text())
        previous = None
        for revision, row in enumerate(fixture["vectors"], 1):
            text = ("synthetic café", "replacement", "")[revision - 1]
            raw = produce(revision, row["name"], text, previous)
            self.assertEqual(raw, independent_bytes(row["wire"]))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["wire_sha256"])
            self.assertEqual(
                hashlib.sha256(independent_bytes(row["wire"]["event"])).hexdigest(),
                row["semantic_sha256"],
            )
            previous = raw

    def test_task_guard_mutant_fails_independent_regression(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "tether/intent.py").read_text()
        old = 'or binding["task_id"] != expected_task_id(source)'
        self.assertEqual(source.count(old), 1)
        module = ModuleType("intent_task_mutant")
        exec(
            compile(source.replace(old, "or False", 1), "intent_task_mutant", "exec"),
            module.__dict__,
        )
        with patch.dict(
            globals(),
            build_intent=module.build_intent,
            decode_intent=module.decode_intent,
        ):
            result = unittest.TestResult()
            IntentTest("test_source_owned_task_identity_excludes_actor").run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertTrue(
            result.failures, "task identity guard mutant escaped regression"
        )

    def test_guard_mutant_fails_independent_regression(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "tether/intent.py").read_text()
        old = 'if event["mirrored"]:'
        self.assertEqual(source.count(old), 1)
        module = ModuleType("intent_mutant")
        exec(
            compile(source.replace(old, "if False:", 1), "intent_mutant", "exec"),
            module.__dict__,
        )
        with patch.dict(globals(), build_intent=module.build_intent):
            result = unittest.TestResult()
            IntentTest("test_mirror_and_delete_content").run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertTrue(result.failures, "mirror-removal mutant escaped regression")


if __name__ == "__main__":
    unittest.main()
