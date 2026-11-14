"""Synthetic transport semantics; independent store observations, no providers."""

import importlib.util
import itertools
import socket
import sys
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import patch

from tests.test_admission import authenticate, event, grant, proof
from tether.admission import Admission, Rejected, canonical
from tether.testing import (
    Attachment,
    Destination,
    FakeSlack,
    Fault,
    Payload,
    Record,
    confirm_readback,
)

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = Destination("workspace-1", "channel-1", "thread-1")
PAYLOAD = Payload(
    "Synthetic public final output",
    (Attachment("artifact-1", "example.txt", b"synthetic artifact"),),
)


class FakeTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        ids = itertools.count(1)
        self.now = 100
        self.transport = FakeSlack(
            DESTINATION, lambda: self.now, lambda: f"message-{next(ids)}"
        )
        self.network = patch.object(
            socket.socket,
            "connect",
            side_effect=AssertionError("unexpected outbound network"),
        )
        self.connect = self.network.start()
        self.addCleanup(self.network.stop)

    def tearDown(self) -> None:
        self.connect.assert_not_called()

    def test_send_is_only_accepted_until_exact_independent_readback(self) -> None:
        reply = self.transport.send(DESTINATION, "send-1", PAYLOAD)
        self.assertEqual(reply.state, "accepted")
        self.assertEqual(reply.evidence_class, "synthetic")
        self.assertEqual(len(self.transport.records), 1)
        row = self.transport.records["message-1"]
        self.assertEqual(row.payload, PAYLOAD)
        confirmed = confirm_readback(
            self.transport.readback(DESTINATION, "send-1"),
            DESTINATION,
            "send-1",
            PAYLOAD,
        )
        self.assertEqual(confirmed.state, "destination_confirmed")
        self.assertEqual(confirmed.message_id, "message-1")
        self.assertEqual(self.transport.requests[0].payload_digest, PAYLOAD.digest())

    def test_lost_ack_reconciles_without_retry_or_second_effect(self) -> None:
        self.transport.inject("send", Fault.LOST_ACK)
        reply = self.transport.send(DESTINATION, "send-1", PAYLOAD)
        self.assertEqual(reply.state, "unknown")
        self.assertIsNone(reply.message_id)
        confirmed = confirm_readback(
            self.transport.readback(DESTINATION, "send-1"),
            DESTINATION,
            "send-1",
            PAYLOAD,
        )
        self.assertEqual(confirmed.state, "destination_confirmed")
        self.assertEqual(
            [r.action for r in self.transport.requests], ["send", "readback"]
        )
        self.assertEqual(list(self.transport.records), ["message-1"])

    def test_fake_deliberately_does_not_hide_duplicate_send_bugs(self) -> None:
        self.transport.send(DESTINATION, "send-1", PAYLOAD)
        self.transport.send(DESTINATION, "send-1", PAYLOAD)
        self.assertEqual(len(self.transport.records), 2)
        self.assertEqual(
            confirm_readback(
                self.transport.readback(DESTINATION, "send-1"),
                DESTINATION,
                "send-1",
                PAYLOAD,
            ).state,
            "unknown",
        )

    def test_update_and_delete_readback_preserve_message_identity(self) -> None:
        self.transport.send(DESTINATION, "send-1", PAYLOAD)
        updated = Payload("Synthetic edited output")
        self.transport.inject("update", Fault.LOST_ACK)
        self.assertEqual(
            self.transport.update(DESTINATION, "edit-1", "message-1", updated).state,
            "unknown",
        )
        self.assertEqual(
            confirm_readback(
                self.transport.readback(DESTINATION, "edit-1"),
                DESTINATION,
                "edit-1",
                updated,
                "message-1",
            ).state,
            "destination_confirmed",
        )
        self.transport.inject("delete", Fault.LOST_ACK)
        self.assertEqual(
            self.transport.delete(DESTINATION, "delete-1", "message-1").state, "unknown"
        )
        self.assertEqual(
            confirm_readback(
                self.transport.readback(DESTINATION, "delete-1"),
                DESTINATION,
                "delete-1",
                None,
                "message-1",
            ).state,
            "destination_confirmed",
        )
        self.assertTrue(self.transport.records["message-1"].deleted)
        self.assertIsNone(self.transport.records["message-1"].payload)
        self.assertEqual(
            self.transport.update(DESTINATION, "late-edit", "message-1", PAYLOAD).state,
            "failed",
        )
        self.assertEqual(len(self.transport.records), 1)

    def test_wrong_scope_has_no_destination_effect_and_does_not_consume_fault(
        self,
    ) -> None:
        self.transport.send(DESTINATION, "send-1", PAYLOAD)
        self.transport.inject("send", Fault.BEFORE_EFFECT)
        before = dict(self.transport.records)
        for field in ("workspace_id", "channel_id", "thread_id"):
            wrong = replace(DESTINATION, **{field: "wrong"})
            operations: tuple[Callable[[], object], ...] = (
                lambda: self.transport.send(wrong, "wrong-send", PAYLOAD),
                lambda: self.transport.update(
                    wrong, "wrong-update", "message-1", PAYLOAD
                ),
                lambda: self.transport.delete(wrong, "wrong-delete", "message-1"),
                lambda: self.transport.readback(wrong, "wrong-read"),
            )
            for operation in operations:
                with self.assertRaises(ValueError):
                    operation()
                self.assertEqual(self.transport.records, before)
        self.assertEqual(
            self.transport.send(DESTINATION, "send-2", PAYLOAD).state, "failed"
        )
        self.assertEqual(self.transport.records, before)

    def test_rate_limit_and_before_effect_fault_do_not_send_or_retry(self) -> None:
        self.transport.inject("send", Fault.RATE_LIMIT)
        reply = self.transport.send(DESTINATION, "send-1", PAYLOAD)
        self.assertEqual((reply.state, reply.retry_at), ("rate_limited", 103))
        self.assertEqual(self.transport.records, {})
        self.assertEqual(len(self.transport.requests), 1)
        self.now = 103
        self.transport.inject("send", Fault.BEFORE_EFFECT)
        self.assertEqual(
            self.transport.send(DESTINATION, "send-1", PAYLOAD).state, "failed"
        )
        self.assertEqual(self.transport.records, {})
        self.assertEqual(
            self.transport.send(DESTINATION, "send-1", PAYLOAD).state, "accepted"
        )
        self.assertEqual(len(self.transport.records), 1)

    def test_partial_attachment_and_malformed_ack_remain_uncertain(self) -> None:
        self.transport.inject("send", Fault.PARTIAL_ATTACHMENTS)
        self.assertEqual(
            self.transport.send(DESTINATION, "send-1", PAYLOAD).state, "accepted"
        )
        self.assertEqual(
            confirm_readback(
                self.transport.readback(DESTINATION, "send-1"),
                DESTINATION,
                "send-1",
                PAYLOAD,
            ).state,
            "unknown",
        )
        self.assertEqual(
            self.transport.records["message-1"].payload, Payload(PAYLOAD.text)
        )
        self.transport.inject("send", Fault.MALFORMED)
        self.assertEqual(
            self.transport.send(DESTINATION, "send-2", PAYLOAD).state, "unknown"
        )
        self.assertEqual(len(self.transport.records), 2)

    def test_absent_ambiguous_malformed_and_wrong_thread_readbacks(self) -> None:
        self.transport.send(DESTINATION, "send-1", PAYLOAD)
        for fault in (
            Fault.MISSING,
            Fault.AMBIGUOUS,
            Fault.MALFORMED,
            Fault.WRONG_THREAD,
        ):
            before = dict(self.transport.records)
            self.transport.inject("readback", fault)
            self.assertEqual(
                confirm_readback(
                    self.transport.readback(DESTINATION, "send-1"),
                    DESTINATION,
                    "send-1",
                    PAYLOAD,
                ).state,
                "unknown",
            )
            self.assertEqual(self.transport.records, before)

    def test_wrong_thread_fault_cannot_collide_with_intended_thread(self) -> None:
        for thread_id in ("wrong-thread", "wrong-thread-2", "x" * 128):
            destination = replace(DESTINATION, thread_id=thread_id)
            transport = FakeSlack(destination, lambda: 0, lambda: "message-1")
            transport.send(destination, "send-1", PAYLOAD)
            transport.inject("readback", Fault.WRONG_THREAD)
            rows = transport.readback(destination, "send-1")
            if not isinstance(rows, tuple) or len(rows) != 1:
                self.fail("fault must return one mismatched record")
            observed = rows[0]
            self.assertIsInstance(observed, Record)
            observed.destination.validate()
            self.assertNotEqual(observed.destination.thread_id, thread_id)
            self.assertEqual(
                confirm_readback(rows, destination, "send-1", PAYLOAD).state,
                "unknown",
            )
            self.assertEqual(transport.records["message-1"].destination, destination)

    def test_partial_attachment_fault_rejects_inapplicable_empty_payload(self) -> None:
        self.transport.inject("send", Fault.PARTIAL_ATTACHMENTS)
        with self.assertRaises(ValueError):
            self.transport.send(DESTINATION, "send-1", Payload("synthetic"))
        self.assertEqual(self.transport.records, {})

    def test_conflicting_receipts_compare_bytes_metadata_and_all_identities(
        self,
    ) -> None:
        row = Record(DESTINATION, "send-1", "message-1", PAYLOAD, False)
        attachment = PAYLOAD.attachments[0]
        altered_payloads = [
            replace(PAYLOAD, text="changed"),
            replace(
                PAYLOAD, attachments=(replace(attachment, content=b"different bytes"),)
            ),
            replace(
                PAYLOAD, attachments=(replace(attachment, filename="different.txt"),)
            ),
        ]
        conflicts = [replace(row, payload=p) for p in altered_payloads]
        conflicts += [
            replace(row, operation_id="wrong"),
            replace(row, message_id="wrong"),
            replace(row, deleted=True),
            replace(row, evidence_class="live"),
        ]
        conflicts.append(replace(row, message_id="invalid id"))
        for conflict in conflicts:
            self.assertEqual(
                confirm_readback(
                    (conflict,), DESTINATION, "send-1", PAYLOAD, "message-1"
                ).state,
                "unknown",
            )

    def test_limits_and_id_collision_fail_before_effect(self) -> None:
        transport = FakeSlack(DESTINATION, lambda: 0, lambda: "same", limit=2)
        transport.send(DESTINATION, "send-1", PAYLOAD)
        before = dict(transport.records)
        with self.assertRaises(ValueError):
            transport.send(DESTINATION, "send-2", PAYLOAD)
        with self.assertRaises(ValueError):
            transport.readback(DESTINATION, "send-1")
        self.assertEqual(transport.records, before)
        with self.assertRaises(ValueError):
            self.transport.send(DESTINATION, "invalid", cast(Payload, None))
        for payload in (
            Payload("x" * 1048577),
            Payload("synthetic", PAYLOAD.attachments * 2),
        ):
            with self.assertRaises(ValueError):
                self.transport.send(DESTINATION, "invalid", payload)
        self.assertEqual(self.transport.records, {})

    def test_confirmed_fake_mirror_cannot_reenter_existing_admission(self) -> None:
        self.transport.send(DESTINATION, "send-1", PAYLOAD)
        receipt = confirm_readback(
            self.transport.readback(DESTINATION, "send-1"),
            DESTINATION,
            "send-1",
            PAYLOAD,
        )
        self.assertEqual(receipt.message_id, "message-1")
        with tempfile.TemporaryDirectory() as tmp:
            app = Admission(
                str(Path(tmp) / "admission.db"), authenticate, lambda *_: grant(event())
            )
            try:
                app.record_mirror(
                    DESTINATION.workspace_id,
                    DESTINATION.channel_id,
                    DESTINATION.thread_id,
                    "message-1",
                )
                raw = canonical(event())
                with self.assertRaises(Rejected):
                    app.ingest(raw, proof(raw))
                self.assertEqual(app.envelopes(), [])
                self.assertEqual(len(self.transport.records), 1)
            finally:
                app.close()

    def test_wrong_thread_mutation_exposes_false_confirmation(self) -> None:
        source = (ROOT / "tether/testing.py").read_text()
        needle = "or row.destination != destination"
        self.assertEqual(source.count(needle), 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mutant.py"
            path.write_text(source.replace(needle, "or False  # deliberate mutation"))
            spec = importlib.util.spec_from_file_location("transport_mutant", path)
            if spec is None or spec.loader is None:
                raise RuntimeError("mutation loader unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            try:
                spec.loader.exec_module(module)
                wanted = module.Destination("workspace-1", "channel-1", "thread-1")
                wrong = module.Destination("workspace-1", "channel-1", "other-thread")
                payload = module.Payload("synthetic")
                row = module.Record(wrong, "send-1", "message-1", payload, False)
                result = module.confirm_readback((row,), wanted, "send-1", payload)
                self.assertEqual(result.state, "destination_confirmed")
                self.assertNotEqual(
                    row.destination,
                    wanted,
                    "independent observed destination must contradict mutation",
                )
            finally:
                sys.modules.pop(spec.name, None)
