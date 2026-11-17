"""Offline composition tests. Fake destination survives journal reopen independently."""

import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tether.campaign_testing import OfflineCampaign
from tether.native_testing import Binding, Event, Mode, NativeSource
from tether.sanitization import Sanitizer
from tether.testing import Attachment, Destination, FakeSlack, Fault, Payload, Reply


class Interrupted(BaseException):
    pass


class CampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "campaign.sqlite"
        self.now = 100
        self.ids = 0
        self.binding = Binding(
            "task", "host", "session", Destination("workspace", "channel", "thread")
        )
        self.sanitizer = Sanitizer(("CANARY_SECRET_7391",))
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("offline only")
        )
        self.network.start()
        self.addCleanup(self.network.stop)
        self.provider = FakeSlack(
            self.binding.destination, lambda: self.now, self.new_id
        )
        self.campaign = self.open()
        self.addCleanup(lambda: self.campaign.close())

    def new_id(self) -> str:
        self.ids += 1
        return f"message-{self.ids}"

    def open(
        self,
        *,
        capacity: int = 32,
        retries: int = 2,
        checkpoint: Callable[[str], None] = lambda _: None,
    ) -> OfflineCampaign:
        return OfflineCampaign(
            self.path,
            self.binding,
            self.sanitizer,
            lambda: self.now,
            capacity=capacity,
            retries=retries,
            checkpoint=checkpoint,
        )

    def event(self, sequence: int = 1, kind: str = "public_summary") -> Event:
        return Event(
            self.binding,
            f"event-{sequence}",
            sequence,
            self.now,
            kind,
            Payload("invented"),
        )

    def enqueue(
        self,
        sequence: int = 1,
        action: str = "send",
        target: str | None = None,
        kind: str = "public_summary",
    ) -> str:
        return self.campaign.enqueue(
            self.event(sequence, kind),
            {
                "version": "runspindle.projection.v1",
                "kind": kind,
                "message": "invented",
            },
            action,
            target,
        )

    def test_native_source_sanitized_queue_and_distinct_accounting(self) -> None:
        source = NativeSource(self.binding, Mode.EVENTS, lambda: self.now)
        event = self.event()
        projected = {
            "version": "runspindle.projection.v1",
            "kind": event.kind,
            "message": "CANARY_SECRET_7391",
            "arguments": {
                "nested": ["CANARY_SECRET_7391"],
                "token": "CANARY_SECRET_7391",
            },
            "result": {"url": "https://invalid.example/?token=CANARY_SECRET_7391"},
            "error": {"text": "CANARY_SECRET_7391"},
            "attachments": [
                {"filename": "CANARY_SECRET_7391.txt", "caption": "CANARY_SECRET_7391"}
            ],
        }
        observed = source.emit(event, lambda e: self.campaign.enqueue(e, projected))
        self.assertEqual(observed.outcome, "submitted")
        self.assertEqual(
            self.campaign.counters(),
            dict(
                origin_observation=1,
                origin_event=1,
                queued=1,
                rejected=0,
                sent=0,
                destination_confirmed=0,
                dispatch_reserved=0,
            ),
        )
        self.assertEqual(self.campaign.tick(self.provider), "unknown")
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.campaign.counters()["sent"], 1)
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 0)
        self.assertEqual(self.campaign.tick(self.provider), "confirmed")
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 1)
        self.assertNotIn(b"CANARY_SECRET_7391", self.path.read_bytes())
        record = next(iter(self.provider.records.values()))
        self.assertNotIn("CANARY_SECRET_7391", repr(record))
        self.assertEqual(record.evidence_class, "synthetic")

    def test_429_virtual_retry_is_bounded_and_never_early(self) -> None:
        self.enqueue()
        for _ in range(3):
            self.provider.inject("send", Fault.RATE_LIMIT)
        for attempt in range(3):
            self.assertEqual(
                self.campaign.tick(self.provider),
                "retry" if attempt < 2 else "exhausted",
            )
            self.assertEqual(len(self.provider.requests), attempt + 1)
            if attempt < 2:
                self.assertEqual(self.campaign.tick(self.provider), "waiting")
                self.now += 3
        self.assertEqual(self.provider.records, {})
        self.assertEqual(self.campaign.tick(self.provider), "idle")
        self.assertEqual(self.campaign.counters()["sent"], 0)

    def test_lost_ack_missing_ambiguous_wrong_thread_never_resend(self) -> None:
        self.enqueue()
        self.provider.inject("send", Fault.LOST_ACK)
        self.campaign.tick(self.provider)
        self.campaign.close()
        self.campaign = self.open()
        for fault in (
            Fault.MISSING,
            Fault.AMBIGUOUS,
            Fault.WRONG_THREAD,
            Fault.MALFORMED,
        ):
            self.provider.inject("readback", fault)
            self.assertEqual(self.campaign.tick(self.provider), "unknown")
            self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.campaign.tick(self.provider), "confirmed")
        self.assertEqual(sum(r.action == "send" for r in self.provider.requests), 1)
        self.assertEqual(self.campaign.counters()["sent"], 0)
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 1)

    def test_ordered_update_delete_exact_readback_terminal(self) -> None:
        self.enqueue()
        self.campaign.tick(self.provider)
        self.campaign.tick(self.provider)
        target = self.campaign.receipt("event-1")
        if target is None:
            self.fail("missing confirmed receipt")
        self.assertEqual(self.enqueue(2, "update", target), "queued")
        self.provider.inject("update", Fault.LOST_ACK)
        self.assertEqual(self.campaign.tick(self.provider), "unknown")
        self.assertEqual(self.enqueue(3, "delete", target, "final"), "queued")
        self.assertEqual(self.campaign.tick(self.provider), "confirmed")
        self.assertEqual([r.action for r in self.provider.requests][-1], "readback")
        self.provider.inject("delete", Fault.LOST_ACK)
        self.campaign.tick(self.provider)
        self.assertEqual(self.campaign.tick(self.provider), "confirmed")
        self.assertTrue(self.provider.records[target].deleted)
        self.assertIsNone(self.provider.records[target].payload)
        self.assertEqual(self.provider.records[target].operation_id, "event-3")
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 3)
        self.assertEqual(self.enqueue(4), "rejected")

    def test_duplicate_gap_wrong_route_dirty_identity_attachment_rejected(self) -> None:
        self.enqueue()
        self.assertEqual(self.enqueue(), "rejected")
        self.assertEqual(self.enqueue(3), "rejected")
        for event in (
            replace(
                self.event(2),
                binding=replace(
                    self.binding,
                    destination=Destination("workspace", "channel", "other"),
                ),
            ),
            replace(self.event(2), event_id="CANARY_SECRET_7391"),
            replace(
                self.event(2),
                payload=Payload(
                    "safe", (Attachment("a", "safe", b"CANARY_SECRET_7391"),)
                ),
            ),
        ):
            self.assertEqual(
                self.campaign.enqueue(
                    event,
                    {
                        "version": "runspindle.projection.v1",
                        "kind": event.kind,
                        "message": "safe",
                    },
                ),
                "rejected",
            )
        self.assertEqual(self.campaign.counters()["origin_event"], 1)
        self.assertEqual(self.campaign.counters()["origin_observation"], 6)
        self.assertNotIn(b"CANARY_SECRET_7391", self.path.read_bytes())
        wrong = FakeSlack(
            Destination("workspace", "channel", "other"), lambda: self.now, self.new_id
        )
        with self.assertRaises(ValueError):
            self.campaign.tick(wrong)
        self.assertEqual(wrong.requests, [])

    def test_capacity_and_unsupported_fields_fail_closed(self) -> None:
        self.campaign.close()
        self.path.unlink()
        self.campaign = self.open(capacity=1)
        self.enqueue()
        self.assertEqual(self.enqueue(2), "rejected")
        self.assertEqual(
            self.campaign.enqueue(
                self.event(2),
                {
                    "version": "runspindle.projection.v1",
                    "kind": "public_summary",
                    "unknown": "CANARY_SECRET_7391",
                },
            ),
            "rejected",
        )
        self.assertEqual(len(self.provider.requests), 0)

    def test_crash_checkpoints_preserve_effect_and_fence(self) -> None:
        self.enqueue()

        def crash(point: str) -> None:
            if point == "after_send":
                raise Interrupted()

        self.campaign.checkpoint = crash
        with self.assertRaises(Interrupted):
            self.campaign.tick(self.provider)
        self.assertEqual(len(self.provider.records), 1)
        self.campaign.close()
        self.campaign = self.open()
        self.assertEqual(self.campaign.tick(self.provider), "confirmed")
        self.assertEqual(sum(r.action == "send" for r in self.provider.requests), 1)
        self.assertEqual(self.campaign.counters()["sent"], 0)

    def test_before_persist_rollback_and_after_receipt_durable(self) -> None:
        def before(point: str) -> None:
            if point == "before_persist":
                raise Interrupted()

        self.campaign.checkpoint = before
        with self.assertRaises(Interrupted):
            self.enqueue()
        self.assertEqual(self.campaign.counters()["origin_observation"], 0)
        self.campaign.checkpoint = lambda _: None
        self.enqueue()
        self.campaign.tick(self.provider)

        def after(point: str) -> None:
            if point == "after_receipt":
                raise Interrupted()

        self.campaign.checkpoint = after
        with self.assertRaises(Interrupted):
            self.campaign.tick(self.provider)
        self.campaign.close()
        self.campaign = self.open()
        self.assertEqual(self.campaign.state("event-1"), "confirmed")
        self.assertEqual(self.campaign.tick(self.provider), "idle")

    def test_concurrent_connections_deduplicate_and_dispatch_once(self) -> None:
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                campaign = self.open()
                try:
                    barrier.wait(timeout=5)
                    outcomes.append(
                        campaign.enqueue(
                            self.event(),
                            {
                                "version": "runspindle.projection.v1",
                                "kind": "public_summary",
                                "message": "safe",
                            },
                        )
                    )
                    campaign.tick(self.provider)
                finally:
                    campaign.close()
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=writer) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertCountEqual(outcomes, ["queued", "rejected"])
        self.assertEqual(sum(r.action == "send" for r in self.provider.requests), 1)
        self.assertEqual(len(self.provider.records), 1)
        self.campaign.tick(self.provider)
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 1)

    def test_fresh_process_exit_after_fence_never_dispatches_on_restart(self) -> None:
        self.enqueue()
        code = """import os,socket,sys
from pathlib import Path
from tether.campaign_testing import OfflineCampaign
from tether.native_testing import Binding
from tether.testing import Destination,FakeSlack
from tether.sanitization import Sanitizer
def deny(*a,**k): raise AssertionError("offline only")
socket.socket.connect=deny; socket.create_connection=deny
binding=Binding("task","host","session",Destination("workspace","channel","thread"))
def checkpoint(point):
 if point=="before_send": os._exit(73)
c=OfflineCampaign(Path(sys.argv[1]),binding,Sanitizer(("CANARY_SECRET_7391",)),lambda:100,checkpoint=checkpoint)
c.tick(FakeSlack(binding.destination,lambda:100,lambda:"never"))
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.path)],
            timeout=10,
            capture_output=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 73, result.stderr)
        self.campaign.close()
        self.campaign = self.open()
        self.assertEqual(self.campaign.tick(self.provider), "unknown")
        self.assertEqual(self.provider.records, {})
        self.assertEqual([r.action for r in self.provider.requests], ["readback"])

    def test_fresh_process_after_send_update_delete_effects_recover_exactly(
        self,
    ) -> None:
        from offline_destination_peer import StoredFakeSlack

        peer_path = Path(self.temp.name) / "peer.sqlite"
        peer = StoredFakeSlack(peer_path, self.binding.destination, lambda: self.now)
        peer.close()
        code = """import os,socket,sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()/"tests"))
from offline_destination_peer import StoredFakeSlack
from tether.campaign_testing import OfflineCampaign
from tether.native_testing import Binding
from tether.testing import Destination
from tether.sanitization import Sanitizer
def deny(*a,**k): raise AssertionError("offline only")
socket.socket.connect=deny;socket.create_connection=deny
b=Binding("task","host","session",Destination("workspace","channel","thread"))
def crash(point):
 if point=="after_send": os._exit(74)
c=OfflineCampaign(Path(sys.argv[1]),b,Sanitizer(("CANARY_SECRET_7391",)),lambda:100,checkpoint=crash)
p=StoredFakeSlack(Path(sys.argv[2]),b.destination,lambda:100)
c.tick(p)
"""
        target = None
        for sequence, action in enumerate(("send", "update", "delete"), 1):
            self.assertEqual(
                self.enqueue(
                    sequence,
                    action,
                    target,
                    "final" if action == "delete" else "public_summary",
                ),
                "queued",
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(self.path), str(peer_path)],
                timeout=10,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 74, result.stderr)
            # Independent destination observation before journal recovery, not a
            # receipt synthesized from expected state or a freshly empty peer.
            with sqlite3.connect(peer_path) as db:
                snapshot = json.loads(
                    db.execute("SELECT snapshot FROM peer WHERE id=1").fetchone()[0]
                )
            self.assertEqual(len(snapshot["records"]), 1)
            record = snapshot["records"][0]
            self.assertEqual(record["operation_id"], f"event-{sequence}")
            self.assertEqual(record["deleted"], action == "delete")
            self.assertEqual(
                record["destination"],
                dict(
                    workspace_id="workspace", channel_id="channel", thread_id="thread"
                ),
            )
            peer = StoredFakeSlack(
                peer_path, self.binding.destination, lambda: self.now
            )
            try:
                self.campaign.close()
                self.campaign = self.open()
                self.assertEqual(self.campaign.tick(peer), "confirmed")
                target = self.campaign.receipt(f"event-{sequence}")
                self.assertEqual(sum(r.action == action for r in peer.requests), 1)
            finally:
                peer.close()
        self.assertEqual(self.campaign.counters()["sent"], 0)
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 3)

    def test_provider_identity_canary_is_never_persisted(self) -> None:
        provider = FakeSlack(
            self.binding.destination, lambda: self.now, lambda: "CANARY_SECRET_7391"
        )
        self.enqueue()
        self.assertEqual(self.campaign.tick(provider), "unknown")
        self.assertEqual(self.campaign.tick(provider), "unknown")
        self.assertNotIn(b"CANARY_SECRET_7391", self.path.read_bytes())

    def test_source_observations_are_separate_from_campaign_admission(self) -> None:
        self.campaign.close()
        self.path.unlink()
        self.campaign = self.open(capacity=1)
        source = NativeSource(self.binding, Mode.EVENTS, lambda: self.now)

        def sink(e: Event) -> str:
            return self.campaign.enqueue(
                e,
                {
                    "version": "runspindle.projection.v1",
                    "kind": e.kind,
                    "message": "safe",
                },
            )

        unsupported = source.emit(self.event(kind="hidden_reasoning"), sink)
        self.assertEqual(unsupported.outcome, "unsupported")
        self.assertEqual(self.campaign.counters()["origin_observation"], 0)
        self.assertEqual(source.emit(self.event(), sink).outcome, "submitted")
        self.assertEqual(source.emit(self.event(2), sink).outcome, "submitted")
        self.assertEqual(
            [o.outcome for o in source.observations],
            ["unsupported", "submitted", "submitted"],
        )
        self.assertEqual(self.campaign.counters()["origin_observation"], 2)
        self.assertEqual(self.campaign.counters()["origin_event"], 1)
        self.assertEqual(self.campaign.counters()["rejected"], 1)
        self.assertEqual(len(self.provider.requests), 0)

    def test_before_receipt_interruption_retains_unknown_and_only_reads_again(
        self,
    ) -> None:
        self.enqueue()
        self.campaign.tick(self.provider)

        def stop(point: str) -> None:
            if point == "before_receipt":
                raise Interrupted()

        self.campaign.checkpoint = stop
        with self.assertRaises(Interrupted):
            self.campaign.tick(self.provider)
        self.assertEqual(self.campaign.state("event-1"), "unknown")
        self.campaign.close()
        self.campaign = self.open()
        self.assertEqual(self.campaign.tick(self.provider), "confirmed")
        self.assertEqual(sum(r.action == "send" for r in self.provider.requests), 1)

    def test_429_update_delete_retries_only_no_effect(self) -> None:
        self.enqueue()
        self.campaign.tick(self.provider)
        self.campaign.tick(self.provider)
        target = self.campaign.receipt("event-1")
        for sequence, action in ((2, "update"), (3, "delete")):
            self.assertEqual(self.enqueue(sequence, action, target), "queued")
            before = dict(self.provider.records)
            self.provider.inject(action, Fault.RATE_LIMIT)
            self.assertEqual(self.campaign.tick(self.provider), "retry")
            self.assertEqual(self.provider.records, before)
            self.assertEqual(self.campaign.tick(self.provider), "waiting")
            self.now += 3
            self.assertEqual(self.campaign.tick(self.provider), "unknown")
            self.assertEqual(self.campaign.tick(self.provider), "confirmed")

    def test_before_effect_failure_is_terminal_not_a_blind_retry(self) -> None:
        self.enqueue()
        self.provider.inject("send", Fault.BEFORE_EFFECT)
        self.assertEqual(self.campaign.tick(self.provider), "failed")
        self.assertEqual(self.campaign.tick(self.provider), "idle")
        self.assertEqual(self.provider.records, {})
        self.assertEqual(len(self.provider.requests), 1)

    def test_unknown_resend_source_mutation_causes_independent_duplicate_effect(
        self,
    ) -> None:
        from offline_destination_peer import StoredFakeSlack
        import tether.campaign_testing as original

        peer_path = Path(self.temp.name) / "mutation-peer.sqlite"
        peer = StoredFakeSlack(peer_path, self.binding.destination, lambda: self.now)
        try:
            self.enqueue()
            peer.inject("send", Fault.LOST_ACK)
            self.assertEqual(self.campaign.tick(peer), "unknown")
            self.campaign.close()
            self.campaign = self.open()
            source = Path(original.__file__).read_text()
            needle = 'row["state"] in {"queued", "retry"}'
            self.assertEqual(source.count(needle), 1)
            mutation = Path(self.temp.name) / "mutant_campaign.py"
            mutation.write_text(
                source.replace(needle, 'row["state"] in {"queued", "retry", "unknown"}')
            )
            spec = importlib.util.spec_from_file_location("offline_mutant", mutation)
            if spec is None or spec.loader is None:
                self.fail("mutation could not load")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            mutant = module.OfflineCampaign(
                self.path, self.binding, self.sanitizer, lambda: self.now
            )
            try:
                mutant.tick(peer)
            finally:
                mutant.close()
            with sqlite3.connect(peer_path) as db:
                actual = json.loads(
                    db.execute("SELECT snapshot FROM peer WHERE id=1").fetchone()[0]
                )
            self.assertEqual(len(actual["records"]), 2)
            self.assertEqual(sum(r["action"] == "send" for r in actual["requests"]), 2)
            with self.assertRaises(AssertionError):
                self.assertEqual(
                    len(actual["records"]), 1, "duplicate destination effect"
                )
            self.assertEqual(self.campaign.tick(peer), "unknown")
            self.assertEqual(self.campaign.counters()["destination_confirmed"], 0)
        finally:
            peer.close()

    def test_fresh_process_persistence_checkpoints(self) -> None:
        code = """import os,socket,sys
from pathlib import Path
from tether.campaign_testing import OfflineCampaign
from tether.native_testing import Binding,Event
from tether.testing import Destination,Payload
from tether.sanitization import Sanitizer
def deny(*a,**k): raise AssertionError("offline only")
socket.socket.connect=deny;socket.create_connection=deny
b=Binding("task","host","session",Destination("workspace","channel","thread"))
def stop(point):
 if point==sys.argv[2]: os._exit(75)
c=OfflineCampaign(Path(sys.argv[1]),b,Sanitizer(("CANARY_SECRET_7391",)),lambda:100,checkpoint=stop)
c.enqueue(Event(b,"event-1",1,100,"public_summary",Payload("safe")),{"version":"runspindle.projection.v1","kind":"public_summary","message":"safe"})
"""
        for point, expected in (("before_persist", None), ("after_persist", "queued")):
            with self.subTest(point=point):
                self.campaign.close()
                self.path.unlink()
                result = subprocess.run(
                    [sys.executable, "-c", code, str(self.path), point],
                    timeout=10,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 75, result.stderr)
                self.campaign = self.open()
                self.assertEqual(self.campaign.state("event-1"), expected)
                self.assertEqual(
                    self.campaign.counters()["queued"], int(expected == "queued")
                )

    def test_existing_damaged_schema_or_metadata_never_repairs_after_effect(
        self,
    ) -> None:
        damage = (
            "DROP TABLE campaign_operations",
            "DELETE FROM campaign_counts WHERE name='sent'",
            "UPDATE campaign_counts SET value=-1 WHERE name='queued'",
            "DELETE FROM campaign_meta",
            "ALTER TABLE campaign_operations ADD COLUMN surprise TEXT",
            "CREATE INDEX extra ON campaign_operations(state)",
            "PRAGMA user_version=0",
        )
        for index, statement in enumerate(damage):
            with self.subTest(statement=statement):
                path = Path(self.temp.name) / f"damage-{index}.sqlite"
                campaign = OfflineCampaign(
                    path, self.binding, self.sanitizer, lambda: self.now
                )
                provider = FakeSlack(
                    self.binding.destination, lambda: self.now, self.new_id
                )
                provider.inject("send", Fault.LOST_ACK)
                campaign.enqueue(
                    self.event(),
                    {
                        "version": "runspindle.projection.v1",
                        "kind": "public_summary",
                        "message": "safe",
                    },
                )
                campaign.tick(provider)
                campaign.close()
                self.assertEqual(len(provider.records), 1)
                with sqlite3.connect(path) as db:
                    db.execute(statement)
                before = path.read_bytes()
                with self.assertRaises((ValueError, sqlite3.Error)):
                    OfflineCampaign(
                        path, self.binding, self.sanitizer, lambda: self.now
                    )
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(len(provider.records), 1)
                self.assertEqual(len(provider.requests), 1)

    def test_pending_ack_blocks_concurrent_confirmation_and_successor(self) -> None:
        effect = threading.Event()
        release = threading.Event()
        done = threading.Event()
        errors: list[BaseException] = []
        outcomes: list[str] = []

        class LateAck(FakeSlack):
            def send(
                peer, destination: Destination, operation_id: str, payload: Payload
            ) -> Reply:
                original = super().send(destination, operation_id, payload)
                effect.set()
                if not release.wait(5):
                    raise RuntimeError("bounded acknowledgement deadline")
                return replace(original, message_id="conflicting-ack")

        peer = LateAck(self.binding.destination, lambda: self.now, self.new_id)
        self.enqueue()
        self.enqueue(2)

        def writer() -> None:
            campaign = self.open()
            try:
                outcomes.append(campaign.tick(peer))
            except BaseException as error:
                errors.append(error)
            finally:
                campaign.close()

        def reader() -> None:
            campaign = self.open()
            try:
                outcomes.append(campaign.tick(peer))
            except BaseException as error:
                errors.append(error)
            finally:
                campaign.close()
                done.set()

        sending = threading.Thread(target=writer)
        reading = threading.Thread(target=reader)
        sending.start()
        try:
            self.assertTrue(effect.wait(5))
            reading.start()
            self.assertFalse(done.wait(0.05))
            self.assertEqual(self.campaign.counters()["destination_confirmed"], 0)
        finally:
            release.set()
            sending.join(10)
            if reading.ident is not None:
                reading.join(10)
        self.assertFalse(sending.is_alive())
        self.assertFalse(reading.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(outcomes, ["unknown", "unknown"])
        self.assertEqual(self.campaign.state("event-1"), "unknown")
        self.assertEqual(self.campaign.state("event-2"), "queued")
        self.assertEqual(len(peer.records), 1)
        self.assertEqual(self.campaign.counters()["destination_confirmed"], 0)

    def test_same_instance_reentrancy_cannot_rollback_outer_dispatch(self) -> None:
        rejected: list[str] = []
        campaign = self.campaign

        class Nested(FakeSlack):
            def send(
                peer, destination: Destination, operation_id: str, payload: Payload
            ) -> Reply:
                try:
                    campaign.tick(peer)
                except ValueError:
                    rejected.append("reentrant")
                return super().send(destination, operation_id, payload)

        peer = Nested(self.binding.destination, lambda: self.now, self.new_id)
        self.enqueue()
        self.assertEqual(campaign.tick(peer), "unknown")
        self.assertEqual(rejected, ["reentrant"])
        self.assertEqual(campaign.counters()["sent"], 1)
        self.assertEqual(campaign.tick(peer), "confirmed")
        self.assertEqual(len(peer.records), 1)

    def test_contradictory_reply_fields_never_retry_or_skip_unknown_effect(
        self,
    ) -> None:
        replies = (
            Reply("failed", message_id="contradiction"),
            Reply("failed", retry_at=103),
            Reply("rate_limited", message_id="contradiction", retry_at=103),
            Reply("rate_limited", retry_at=True),
            Reply("rate_limited", retry_at=2**64),
            Reply("rate_limited", retry_at=100),
            Reply("accepted", message_id="message-1", retry_at=103),
            Reply("accepted"),
            Reply("unknown", message_id="contradiction"),
            Reply("unknown", retry_at=103),
            Reply("unrecognized"),
        )
        for reply in replies:
            with self.subTest(reply=reply):
                self.campaign.close()
                self.path.unlink()
                self.now = 100
                self.campaign = self.open()

                class Contradictory(FakeSlack):
                    def send(
                        peer,
                        destination: Destination,
                        operation_id: str,
                        payload: Payload,
                    ) -> Reply:
                        super().send(destination, operation_id, payload)
                        return reply

                peer = Contradictory(
                    self.binding.destination, lambda: self.now, self.new_id
                )
                self.enqueue()
                self.enqueue(2)
                self.assertEqual(self.campaign.tick(peer), "unknown")
                self.assertEqual(len(peer.records), 1)
                self.assertEqual(self.campaign.counters()["sent"], 0)
                self.now = 200
                peer.inject("readback", Fault.MISSING)
                self.assertEqual(self.campaign.tick(peer), "unknown")
                self.assertEqual(self.campaign.state("event-2"), "queued")
                self.assertEqual(len(peer.records), 1)
                self.assertEqual(
                    [r.action for r in peer.requests], ["send", "readback"]
                )
                self.assertEqual(self.campaign.tick(peer), "confirmed")
                self.assertEqual(len(peer.records), 1)


if __name__ == "__main__":
    unittest.main()
