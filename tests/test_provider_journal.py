"""Real SQLite journals plus independent synthetic provider store, no network."""

import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.test_admission import authenticate, event, grant, proof
from tether.admission import Admission, Rejected, canonical
from tether.journal import ProviderJournal
from tether.testing import (
    Attachment,
    Destination,
    FakeSlack,
    Fault,
    Payload,
    Record,
    Reply,
)

ROOT = Path(__file__).resolve().parents[1]
DEST = Destination("workspace-1", "channel-1", "thread-1")
PAYLOAD = Payload(
    "Synthetic accepted artifact",
    (Attachment("artifact-1", "result.txt", b"synthetic bytes"),),
)


def envelope() -> bytes:
    encoded: bytes = canonical(
        {
            "version": "runspindle.envelope.v1",
            "message_type": "delivery_request",
            "message_id": "delivery-message-1",
            "binding": {
                "task_id": "task-1",
                "revision": 1,
                "operation_id": "operation-1",
                "policy_revision": "policy-1",
                "host_id": "host-1",
                "workspace_id": "workspace-1",
                "lease_epoch": 1,
            },
            "payload": {
                "artifact_id": "artifact-1",
                "artifact_revision": 1,
                "sha256": hashlib.sha256(PAYLOAD.attachments[0].content).hexdigest(),
                "validator_revision": "validator-1",
                "account_id": "account-1",
                "destination_id": "destination-1",
                "delivery_operation_id": "delivery-1",
            },
        }
    )
    return encoded


def authorize(raw: bytes, digest: str) -> bool:
    return raw == envelope() and digest == PAYLOAD.digest()


def route(account: str, destination: str) -> Destination | None:
    return DEST if (account, destination) == ("account-1", "destination-1") else None


class DurableFake:
    """Test-only real SQLite provider effects across processes; reuses FakeSlack."""

    def __init__(
        self, path: str, fault: Fault | None = None, crash_after: bool = False
    ) -> None:
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS effects(message TEXT PRIMARY KEY,operation TEXT,workspace TEXT,channel TEXT,thread TEXT,text TEXT,artifact TEXT,filename TEXT,content BLOB);
            CREATE TABLE IF NOT EXISTS calls(action TEXT);
        """)
        self.fault = fault
        self.crash_after = crash_after

    def close(self) -> None:
        self.db.close()

    def _hydrate(self) -> FakeSlack:
        rows = self.db.execute("SELECT * FROM effects").fetchall()
        fake = FakeSlack(DEST, lambda: 100, lambda: f"message-{len(rows) + 1}")
        for row in rows:
            payload = Payload(
                row[5], () if row[6] is None else (Attachment(row[6], row[7], row[8]),)
            )
            fake.records[row[0]] = Record(
                Destination(row[2], row[3], row[4]), row[1], row[0], payload, False
            )
        return fake

    def send(
        self, destination: Destination, operation_id: str, payload: Payload
    ) -> Reply:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("INSERT INTO calls VALUES ('send')")
            fake = self._hydrate()
            if self.fault is not None:
                fake.inject("send", self.fault)
            reply = fake.send(destination, operation_id, payload)
            for row in fake.records.values():
                if row.payload is None:
                    raise RuntimeError("unexpected deletion")
                attachment = (
                    row.payload.attachments[0] if row.payload.attachments else None
                )
                self.db.execute(
                    "INSERT OR IGNORE INTO effects VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        row.message_id,
                        row.operation_id,
                        row.destination.workspace_id,
                        row.destination.channel_id,
                        row.destination.thread_id,
                        row.payload.text,
                        attachment.attachment_id if attachment else None,
                        attachment.filename if attachment else None,
                        attachment.content if attachment else None,
                    ),
                )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        if self.crash_after:
            os._exit(17)
        return reply

    def readback(self, destination: Destination, operation_id: str) -> object:
        self.db.execute("INSERT INTO calls VALUES ('readback')")
        return self._hydrate().readback(destination, operation_id)


class JournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.admission = Admission(
            str(self.base / "admission.db"), authenticate, lambda *_: grant(event())
        )
        self.addCleanup(self.admission.close)
        raw = canonical(event())
        self.admission.ingest(raw, proof(raw))
        self.journal = ProviderJournal(
            str(self.base / "journal.db"), self.admission, authorize, route
        )
        self.addCleanup(self.journal.close)
        self.provider = DurableFake(str(self.base / "provider.db"))
        self.addCleanup(self.provider.close)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("forbidden network")
        )
        self.calls = self.network.start()
        self.addCleanup(self.network.stop)

    def tearDown(self) -> None:
        self.calls.assert_not_called()

    def observed(self) -> tuple[int, int]:
        with sqlite3.connect(self.base / "provider.db") as db:
            return (
                db.execute("SELECT COUNT(*) FROM effects").fetchone()[0],
                db.execute("SELECT COUNT(*) FROM calls WHERE action='send'").fetchone()[
                    0
                ],
            )

    def test_accepted_is_not_confirmed_and_exact_readback_never_resends(self) -> None:
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state, "accepted"
        )
        self.assertEqual(
            self.journal.lookup(envelope(), PAYLOAD, self.provider).state,
            "destination_confirmed",
        )
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state,
            "destination_confirmed",
        )
        self.assertEqual(self.observed(), (1, 1))
        stored = self.journal.db.execute(
            "SELECT envelope,payload_digest,destination FROM provider_attempts"
        ).fetchone()
        self.assertEqual(stored[0], envelope())
        self.assertEqual(stored[1], PAYLOAD.digest())
        self.assertNotIn(PAYLOAD.text, str(list(self.journal.db.iterdump())))
        self.assertNotIn(
            PAYLOAD.attachments[0].content.decode(),
            str(list(self.journal.db.iterdump())),
        )

    def test_lost_ack_and_partial_attachments_remain_truthful(self) -> None:
        self.provider.fault = Fault.LOST_ACK
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state, "unknown"
        )
        self.assertEqual(
            self.journal.lookup(envelope(), PAYLOAD, self.provider).state,
            "destination_confirmed",
        )
        self.assertEqual(self.observed(), (1, 1))

    def test_partial_attachment_readback_does_not_confirm(self) -> None:
        self.provider.fault = Fault.PARTIAL_ATTACHMENTS
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state, "accepted"
        )
        self.assertEqual(
            self.journal.lookup(envelope(), PAYLOAD, self.provider).state, "unknown"
        )
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state, "unknown"
        )
        self.assertEqual(self.observed(), (1, 1))

    def test_rate_limit_is_durable_but_never_automatically_retried(self) -> None:
        self.provider.fault = Fault.RATE_LIMIT
        result = self.journal.send(envelope(), PAYLOAD, self.provider)
        self.assertEqual((result.state, result.retry_at), ("rate_limited", 103))
        self.assertEqual(
            self.journal.db.execute(
                "SELECT state,retry_at FROM provider_attempts"
            ).fetchone(),
            ("rate_limited", 103),
        )
        self.fresh_process("send", "unknown")
        self.assertEqual(self.observed(), (0, 1))

    def test_missing_authority_admission_and_route_deny_before_effects(self) -> None:
        for field in ("authorize", "admission", "resolve"):
            with patch.object(self.journal, field, None):
                with self.assertRaises(Rejected):
                    self.journal.send(envelope(), PAYLOAD, self.provider)
        for callback in (
            lambda *_: False,
            lambda *_: (_ for _ in ()).throw(OSError("unavailable")),
        ):
            with patch.object(self.journal, "authorize", callback):
                with self.assertRaises(Rejected):
                    self.journal.send(envelope(), PAYLOAD, self.provider)
        self.assertEqual(self.observed(), (0, 0))
        self.assertEqual(
            self.journal.db.execute(
                "SELECT COUNT(*) FROM provider_attempts"
            ).fetchone()[0],
            0,
        )

    def test_authority_rechecked_after_reservation_before_send(self) -> None:
        checks = iter([True, False])
        with patch.object(self.journal, "authorize", lambda *_: next(checks)):
            with self.assertRaises(Rejected):
                self.journal.send(envelope(), PAYLOAD, self.provider)
        self.assertEqual(self.observed(), (0, 0))
        self.fresh_process("send", "unknown")
        self.assertEqual(self.observed(), (0, 0))

    def test_superseded_deleted_admission_denies(self) -> None:
        revised = event(2, kind="delete", text="")
        self.admission.authorize = lambda *_: grant(revised)
        raw = canonical(revised)
        self.admission.ingest(raw, proof(raw))
        with self.assertRaises(Rejected):
            self.journal.send(envelope(), PAYLOAD, self.provider)
        self.assertEqual(self.observed(), (0, 0))

    def test_changed_payload_route_or_envelope_cannot_rebind_operation(self) -> None:
        self.journal.send(envelope(), PAYLOAD, self.provider)
        with patch.object(self.journal, "authorize", lambda *_: True):
            for payload in (
                replace(PAYLOAD, text="changed"),
                replace(
                    PAYLOAD,
                    attachments=(replace(PAYLOAD.attachments[0], filename="changed"),),
                ),
            ):
                with self.assertRaises(Rejected):
                    self.journal.send(envelope(), payload, self.provider)
            with patch.object(
                self.journal, "resolve", lambda *_: replace(DEST, thread_id="wrong")
            ):
                with self.assertRaises(Rejected):
                    self.journal.send(envelope(), PAYLOAD, self.provider)
            value = json.loads(envelope())
            value["message_id"] = "other"
            with self.assertRaises(Rejected):
                self.journal.send(canonical(value), PAYLOAD, self.provider)
        self.assertEqual(self.observed(), (1, 1))

    def test_artifact_bytes_cannot_be_replaced_even_if_callback_allows(self) -> None:
        wrong = replace(
            PAYLOAD,
            attachments=(replace(PAYLOAD.attachments[0], content=b"wrong bytes"),),
        )
        with patch.object(self.journal, "authorize", lambda *_: True):
            with self.assertRaises(Rejected):
                self.journal.send(envelope(), wrong, self.provider)
        self.assertEqual(self.observed(), (0, 0))

    def test_conflicting_receipt_is_fenced_after_restart(self) -> None:
        self.journal.send(envelope(), PAYLOAD, self.provider)
        self.provider.db.execute("UPDATE effects SET message='different-message'")
        self.assertEqual(
            self.journal.lookup(envelope(), PAYLOAD, self.provider).state, "unknown"
        )
        self.assertEqual(
            self.journal.db.execute(
                "SELECT conflict FROM provider_attempts"
            ).fetchone()[0],
            1,
        )
        self.provider.db.execute("UPDATE effects SET message='message-1'")
        self.fresh_process("send", "unknown")
        self.assertEqual(self.observed(), (1, 1))

    def test_wrong_thread_malformed_and_ambiguous_readback(self) -> None:
        self.journal.send(envelope(), PAYLOAD, self.provider)
        good = self.provider.readback(DEST, "delivery-1")
        if not isinstance(good, tuple):
            self.fail("fixture readback type")
        for rows in (
            {"malformed": True},
            (),
            good + good,
            (replace(good[0], destination=replace(DEST, thread_id="wrong")),),
        ):
            with patch.object(self.provider, "readback", return_value=rows):
                self.assertEqual(
                    self.journal.lookup(envelope(), PAYLOAD, self.provider).state,
                    "unknown",
                )
        self.assertEqual(self.observed(), (1, 1))

    def test_sql_failure_before_reservation_creates_no_effect(self) -> None:
        self.journal.db.execute(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON provider_attempts BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.journal.send(envelope(), PAYLOAD, self.provider)
        self.assertEqual(self.observed(), (0, 0))

    def test_cancel_after_reservation_never_resends(self) -> None:
        with patch.object(
            self.provider, "send", side_effect=KeyboardInterrupt("cancel")
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.journal.send(envelope(), PAYLOAD, self.provider)
        self.fresh_process("send", "unknown")
        self.assertEqual(self.observed(), (0, 0))

    def child(self, action: str, expected: str) -> subprocess.Popen[str]:
        script = """
import sys,socket
from tests.test_provider_journal import *
socket.socket.connect=lambda *_: (_ for _ in ()).throw(RuntimeError("forbidden network"))
base=Path(sys.argv[1]);action=sys.argv[2]
a=Admission(str(base/"admission.db"))
j=ProviderJournal(str(base/"journal.db"),a,authorize,route)
p=DurableFake(str(base/"provider.db"), crash_after=action=="crash")
try:
    result=j.lookup(envelope(),PAYLOAD,p) if action=="lookup" else j.send(envelope(),PAYLOAD,p)
    if result.state not in sys.argv[3].split(","):raise RuntimeError(result.state)
finally:
    p.close();j.close();a.close()
"""
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        return subprocess.Popen(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.base),
                action,
                expected,
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def finish_child(self, child: subprocess.Popen[str], code: int = 0) -> None:
        try:
            _, stderr = child.communicate(timeout=20)
            self.assertEqual(child.returncode, code, stderr)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=20)

    def fresh_process(self, action: str, expected: str) -> None:
        self.finish_child(self.child(action, expected))

    def test_fresh_process_crash_after_effect_reconciles_once(self) -> None:
        self.finish_child(self.child("crash", "unused"), 17)
        self.assertEqual(self.observed(), (1, 1))
        self.fresh_process("send", "destination_confirmed")
        self.fresh_process("lookup", "destination_confirmed")
        self.assertEqual(self.observed(), (1, 1))

    def test_competing_process_sends_are_fenced(self) -> None:
        # An existing unknown reservation forces both contenders into readback.
        self.provider.fault = Fault.LOST_ACK
        self.journal.send(envelope(), PAYLOAD, self.provider)
        children = [self.child("send", "destination_confirmed") for _ in range(2)]
        self.finish_all(children)
        self.assertEqual(self.observed(), (1, 1))

    def finish_all(self, children: list[subprocess.Popen[str]]) -> None:
        try:
            for child in children:
                self.finish_child(child)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=20)

    def test_virgin_operation_competing_processes_commit_one_attempt(self) -> None:
        children = [
            self.child("send", "accepted,destination_confirmed,unknown")
            for _ in range(2)
        ]
        self.finish_all(children)
        self.assertEqual(self.observed(), (1, 1))
        self.fresh_process("lookup", "destination_confirmed")
        self.assertEqual(self.observed(), (1, 1))

    def test_authority_revoked_during_readback_cannot_confirm(self) -> None:
        self.journal.send(envelope(), PAYLOAD, self.provider)
        original = self.provider.readback

        def revoke(destination: Destination, operation: str) -> object:
            result = original(destination, operation)
            self.journal.authorize = lambda *_: False
            return result

        with patch.object(self.provider, "readback", side_effect=revoke):
            with self.assertRaises(Rejected):
                self.journal.lookup(envelope(), PAYLOAD, self.provider)
        self.assertEqual(
            self.journal.db.execute(
                "SELECT observed FROM provider_attempts"
            ).fetchone()[0],
            None,
        )
        self.assertEqual(self.observed(), (1, 1))

    def test_authority_revoked_at_lookup_lock_boundary_cannot_confirm(self) -> None:
        self.journal.send(envelope(), PAYLOAD, self.provider)
        real = self.journal.db
        journal = self.journal

        class RevokeAtLock:
            def execute(
                self, sql: str, args: tuple[object, ...] = ()
            ) -> sqlite3.Cursor:
                result = real.execute(sql, args)
                if sql == "BEGIN IMMEDIATE":
                    journal.authorize = lambda *_: False
                return result

        with patch.object(self.journal, "db", RevokeAtLock()):
            with self.assertRaises(Rejected):
                self.journal.lookup(envelope(), PAYLOAD, self.provider)
        self.assertEqual(
            real.execute("SELECT observed FROM provider_attempts").fetchone()[0], None
        )
        self.assertFalse(real.in_transaction)
        self.assertEqual(self.observed(), (1, 1))

    def test_deliberate_resend_mutation_is_observed_in_provider_store(self) -> None:
        source = (ROOT / "tether/journal.py").read_text()
        needle = "return self.lookup(raw, payload, provider)"
        self.assertEqual(source.count(needle), 1)
        path = self.base / "mutant.py"
        path.write_text(
            source.replace(
                needle,
                "return provider.send(destination, operation, payload)  # deliberate mutation",
            )
        )
        spec = importlib.util.spec_from_file_location("journal_mutant", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("mutation loader unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            mutant = module.ProviderJournal(
                str(self.base / "mutant.db"), self.admission, authorize, route
            )
            try:
                mutant.send(envelope(), PAYLOAD, self.provider)
                mutant.send(envelope(), PAYLOAD, self.provider)
                self.assertEqual(
                    self.observed(),
                    (2, 2),
                    "independent destination store must expose duplicate effect",
                )
            finally:
                mutant.close()
        finally:
            sys.modules.pop(spec.name, None)

    def test_strict_envelope_rejects_before_effects(self) -> None:
        raw = envelope()
        bad = [raw + b" ", raw[:-1] + b',"message_id":"duplicate"}', b"not-json"]
        for value in (True, 1.0, 0, -1, 2**64):
            decoded = json.loads(raw)
            decoded["binding"]["revision"] = value
            bad.append(canonical(decoded))
        for malformed in bad:
            with self.assertRaises(Rejected):
                self.journal.send(malformed, PAYLOAD, self.provider)
        self.assertEqual(self.observed(), (0, 0))
