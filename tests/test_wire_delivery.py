"""Real journals and wire parser against an independent SQLite HTTP peer."""

import json
import types
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from contextlib import closing
from unittest.mock import patch
from typing import Any

from tests.test_admission import event, grant, proof
from tests.test_provider_journal import envelope as legacy_envelope
from tests.test_slack_upload import StoredHTTP, MESSAGE
from tether.admission import Admission, Identity, Rejected, canonical
from tether.journal import ProviderJournal
from tether.testing import Attachment, Destination, Payload
from tether.wire_delivery import WireDeliveryJournal

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = Identity("actor-1", "T100", "C100", "1700000000.000001")
DEST = Destination(IDENTITY.workspace_id, IDENTITY.channel_id, IDENTITY.thread_id)
PAYLOAD = Payload(
    "Synthetic accepted artifact",
    (Attachment("artifact-1", "result.txt", b"synthetic bytes"),),
)


def envelope() -> bytes:
    value = json.loads(legacy_envelope())
    value["binding"]["workspace_id"] = "T100"
    return canonical(value)


def ingress() -> dict[str, Any]:
    return event(workspace_id="T100", channel_id="C100", thread_id=IDENTITY.thread_id)


def prepare(
    base: Path, fault: str = ""
) -> tuple[Admission, StoredHTTP, WireDeliveryJournal]:
    admission = Admission(
        str(base / "admission.db"),
        lambda raw, signature: IDENTITY if signature == proof(raw) else None,
        lambda *_: replace(grant(ingress()), identity=IDENTITY),
    )
    raw = canonical(ingress())
    admission.ingest(raw, proof(raw))
    service = StoredHTTP(str(base / "service.db"), fault)
    journal = WireDeliveryJournal(
        str(base / "wire.db"),
        str(base / "journal.db"),
        service,
        admission,
        lambda raw, digest: raw == envelope() and digest == PAYLOAD.digest(),
        lambda account, destination: DEST
        if (account, destination) == ("account-1", "destination-1")
        else None,
        lambda request: True,
    )
    return admission, service, journal


def worker(base: str, fault: str) -> None:
    with patch.object(
        socket.socket, "connect", side_effect=AssertionError("forbidden network")
    ):
        a, s, j = prepare(Path(base), fault)
        try:
            if fault == "outer-gap":
                with patch.object(
                    j, "_observe", side_effect=lambda *args, **kwargs: os._exit(32)
                ):
                    j.send(envelope(), PAYLOAD)
            result = j.send(envelope(), PAYLOAD)
            print(
                json.dumps(
                    {
                        "state": result.state,
                        "message": result.message_id,
                        "conflict": result.conflict,
                    }
                )
            )
        finally:
            j.close()
            s.close()
            a.close()


class WireDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.admission, self.peer, self.journal = prepare(self.base)
        self.addCleanup(self.admission.close)
        self.addCleanup(self.peer.close)
        self.addCleanup(self.journal.close)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("forbidden network")
        )
        self.spy = self.network.start()
        self.addCleanup(self.network.stop)

    def tearDown(self) -> None:
        self.assertEqual(self.spy.call_count, 0)

    def counts(self) -> dict[str, int]:
        return dict(
            self.peer.db.execute("SELECT action,count(*) FROM calls GROUP BY action")
        )

    def child(
        self, fault: str = "", base: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                "from tests.test_wire_delivery import worker; import sys; worker(sys.argv[1],sys.argv[2])",
                str(self.base if base is None else base),
                fault,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_exact_actual_wire_bridge_and_recovery_only_reads(self) -> None:
        result = self.journal.send(envelope(), PAYLOAD)
        self.assertEqual(
            (result.state, result.file_id, result.message_id),
            ("content_confirmed", "F100", MESSAGE),
        )
        self.assertEqual(result.evidence_class, "slack_wire_content_observation")
        self.assertEqual(
            self.peer.db.execute(
                "SELECT content,channel,thread,text FROM files"
            ).fetchall(),
            [
                (
                    PAYLOAD.attachments[0].content,
                    "C100",
                    IDENTITY.thread_id,
                    PAYLOAD.text,
                )
            ],
        )
        self.journal.authorize_wire = lambda request: request.method == "GET"
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD).state, "content_confirmed"
        )
        self.assertEqual(
            {k: self.counts()[k] for k in ("allocate", "upload", "complete")},
            dict(allocate=1, upload=1, complete=1),
        )

    def test_lost_completion_ack_reads_exact_bytes_without_resend(self) -> None:
        self.peer.fault = "lost:complete"
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD).state, "content_confirmed"
        )
        self.peer.fault = ""
        result = self.child()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "content_confirmed")
        self.assertEqual(self.counts()["complete"], 1)

    def test_wrong_thread_and_partial_bytes_remain_unknown(self) -> None:
        self.journal.send(envelope(), PAYLOAD)
        self.peer.db.execute("UPDATE files SET thread='1700000000.000099'")
        self.assertEqual(self.journal.lookup(envelope(), PAYLOAD).state, "unknown")
        self.peer.db.execute(
            "UPDATE files SET thread=?,content=?", (IDENTITY.thread_id, b"partial")
        )
        self.assertEqual(self.journal.lookup(envelope(), PAYLOAD).state, "unknown")
        self.assertEqual(self.counts()["complete"], 1)

    def test_conflicting_exact_receipt_is_sticky(self) -> None:
        self.journal.send(envelope(), PAYLOAD)
        self.peer.db.execute("UPDATE files SET message='1700000002.000003'")
        result = self.journal.lookup(envelope(), PAYLOAD)
        self.assertTrue(result.conflict)
        self.assertEqual(result.state, "unknown")
        self.peer.db.execute("UPDATE files SET message=?", (MESSAGE,))
        calls = self.counts()
        self.assertTrue(self.journal.lookup(envelope(), PAYLOAD).conflict)
        self.assertEqual(self.counts(), calls)

    def test_missing_authority_denies_without_calls(self) -> None:
        self.journal.authorize = None
        with self.assertRaises(Rejected):
            self.journal.send(envelope(), PAYLOAD)
        self.assertEqual(self.counts(), {})
        self.assertEqual(
            self.journal.db.execute("SELECT count(*) FROM wire_deliveries").fetchone(),
            (0,),
        )

    def test_request_authorizer_cannot_revoke_or_redirect_before_effect(self) -> None:
        for mode in ("revoke", "redirect"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                a, s, j = prepare(Path(d))
                try:

                    def mutate(request: object) -> bool:
                        if mode == "revoke":
                            j.authorize = lambda *_: False
                        else:
                            j.resolve = lambda *_: replace(
                                DEST, thread_id="1700000000.000099"
                            )
                        return True

                    j.authorize_wire = mutate
                    try:
                        j.send(envelope(), PAYLOAD)
                    except (Rejected, ValueError):
                        pass
                    self.assertEqual(
                        s.db.execute("SELECT count(*) FROM calls").fetchone(), (0,)
                    )
                finally:
                    j.close()
                    s.close()
                    a.close()

    def test_scope_rebinding_and_altered_bytes_rejected(self) -> None:
        self.journal.send(envelope(), PAYLOAD)
        before = self.counts()
        self.journal.authorize = lambda *_: True
        for payload in (
            replace(PAYLOAD, text="other"),
            replace(
                PAYLOAD,
                attachments=(replace(PAYLOAD.attachments[0], content=b"other"),),
            ),
        ):
            with self.assertRaises(Rejected):
                self.journal.send(envelope(), payload)
        value = json.loads(envelope())
        value["payload"]["account_id"] = "account-2"
        self.journal.resolve = lambda *_: DEST
        with self.assertRaises(Rejected):
            self.journal.lookup(canonical(value), PAYLOAD)
        self.assertEqual(self.counts(), before)

    def test_rate_limit_is_retained_not_retry_authority(self) -> None:
        self.peer.fault = "rate:allocate"
        result = self.journal.send(envelope(), PAYLOAD)
        self.assertEqual(
            (result.state, result.retry_action, result.retry_after),
            ("unknown", "allocate", 7),
        )
        self.peer.fault = ""
        self.journal.send(envelope(), PAYLOAD)
        self.assertEqual(self.counts(), {"allocate": 1})

    def test_outer_reservation_crash_gap_never_starts_upload(self) -> None:
        result = self.child("outer-gap")
        self.assertEqual(result.returncode, 32, result.stderr)
        self.assertEqual(
            self.journal.db.execute("SELECT count(*) FROM wire_deliveries").fetchone(),
            (1,),
        )
        result = self.child()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "unknown")
        self.assertEqual(self.counts(), {})

    def test_crash_after_complete_recovers_actual_peer_once(self) -> None:
        result = self.child("after:complete")
        self.assertEqual(result.returncode, 32, result.stderr)
        result = self.child()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "content_confirmed")
        self.assertEqual(self.counts()["allocate"], 1)
        self.assertEqual(self.counts()["complete"], 1)

    def test_cancellation_preserves_outer_and_inner_fences(self) -> None:
        self.peer.fault = "cancel:upload"
        with self.assertRaises(KeyboardInterrupt):
            self.journal.send(envelope(), PAYLOAD)
        self.peer.fault = ""
        self.assertEqual(self.journal.send(envelope(), PAYLOAD).state, "unknown")
        self.assertEqual(self.counts().get("upload"), 1)
        self.assertNotIn("complete", self.counts())

    def test_concurrent_fresh_processes_share_one_send(self) -> None:
        args = [
            sys.executable,
            "-c",
            "from tests.test_wire_delivery import worker;import sys;worker(sys.argv[1],'')",
            str(self.base),
        ]
        children = [
            subprocess.Popen(
                args,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        try:
            for p in children:
                _, err = p.communicate(timeout=10)
                self.assertEqual(p.returncode, 0, err)
        finally:
            for p in children:
                if p.poll() is None:
                    p.kill()
                    p.wait()
        self.assertEqual(
            {k: self.counts()[k] for k in ("allocate", "upload", "complete")},
            dict(allocate=1, upload=1, complete=1),
        )

    def test_legacy_synthetic_store_cannot_be_adopted(self) -> None:
        legacy = ProviderJournal(str(self.base / "legacy.db"))
        legacy.close()
        with self.assertRaises(ValueError):
            WireDeliveryJournal(
                str(self.base / "legacy.db"), str(self.base / "other.db"), self.peer
            )

    def test_crashes_at_every_wire_phase_never_reissue_effects(self) -> None:
        for point in (
            "before:allocate",
            "after:allocate",
            "before:upload",
            "after:upload",
            "before:complete",
            "after:complete",
            "before:info",
            "after:replies",
            "after:download",
        ):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as d:
                base = Path(d)
                a, s, j = prepare(base)
                try:
                    result = self.child(point, base)
                    self.assertEqual(
                        result.returncode,
                        31 if point.startswith("before:") else 32,
                        result.stderr,
                    )
                    effects = dict(
                        s.db.execute(
                            "SELECT action,count(*) FROM calls WHERE action IN ('allocate','upload','complete') GROUP BY action"
                        )
                    )
                    recovered = self.child(base=base)
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    self.assertEqual(
                        dict(
                            s.db.execute(
                                "SELECT action,count(*) FROM calls WHERE action IN ('allocate','upload','complete') GROUP BY action"
                            )
                        ),
                        effects,
                    )
                    self.assertTrue(all(n == 1 for n in effects.values()))
                    expected = (
                        "content_confirmed"
                        if point
                        in (
                            "after:complete",
                            "before:info",
                            "after:replies",
                            "after:download",
                        )
                        else "unknown"
                    )
                    self.assertEqual(json.loads(recovered.stdout)["state"], expected)
                finally:
                    j.close()
                    s.close()
                    a.close()

    def test_revocation_between_readback_and_retention_cannot_publish(self) -> None:
        self.journal.send(envelope(), PAYLOAD)
        exchange = self.peer.exchange

        def revoke(request: Any) -> Any:
            result = exchange(request)
            if request.action == "download":
                self.journal.authorize = lambda *_: False
            return result

        with patch.object(self.peer, "exchange", side_effect=revoke):
            with self.assertRaises(Rejected):
                self.journal.lookup(envelope(), PAYLOAD)
        self.assertEqual(self.counts()["complete"], 1)

    def test_each_wire_action_revalidates_core_before_exchange(self) -> None:
        for action in ("allocate", "upload", "complete", "info", "replies", "download"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as d:
                a, s, j = prepare(Path(d))
                try:

                    def authorization(request: Any) -> bool:
                        if request.action == action:
                            j.authorize = lambda *_: False
                        return True

                    j.authorize_wire = authorization
                    try:
                        j.send(envelope(), PAYLOAD)
                    except (Rejected, ValueError):
                        pass
                    self.assertEqual(
                        s.db.execute(
                            "SELECT count(*) FROM calls WHERE action=?", (action,)
                        ).fetchone(),
                        (0,),
                    )
                finally:
                    j.close()
                    s.close()
                    a.close()

    def test_missing_wire_authorizer_does_not_consume_reservation(self) -> None:
        self.journal.authorize_wire = None
        with self.assertRaises(Rejected):
            self.journal.send(envelope(), PAYLOAD)
        self.assertEqual(
            self.journal.db.execute("SELECT count(*) FROM wire_deliveries").fetchone(),
            (0,),
        )
        self.assertEqual(self.counts(), {})

    def test_deliberate_resend_mutant_is_detected_by_independent_effect_oracle(
        self,
    ) -> None:
        source = (ROOT / "tether/wire_delivery.py").read_text()
        self.assertEqual(source.count("begin=not existing"), 1)
        module = types.ModuleType("tether.wire_delivery_mutant")
        sys.modules[module.__name__] = module
        self.addCleanup(lambda: sys.modules.pop(module.__name__, None))
        exec(
            compile(
                source.replace("begin=not existing", "begin=True"),
                "wire-mutant",
                "exec",
            ),
            module.__dict__,
        )
        self.assertEqual(self.child("outer-gap").returncode, 32)
        mutant = module.WireDeliveryJournal(
            str(self.base / "wire.db"),
            str(self.base / "journal.db"),
            self.peer,
            self.admission,
            self.journal.authorize,
            self.journal.resolve,
            lambda _: True,
        )
        try:
            mutant.send(envelope(), PAYLOAD)
            with self.assertRaises(AssertionError):
                self.assertEqual(self.counts(), {})
            self.assertEqual(self.counts()["complete"], 1)
        finally:
            mutant.close()

    def test_retained_outer_binding_cannot_be_erased(self) -> None:
        self.journal.send(envelope(), PAYLOAD)
        with self.assertRaises(sqlite3.IntegrityError):
            self.journal.db.execute("DELETE FROM wire_deliveries")
        with self.assertRaises(sqlite3.IntegrityError):
            self.journal.db.execute("UPDATE wire_deliveries SET payload_digest='other'")

    def test_inner_conflict_committed_before_outer_lock_is_not_stale_success(
        self,
    ) -> None:
        self.journal.send(envelope(), PAYLOAD)
        original = self.journal.db
        base = self.base

        class LockBoundary:
            def execute(self, sql: str, *args: Any) -> Any:
                if sql == "BEGIN IMMEDIATE":
                    # Another caller commits its inner conflict before this
                    # caller can acquire the outer retention lock.
                    with closing(
                        sqlite3.connect(base / "journal.db", isolation_level=None)
                    ) as concurrent:
                        concurrent.execute("UPDATE uploads SET conflict=1")
                return original.execute(sql, *args)

            def commit(self) -> None:
                original.commit()

            def rollback(self) -> None:
                original.rollback()

        with patch.object(self.journal, "db", LockBoundary()):
            result = self.journal.lookup(envelope(), PAYLOAD)
        self.assertEqual(result.state, "unknown")
        self.assertTrue(result.conflict)
        self.assertIsNone(result.message_id)
        self.assertEqual(
            original.execute("SELECT conflict FROM wire_deliveries").fetchone(), (1,)
        )

    def test_request_authorizer_cannot_pass_newly_retained_conflict(self) -> None:
        for store, table in (("wire.db", "wire_deliveries"), ("journal.db", "uploads")):
            with self.subTest(store=store), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                admission, peer, journal = prepare(base)
                try:
                    journal.send(envelope(), PAYLOAD)
                    before = peer.db.execute("SELECT count(*) FROM calls").fetchone()

                    def authority(request: Any) -> bool:
                        with closing(
                            sqlite3.connect(base / store, isolation_level=None)
                        ) as concurrent:
                            concurrent.execute(f"UPDATE {table} SET conflict=1")
                        return True

                    journal.authorize_wire = authority
                    result = journal.lookup(envelope(), PAYLOAD)
                    self.assertEqual(result.state, "unknown")
                    self.assertTrue(result.conflict)
                    self.assertEqual(
                        peer.db.execute("SELECT count(*) FROM calls").fetchone(), before
                    )
                finally:
                    journal.close()
                    peer.close()
                    admission.close()
