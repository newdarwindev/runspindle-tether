"""Append-only explicit resolution with real stores and independent wire peer."""

import asyncio
import hashlib
import socket
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_slack_upload import READBACK_CANARY
from tests.test_wire_delivery import PAYLOAD, ROOT, envelope, prepare
from tether.admission import Rejected, canonical
from tether.sanitization import Sanitizer
from tether.wire_resolution import ResolutionDecision, ResolutionJournal

MESSAGE = "1700000002.000003"


class ResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.a, self.peer, self.bridge = prepare(self.base)
        self.addCleanup(self.a.close)
        self.addCleanup(self.peer.close)
        self.addCleanup(self.bridge.close)
        self.socket = patch.object(
            socket, "socket", side_effect=AssertionError("network forbidden")
        )
        self.spy = self.socket.start()
        self.addCleanup(self.socket.stop)
        self.bridge.send(envelope(), PAYLOAD)
        self.peer.db.execute("UPDATE files SET message=?", (MESSAGE,))
        self.assertTrue(self.bridge.lookup(envelope(), PAYLOAD).conflict)
        self.resolution = ResolutionJournal(
            str(self.base / "resolution.db"), self.bridge
        )
        self.addCleanup(self.resolution.close)
        self.snapshot = self.resolution.conflict_snapshot(envelope(), PAYLOAD)
        self.decision = ResolutionDecision(
            "decision-1",
            "policy-1",
            "resolver-1",
            hashlib.sha256(self.snapshot).hexdigest(),
            "a" * 64,
            "F100",
            MESSAGE,
        )
        self.resolution.authorize_resolution = (
            lambda raw, digest, decision: raw == envelope()
            and digest == PAYLOAD.digest()
            and decision == self.decision.encode()
        )
        self.before = self.effects()

    def tearDown(self) -> None:
        self.assertEqual(self.spy.call_count, 0)
        self.assertEqual(self.effects(), self.before)

    def effects(self) -> list[tuple[str, int]]:
        return self.peer.db.execute(
            "SELECT action,count(*) FROM calls WHERE action IN ('allocate','upload','complete') GROUP BY action"
        ).fetchall()

    def resolve(self) -> object:
        return self.resolution.resolve(envelope(), PAYLOAD, self.decision)

    def test_authorizer_errors_and_cancellations_do_not_escape_sensitive_text(
        self,
    ) -> None:
        canary = "synthetic-resolution-secret"
        for category in (
            ValueError,
            asyncio.CancelledError,
            GeneratorExit,
            KeyboardInterrupt,
            SystemExit,
            BaseException,
        ):
            with self.subTest(category=category.__name__):
                original = category(canary)
                original.add_note(canary)
                original.__cause__ = RuntimeError(canary)
                original.__context__ = RuntimeError(canary)

                def fail(*_: object) -> bool:
                    raise original

                self.resolution.authorize_resolution = fail
                before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()
                expected = Rejected if category is ValueError else category
                with self.assertRaises(expected) as caught:
                    self.resolve()
                self.assertNotIn(canary, str(caught.exception))
                self.assertIsNot(caught.exception, original)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertFalse(getattr(caught.exception, "__notes__", None))
                self.assertEqual(
                    self.peer.db.execute("SELECT count(*) FROM calls").fetchone(),
                    before,
                )
                self.assertEqual(
                    self.resolution.db.execute(
                        "SELECT count(*) FROM decisions"
                    ).fetchone(),
                    (0,),
                )
                self.assertFalse(self.resolution.db.in_transaction)
                self.assertFalse(self.bridge.db.in_transaction)
                self.assertFalse(self.resolution.inner.in_transaction)
                for path in self.base.iterdir():
                    if path.is_file():
                        self.assertNotIn(canary.encode(), path.read_bytes())

    def test_late_authorizer_cancellation_after_readback_keeps_stores_unchanged(
        self,
    ) -> None:
        before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()[0]

        def cancel_after_read(*_: object) -> bool:
            if (
                self.peer.db.execute("SELECT count(*) FROM calls").fetchone()[0]
                > before
            ):
                raise KeyboardInterrupt("synthetic-private-readback-context")
            return True

        self.resolution.authorize_resolution = cancel_after_read
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.resolve()
        self.assertNotIn("synthetic-private", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (0,),
        )
        self.assertEqual(self.effects(), self.before)
        self.assertFalse(self.resolution.db.in_transaction)

    def test_cancellation_inside_commit_lock_rolls_back_without_sensitive_chain(
        self,
    ) -> None:
        def cancel_locked(*_: object) -> bool:
            if self.resolution.db.in_transaction:
                raise SystemExit("synthetic-locked-secret")
            return True

        self.resolution.authorize_resolution = cancel_locked
        with self.assertRaises(SystemExit) as caught:
            self.resolve()
        self.assertNotIn("synthetic-locked-secret", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        with sqlite3.connect(self.base / "resolution.db") as independent:
            self.assertEqual(
                independent.execute("SELECT count(*) FROM decisions").fetchone(), (0,)
            )
        self.assertFalse(self.resolution.db.in_transaction)
        self.assertFalse(self.bridge.db.in_transaction)
        self.assertFalse(self.resolution.inner.in_transaction)
        self.assertEqual(self.effects(), self.before)

    def test_restoring_exception_propagation_mutation_exposes_canary(self) -> None:
        path = ROOT / "tether/wire_resolution.py"
        source = path.read_text()
        needle = "except Exception:\n            pass"
        self.assertEqual(source.count(needle), 1)
        module = types.ModuleType("resolution_exception_mutant")
        sys.modules[module.__name__] = module
        self.addCleanup(lambda: sys.modules.pop(module.__name__, None))
        exec(
            compile(
                source.replace(needle, "except Exception:\n            raise"),
                str(path),
                "exec",
            ),
            module.__dict__,
        )

        def fail(*_: object) -> bool:
            raise ValueError("synthetic-mutant-secret")

        mutant = module.ResolutionJournal(
            str(self.base / "mutant-errors.db"), self.bridge, fail
        )
        try:
            with self.assertRaises(ValueError) as caught:
                mutant.resolve(
                    envelope(),
                    PAYLOAD,
                    module.ResolutionDecision(**asdict(self.decision)),
                )
            self.assertIn("synthetic-mutant-secret", str(caught.exception))
        finally:
            mutant.close()

    def test_readback_routing_rejects_configured_secret_before_resolution(self) -> None:
        self.bridge.sanitizer = Sanitizer((READBACK_CANARY,))
        self.peer.fault = "secret:download"
        offset = len(self.peer.calls)
        result = self.resolution.resolve(envelope(), PAYLOAD, self.decision)
        self.assertEqual([call.action for call in self.peer.calls[offset:]], ["info"])
        self.assertEqual(result.state, "unknown")
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (0,),
        )
        self.peer.fault = ""
        self.assertEqual(
            self.resolution.resolve(envelope(), PAYLOAD, self.decision).state,
            "independently_reconciled_under_decision",
        )

    def test_exact_resolution_preserves_original_conflict_and_reobserves(self) -> None:
        first = self.resolution.resolve(envelope(), PAYLOAD, self.decision)
        self.assertEqual(first.state, "independently_reconciled_under_decision")
        self.assertEqual((first.file_id, first.message_id), ("F100", MESSAGE))
        self.assertEqual(
            first.decision_sha256, hashlib.sha256(self.decision.encode()).hexdigest()
        )
        self.assertEqual(
            self.resolution.conflict_snapshot(envelope(), PAYLOAD), self.snapshot
        )
        self.assertTrue(self.bridge.lookup(envelope(), PAYLOAD).conflict)
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (1,),
        )
        self.peer.db.execute("UPDATE files SET content=x'00'")
        self.assertEqual(
            self.resolution.resolve(envelope(), PAYLOAD, self.decision).state, "unknown"
        )
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (1,),
        )

    def test_missing_dedicated_authority_never_reads(self) -> None:
        before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()
        self.resolution.authorize_resolution = None
        with self.assertRaises(Rejected):
            self.resolve()
        self.assertEqual(
            self.peer.db.execute("SELECT count(*) FROM calls").fetchone(), before
        )

    def test_mutated_decision_fields_never_inherit_authority(self) -> None:
        values = {
            "decision_id": "decision-2",
            "policy_ref": "policy-2",
            "authorization_ref": "resolver-2",
            "conflict_sha256": "b" * 64,
            "core_resolution_sha256": "b" * 64,
            "file_id": "F101",
            "message_id": "1700000003.000004",
            "version": "other",
        }
        before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()
        for field, value in values.items():
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.resolution.resolve(
                    envelope(), PAYLOAD, replace(self.decision, **{field: value})
                )
        self.assertEqual(
            self.peer.db.execute("SELECT count(*) FROM calls").fetchone(), before
        )

    def test_current_authority_revoked_inside_request_callback(self) -> None:
        def revoke(request: object) -> bool:
            self.resolution.authorize_resolution = lambda *_: False
            return True

        self.bridge.authorize_wire = revoke
        before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()
        with self.assertRaises(Rejected):
            self.resolve()
        self.assertEqual(
            self.peer.db.execute("SELECT count(*) FROM calls").fetchone(), before
        )
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (0,),
        )

    def test_wrong_thread_partial_content_and_wrong_selected_message_unknown(
        self,
    ) -> None:
        for sql in (
            "UPDATE files SET thread='1700000000.000999'",
            "UPDATE files SET content=x'00'",
            "UPDATE files SET message='1700000003.000004'",
        ):
            with self.subTest(sql=sql):
                self.peer.db.execute(sql)
                self.assertEqual(
                    self.resolution.resolve(envelope(), PAYLOAD, self.decision).state,
                    "unknown",
                )
                self.peer.db.execute(
                    "UPDATE files SET thread='1700000000.000001',content=?,message=?",
                    (PAYLOAD.attachments[0].content, MESSAGE),
                )
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (0,),
        )

    def test_competing_decision_cannot_replace_winner_even_with_authority(self) -> None:
        self.resolve()
        self.resolution.authorize_resolution = lambda *_: True
        other = replace(self.decision, decision_id="decision-2")
        before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()
        with self.assertRaisesRegex(Rejected, "ownership"):
            self.resolution.resolve(envelope(), PAYLOAD, other)
        self.assertEqual(
            self.peer.db.execute("SELECT count(*) FROM calls").fetchone(), before
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.resolution.db.execute("DELETE FROM decisions")
        with self.assertRaises(sqlite3.IntegrityError):
            self.resolution.db.execute("UPDATE decisions SET decision_id='changed'")

    def test_readback_cancellation_leaves_no_decision_and_never_retries_effect(
        self,
    ) -> None:
        self.peer.fault = "cancel:download"
        with self.assertRaises(KeyboardInterrupt):
            self.resolve()
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (0,),
        )
        self.peer.fault = ""
        self.assertEqual(
            self.resolution.resolve(envelope(), PAYLOAD, self.decision).state,
            "independently_reconciled_under_decision",
        )

    def test_fresh_process_lost_resolution_response_repeats_readback_only(self) -> None:
        expected = self.base / "decision.json"
        expected.write_bytes(canonical(asdict(self.decision)))
        code = """import json,socket,sys
from pathlib import Path
from unittest.mock import patch
from tests.test_wire_delivery import prepare,envelope,PAYLOAD
from tether.wire_resolution import ResolutionJournal,ResolutionDecision
with patch.object(socket,"socket",side_effect=AssertionError("network")):
 a,p,b=prepare(Path(sys.argv[1])); d=ResolutionDecision(**json.loads(Path(sys.argv[2]).read_bytes()))
 r=ResolutionJournal(str(Path(sys.argv[1])/"resolution.db"),b,lambda raw,digest,decision: raw==envelope() and digest==PAYLOAD.digest() and decision==d.encode())
 try:
  result=r.resolve(envelope(),PAYLOAD,d)
  if sys.argv[3]=="lost": __import__("os")._exit(32)
  print(result.state)
 finally:r.close();b.close();p.close();a.close()
"""
        for mode, expected_code in (("lost", 32), ("recovered", 0)):
            result = subprocess.run(
                [
                    sys.executable,
                    *(["-O"] if sys.flags.optimize else []),
                    "-c",
                    code,
                    str(self.base),
                    str(expected),
                    mode,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, expected_code, result.stderr)
            if mode == "recovered":
                self.assertEqual(
                    result.stdout.strip(), "independently_reconciled_under_decision"
                )
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (1,),
        )

    def test_resolution_authority_revoked_at_commit_boundary(self) -> None:
        original = self.resolution.db
        owner = self.resolution

        class Boundary:
            def execute(self, sql: str, *args: Any) -> Any:
                if sql == "BEGIN IMMEDIATE":
                    owner.authorize_resolution = lambda *_: False
                return original.execute(sql, *args)

            def commit(self) -> None:
                original.commit()

            def rollback(self) -> None:
                original.rollback()

        with patch.object(owner, "db", Boundary()), self.assertRaises(Rejected):
            self.resolve()
        self.assertEqual(
            original.execute("SELECT count(*) FROM decisions").fetchone(), (0,)
        )

    def test_unretained_file_denied_even_by_broad_resolver(self) -> None:
        self.resolution.authorize_resolution = lambda *_: True
        with self.assertRaisesRegex(Rejected, "retained allocation"):
            self.resolution.resolve(
                envelope(), PAYLOAD, replace(self.decision, file_id="F999")
            )

    def test_no_original_conflict_cannot_be_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            a, p, b = prepare(Path(directory))
            try:
                b.send(envelope(), PAYLOAD)
                r = ResolutionJournal(
                    str(Path(directory) / "resolution.db"), b, lambda *_: True
                )
                try:
                    with self.assertRaisesRegex(Rejected, "retained conflict"):
                        r.resolve(envelope(), PAYLOAD, self.decision)
                finally:
                    r.close()
            finally:
                b.close()
                p.close()
                a.close()

    def test_selected_message_mutation_is_detected_by_independent_store(self) -> None:
        path = ROOT / "tether/wire_resolution.py"
        source = path.read_text()
        old = "or result.facts.message.message_ts != decision.message_id"
        self.assertIn(old, source)
        module = types.ModuleType("wire_resolution_mutant")
        sys.modules[module.__name__] = module
        self.addCleanup(lambda: sys.modules.pop(module.__name__, None))
        exec(
            compile(source.replace(old, "or False", 1), str(path), "exec"),
            module.__dict__,
        )
        mutant = module.ResolutionJournal(
            str(self.base / "mutant.db"), self.bridge, lambda *_: True
        )
        try:
            wrong = module.ResolutionDecision(
                **{**asdict(self.decision), "message_id": "1700000003.000004"}
            )
            observed = mutant.resolve(envelope(), PAYLOAD, wrong)
            actual = self.peer.db.execute("SELECT message FROM files").fetchone()[0]
            with self.assertRaises(AssertionError):
                self.assertEqual(observed.message_id, actual)
            self.assertEqual(observed.state, "independently_reconciled_under_decision")
        finally:
            mutant.close()

    def test_concurrent_authorized_decisions_have_one_immutable_owner(self) -> None:
        def attempt(index: int) -> str:
            a, p, b = prepare(self.base)
            r = ResolutionJournal(str(self.base / "resolution.db"), b, lambda *_: True)
            try:
                try:
                    return r.resolve(
                        envelope(),
                        PAYLOAD,
                        replace(self.decision, decision_id=f"decision-{index}"),
                    ).state
                except Rejected:
                    return "denied"
            finally:
                r.close()
                b.close()
                p.close()
                a.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (2, 3)))
        self.assertEqual(
            sorted(results), ["denied", "independently_reconciled_under_decision"]
        )
        self.assertEqual(
            self.resolution.db.execute("SELECT count(*) FROM decisions").fetchone(),
            (1,),
        )
        self.assertEqual(
            self.resolution.conflict_snapshot(envelope(), PAYLOAD), self.snapshot
        )

    def test_tampered_upload_schema_rejected_without_readback(self) -> None:
        before = self.peer.db.execute("SELECT count(*) FROM calls").fetchone()
        self.resolution.inner.execute("DROP TRIGGER upload_conflict_retained")
        with self.assertRaisesRegex(ValueError, "schema"):
            ResolutionJournal(
                str(self.base / "other-resolution.db"), self.bridge, lambda *_: True
            )
        self.assertEqual(
            self.peer.db.execute("SELECT count(*) FROM calls").fetchone(), before
        )

    def test_selected_ids_are_bounded_and_strictly_typed(self) -> None:
        for field, value in (
            ("file_id", None),
            ("message_id", 42),
            ("file_id", "F" + "A" * 300),
            ("message_id", "1" * 100 + ".000001"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(Rejected):
                invalid: dict[str, Any] = {field: value}
                replace(self.decision, **invalid).encode()
