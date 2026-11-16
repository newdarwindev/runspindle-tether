"""Actual signed invalidation and v2 SQLite; no provider calls or live authority."""

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_slack_feedback import MESSAGE, Harness, feedback
from tests.test_slack_ingress import ROUTE, callback, headers, wire
from tether.admission import Rejected

ROOT = Path(__file__).resolve().parents[1]


def mutation(
    kind: str = "message_changed",
    message: str = MESSAGE,
    event_id: str = "EvMUTATION",
    **changes: Any,
) -> bytes:
    value = callback()
    event: dict[str, Any] = dict(
        type="message",
        subtype=kind,
        hidden=True,
        channel=ROUTE.channel_id,
        ts="1900000000.000099",
    )
    if kind == "message_changed":
        event["message"] = dict(
            type="message",
            user=ROUTE.actor_id,
            ts=message,
            text="private-synthetic-text-never-retain",
            edited=dict(user="UEDITOR", ts="1900000000.000099"),
        )
    else:
        event["deleted_ts"] = message
    event.update(changes)
    value["event"] = event
    value["event_id"] = event_id
    return wire(value)


class InvalidationTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.h = Harness(self.root)
        self.addCleanup(self.h.close)
        self.allowed = True
        self.h.app.store.authorize_invalidation = (
            lambda obs: self.allowed and obs["namespace"] == self.h.app.namespace
        )
        self.effects = list(self.h.provider.requests)
        self.admissions = self.h.ingress.admission.db.total_changes
        self.addCleanup(self.check_effects)
        forbidden = patch.object(
            socket, "socket", side_effect=AssertionError("network forbidden")
        )
        spy = forbidden.start()
        self.addCleanup(forbidden.stop)
        self.addCleanup(spy.assert_not_called)

    def check_effects(self) -> None:
        self.assertEqual(self.h.provider.requests, self.effects)
        self.assertEqual(self.h.ingress.admission.db.total_changes, self.admissions)

    def retain(self) -> str:
        raw = feedback()
        return self.h.app.ingest(raw, headers(raw))

    def invalidate(self, raw: bytes, proof: Any = None) -> str:
        with patch.object(
            subprocess, "Popen", side_effect=AssertionError("execution forbidden")
        ) as spawned:
            result = self.h.app.invalidate(
                raw, headers(raw) if proof is None else proof
            )
            spawned.assert_not_called()
            return result

    def evidence(self) -> dict[str, Any]:
        return self.h.app.store.evidence(self.h.app.namespace, MESSAGE)

    def test_changed_and_deleted_are_permanent_not_authored_revisions(self) -> None:
        self.retain()
        before = self.evidence()["revisions"]
        changed = mutation()
        self.assertEqual(self.invalidate(changed), "invalidated")
        self.assertEqual(self.invalidate(changed), "duplicate")
        deleted = mutation("message_deleted", event_id="EvDELETE")
        self.assertEqual(self.invalidate(deleted), "invalidated")
        value = self.evidence()
        self.assertEqual(value["state"], "invalidated")
        self.assertEqual(value["revisions"], before)
        self.assertEqual(value["revisions"][0]["event"]["actor_id"], ROUTE.actor_id)
        self.assertEqual(
            value["provider_invalidation"],
            dict(
                event_id="EvMUTATION",
                cause="message_changed",
                body_sha256=hashlib.sha256(changed).hexdigest(),
            ),
        )
        self.assertNotIn(
            b"private-synthetic-text-never-retain",
            (self.root / "feedback.sqlite").read_bytes(),
        )
        self.assertNotIn(b"UEDITOR", (self.root / "feedback.sqlite").read_bytes())
        with self.assertRaisesRegex(Rejected, "permanently invalidated"):
            self.retain()

    def test_precreate_delete_without_actor_or_thread_blocks_late_create(self) -> None:
        raw = mutation("message_deleted")
        self.assertEqual(self.invalidate(raw), "invalidated")
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_heads_v2"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_revisions"
            ).fetchone()[0],
            0,
        )
        with self.assertRaisesRegex(Rejected, "permanently invalidated"):
            self.retain()
        self.assertIsNone(json.loads(raw)["event"].get("user"))

    def test_wrong_signature_routing_and_identity_hints_have_no_effect(self) -> None:
        raw = mutation()
        changed = json.loads(raw)
        cases = []
        for field, wrong in (("user", "UOTHER"), ("thread_ts", "1900000000.999999")):
            v = json.loads(raw)
            v["event"]["message"][field] = wrong
            cases.append(wire(v))
        for where, field, wrong in (
            ("event", "channel", "COTHER"),
            ("root", "team_id", "TOTHER"),
            ("root", "api_app_id", "AOTHER"),
        ):
            v = json.loads(raw)
            (v if where == "root" else v["event"])[field] = wrong
            cases.append(wire(v))
        changed["event"]["previous_message"] = dict(ts="1900000000.999999")
        cases.append(wire(changed))
        with patch.object(
            self.h.journal,
            "retained_target",
            side_effect=AssertionError("must verify signature first"),
        ) as target:
            with self.assertRaises(ValueError):
                self.invalidate(raw, headers(raw, secret=b"synthetic-wrong-key"))
            target.assert_not_called()
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.invalidate(case)
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_invalidations"
            ).fetchone()[0],
            0,
        )

    def test_missing_or_revoked_invalidation_authority_cannot_fence(self) -> None:
        self.retain()
        self.h.app.store.authorize_invalidation = None
        with self.assertRaises(ValueError):
            self.invalidate(mutation())
        calls = []

        def revoked(obs: Any) -> bool:
            calls.append(obs)
            return len(calls) == 1

        self.h.app.store.authorize_invalidation = revoked
        with self.assertRaisesRegex(Rejected, "authority denied"):
            self.invalidate(mutation())
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.evidence()["state"], "active")
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_invalidations"
            ).fetchone()[0],
            0,
        )

    def test_event_collision_fences_both_without_retargeting(self) -> None:
        self.retain()
        original = self.evidence()["revisions"]
        first = mutation()
        other = "1900000000.777777"
        self.assertEqual(self.invalidate(first), "invalidated")
        self.assertEqual(self.invalidate(mutation(message=other)), "conflict")
        db = self.h.app.store.db
        rows = db.execute(
            "SELECT message,digest FROM feedback_invalidation_events"
        ).fetchall()
        self.assertEqual(rows, [(MESSAGE, hashlib.sha256(first).hexdigest())])
        self.assertTrue(self.h.app.store.invalidated(self.h.app.namespace, other))
        self.assertEqual(self.evidence()["revisions"], original)
        self.assertEqual(
            db.execute("SELECT count(*) FROM feedback_heads_v2").fetchone()[0], 1
        )
        self.assertEqual(self.invalidate(mutation("message_deleted")), "conflict")
        self.assertEqual(
            rows,
            db.execute(
                "SELECT message,digest FROM feedback_invalidation_events"
            ).fetchall(),
        )

    def test_capacity_saturates_store_without_eviction_or_reset(self) -> None:
        self.retain()
        import tether.feedback as store_module

        with patch.object(store_module, "MAX_INVALIDATIONS", 1):
            self.invalidate(mutation(message="1900000000.888888"))
            self.assertEqual(
                self.invalidate(mutation(event_id="EvSECOND")), "saturated"
            )
        self.assertEqual(self.evidence()["state"], "invalidated")
        self.assertEqual(
            self.evidence()["provider_invalidation"]["cause"], "store_saturated"
        )
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_invalidations"
            ).fetchone()[0],
            1,
        )
        with self.assertRaisesRegex(Rejected, "permanently invalidated"):
            self.retain()

    def test_fence_insert_failure_rolls_back_all_invalidation_state(self) -> None:
        self.h.app.store.db.execute(
            "CREATE TEMP TRIGGER fail_event BEFORE INSERT ON feedback_invalidation_events BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;"
        )
        with self.assertRaises(Exception):
            self.invalidate(mutation())
        self.assertFalse(self.h.app.store.db.in_transaction)
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_invalidations"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT blocked FROM feedback_invalidation_state"
            ).fetchone()[0],
            0,
        )
        self.h.app.store.db.execute("DROP TRIGGER fail_event")
        self.assertEqual(self.retain(), "retained")

    def test_saturation_write_failure_rolls_back_without_dropping_a_fence(self) -> None:
        self.h.app.store.db.execute(
            "CREATE TEMP TRIGGER fail_saturation BEFORE UPDATE ON feedback_invalidation_state BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;"
        )
        with (
            patch("tether.feedback.MAX_INVALIDATIONS", 0),
            self.assertRaises(Exception),
        ):
            self.invalidate(mutation())
        self.assertFalse(self.h.app.store.db.in_transaction)
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT blocked FROM feedback_invalidation_state"
            ).fetchone()[0],
            0,
        )
        self.h.app.store.db.execute("DROP TRIGGER fail_saturation")
        with patch("tether.feedback.MAX_INVALIDATIONS", 0):
            self.assertEqual(self.invalidate(mutation()), "saturated")
        with self.assertRaisesRegex(Rejected, "permanently invalidated"):
            self.retain()

    def test_fresh_process_precreate_and_existing_fences_survive(self) -> None:
        for mode in ("precreate", "retained", "saturated"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary)
                    h = Harness(path)
                    try:
                        h.app.store.authorize_invalidation = lambda obs: True
                        if mode != "precreate":
                            raw = feedback()
                            h.app.ingest(raw, headers(raw))
                        raw = mutation("message_deleted")
                        if mode == "saturated":
                            with patch("tether.feedback.MAX_INVALIDATIONS", 0):
                                h.app.invalidate(raw, headers(raw))
                        else:
                            h.app.invalidate(raw, headers(raw))
                    finally:
                        h.close()
                    code = """
import json,socket,sys
from pathlib import Path
from unittest.mock import patch
from tests.test_slack_feedback import Harness, feedback, headers, MESSAGE
h=Harness(Path(sys.argv[1]), False)
try:
 with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
  raw=feedback()
  try: h.app.ingest(raw,headers(raw))
  except ValueError: pass
  else: raise RuntimeError('late resurrection')
  value=None if sys.argv[2]=='precreate' else h.app.store.evidence(h.app.namespace,MESSAGE)['state']
  print(json.dumps(value))
finally: h.close()
"""
                    child = subprocess.run(
                        [sys.executable, "-O", "-c", code, str(path), mode],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    self.assertEqual(child.returncode, 0, child.stderr)
                    self.assertEqual(
                        json.loads(child.stdout),
                        None if mode == "precreate" else "invalidated",
                    )

    def test_removed_read_fence_mutation_exposes_active_invalidated_evidence(
        self,
    ) -> None:
        self.retain()
        self.invalidate(mutation())
        with patch.object(self.h.app.store, "invalidation", return_value=None):
            self.assertEqual(self.evidence()["state"], "active")
        self.assertEqual(self.evidence()["state"], "invalidated")
