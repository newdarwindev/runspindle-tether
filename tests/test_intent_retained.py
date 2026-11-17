"""Actual SQLite retained-export checks; fake transport/authority, no provider."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_intent import event, options
from tether.admission import Admission, Grant, Identity, Rejected, canonical
from tether.intent import expected_task_id, export_retained_intent

IDENTITY = Identity("Utest", "Wtest", "Ctest", "1700000000.000000")
ROOT = Path(__file__).resolve().parents[1]


class RetainedIntentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "ingress.sqlite")
        self.allowed: dict[str, Grant] = {}
        self.app = Admission(
            self.path,
            lambda raw, proof: IDENTITY,
            lambda identity, digest: self.allowed.get(digest),
        )
        self.addCleanup(self.app.close)
        self.raw = canonical(event())
        self.network = patch(
            "socket.socket", side_effect=AssertionError("forbidden network")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def retain(self, value: dict[str, Any]) -> bytes:
        raw: bytes = canonical(value)
        args = options(value["revision"])
        source = {
            key: value[key]
            for key in (
                "actor_id",
                "workspace_id",
                "channel_id",
                "thread_id",
                "message_id",
            )
        }
        source.update(app_id="Atest", account_id="acct-test")
        g = Grant(
            IDENTITY,
            hashlib.sha256(raw).hexdigest(),
            expected_task_id(source),
            value["revision"],
            args["binding"]["operation_id"],
            "policy-1",
            "host-test",
            1,
            "legacy-grant-not-v3",
            "slack-test",
        )
        self.allowed[g.event_digest] = g
        self.app.ingest(raw, None)
        return raw

    def snapshot(self) -> list[str]:
        with closing(sqlite3.connect(self.path)) as db:
            return list(db.iterdump())

    def test_current_retained_export_readonly_and_new_grant_reference(self) -> None:
        self.retain(event())
        before = self.snapshot()
        wire = export_retained_intent(self.app, self.raw, **options())
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.app.db.in_transaction)
        obj = json.loads(wire)
        self.assertEqual(obj["scoped"]["request"]["payload"]["grant_ref"], "v3-grant-1")
        self.assertNotIn(b"legacy-grant-not-v3", wire)
        self.assertNotIn(b"synthetic", wire)

    def test_missing_changed_raw_and_mirrored_reject(self) -> None:
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, self.raw, **options())
        self.retain(event())
        changed = event(text="different")
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, canonical(changed), **options())
        self.app.record_mirror(
            "Wtest", "Ctest", "1700000000.000000", "1700000000.000001"
        )
        before = self.snapshot()
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, self.raw, **options())
        self.assertEqual(self.snapshot(), before)

    def test_global_delivery_conflict_cannot_export_different_source(self) -> None:
        self.retain(event())
        changed = event()
        changed["message_id"] = "other-message"
        with self.assertRaises(Rejected):
            self.retain(changed)
        args = options()
        source = dict(
            json.loads(export_retained_intent(self.app, self.raw, **args))["event"][
                "source"
            ]
        )
        source["message_id"] = "other-message"
        args["binding"]["task_id"] = expected_task_id(source)
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, canonical(changed), **args)

    def test_current_head_fence_and_delete_tombstone(self) -> None:
        self.retain(event())
        first = export_retained_intent(self.app, self.raw, **options())
        second_raw = self.retain(event(2, "edit", "replacement"))
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, self.raw, **options())
        second = export_retained_intent(
            self.app, second_raw, **options(2), previous_wire=first
        )
        third_raw = self.retain(event(3, "delete", ""))
        third = export_retained_intent(
            self.app, third_raw, **options(3), previous_wire=second
        )
        self.assertEqual(json.loads(third)["event"]["kind"], "delete")
        with self.assertRaises(Rejected):
            export_retained_intent(
                self.app, second_raw, **options(2), previous_wire=first
            )
        with self.assertRaises(Rejected):
            self.retain(event(4, "edit", "resurrect"))

    def test_missed_exports_remain_blocked_not_silently_reconstructed(self) -> None:
        # Models admission ahead of export after a crash/offline period. There is
        # no durable ordered semantic outbox here; do not claim recovery works.
        self.retain(event())
        second = self.retain(event(2, "edit", "replacement"))
        before = self.snapshot()
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, self.raw, **options())
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, second, **options(2))
        self.assertEqual(self.snapshot(), before)
        third = self.retain(event(3, "delete", ""))
        with self.assertRaises(Rejected):
            export_retained_intent(self.app, third, **options(3))

    def test_record_corruption_rejects_without_repairs(self) -> None:
        mutations = [
            "UPDATE sources SET task='wrong'",
            "UPDATE deliveries SET digest='wrong'",
            "UPDATE revisions SET scope='wrong'",
            "UPDATE revisions SET kind='delete'",
            "UPDATE revisions SET envelope='{}'",
            "UPDATE heads SET deleted=1",
        ]
        for sql in mutations:
            with self.subTest(sql=sql):
                app = Admission(
                    ":memory:",
                    lambda raw, proof: IDENTITY,
                    lambda identity, digest: self.allowed.get(digest),
                )
                self.retain(event())
                app.ingest(self.raw, None)
                app.db.execute(sql)
                app.db.commit()
                before = list(app.db.iterdump())
                try:
                    with self.assertRaises(Rejected):
                        export_retained_intent(app, self.raw, **options())
                    self.assertEqual(list(app.db.iterdump()), before)
                    self.assertFalse(app.db.in_transaction)
                finally:
                    app.close()

    def test_no_nested_transaction_or_legacy_task_adoption(self) -> None:
        self.retain(event())
        self.app.db.execute("BEGIN")
        try:
            with self.assertRaises(Rejected):
                export_retained_intent(self.app, self.raw, **options())
            self.assertTrue(self.app.db.in_transaction)
        finally:
            self.app.db.rollback()
        app = Admission(
            ":memory:",
            lambda raw, proof: IDENTITY,
            lambda identity, digest: replace(
                self.allowed[digest], task_id="legacy-task"
            ),
        )
        try:
            app.ingest(self.raw, None)
            with self.assertRaises(Rejected):
                export_retained_intent(app, self.raw, **options())
        finally:
            app.close()

    def test_fresh_process_exact_export(self) -> None:
        self.retain(event())
        expected = export_retained_intent(self.app, self.raw, **options())
        code = """
import sys
from tests.test_intent import event,options
from tether.admission import Admission,canonical
from tether.intent import export_retained_intent
app=Admission(sys.argv[1])
try:sys.stdout.buffer.write(export_retained_intent(app,canonical(event()),**options()))
finally:app.close()
"""
        for mode in ([], ["-O"]):
            result = subprocess.run(
                [sys.executable, *mode, "-c", code, self.path],
                cwd=ROOT,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                timeout=20,
                check=True,
            )
            self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main()
