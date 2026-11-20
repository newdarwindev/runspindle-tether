"""Actual store/process tests; synthetic authentication and Core readback only."""

import hashlib
import json
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
from tether.schema import SchemaRejected
from tether.semantic_journal import IntentReferences, SemanticAdmission, encode_batch

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = Identity("Utest", "Wtest", "Ctest", "1700000000.000000")
TASK = options()["binding"]["task_id"]


def references(envelope: dict[str, Any]) -> IntentReferences:
    revision = envelope["binding"]["revision"]
    return IntentReferences(f"v3-grant-{revision}", f"delivery-{revision}")


def make_app(path: str, allowed: dict[str, Grant]) -> SemanticAdmission:
    return SemanticAdmission(
        path,
        app_id="Atest",
        account_id="acct-test",
        references=references,
        authenticate=lambda raw, proof: IDENTITY,
        authorize=lambda identity, digest: allowed.get(digest),
    )


def retain_event(
    app: SemanticAdmission,
    allowed: dict[str, Grant],
    revision: int = 1,
    kind: str = "create",
    text: str = "synthetic café",
) -> str:
    raw: bytes = canonical(event(revision, kind, text))
    args = options(revision)
    g = Grant(
        IDENTITY,
        hashlib.sha256(raw).hexdigest(),
        TASK,
        revision,
        args["binding"]["operation_id"],
        "policy-1",
        "host-test",
        1,
        "legacy-grant",
        "slack-test",
    )
    allowed[g.event_digest] = g
    return app.ingest(raw, None)


def receipt(batch: bytes) -> dict[str, Any]:
    value = json.loads(batch)
    last = value["intents"][-1]
    source = last["event"]["source"]
    task = last["scoped"]["request"]["binding"]["task_id"]
    route = [source["app_id"], source["account_id"], source["workspace_id"], task]
    return dict(
        status="retained",
        workflow_id="intent-"
        + hashlib.sha256(
            json.dumps(
                route, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest(),
        revision=last["event"]["revision"],
        batch_sha256=hashlib.sha256(batch).hexdigest(),
    )


class JournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "semantic.sqlite")
        self.allowed: dict[str, Grant] = {}
        self.app = make_app(self.path, self.allowed)
        self.addCleanup(self.app.close)
        self.network = patch(
            "socket.socket", side_effect=AssertionError("forbidden network")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def retain(
        self, revision: int = 1, kind: str = "create", text: str = "synthetic café"
    ) -> str:
        return retain_event(self.app, self.allowed, revision, kind, text)

    def snapshot(self) -> list[str]:
        with closing(sqlite3.connect(self.path)) as db:
            return list(db.iterdump())

    def test_foreign_store_identity_rejected_before_export_or_readback(self) -> None:
        # Model a misbound restore: the intact retained chain belongs to another
        # app/account than the newly configured store. No candidate is rehashed.
        self.retain()
        batch = self.app.snapshot_batch(TASK)
        for field in ("app_id", "account_id"):
            with self.subTest(field=field):
                changed = "other-app" if field == "app_id" else "other-account"
                self.app.db.execute(f"UPDATE intent_config SET {field}=?", (changed,))
                self.app.db.commit()
                config = dict(app_id="Atest", account_id="acct-test")
                config[field] = changed
                with closing(
                    SemanticAdmission(
                        self.path,
                        app_id=config["app_id"],
                        account_id=config["account_id"],
                    )
                ) as other:
                    before = self.snapshot()
                    calls: list[bytes] = []

                    def observe(wire: bytes) -> dict[str, Any]:
                        calls.append(wire)
                        return receipt(wire)

                    for operation in (
                        lambda: other.snapshot_batch(TASK),
                        lambda: other.pending_batch(TASK),
                        lambda: other.reconcile_retention(batch, observe),
                    ):
                        with self.assertRaisesRegex(
                            Rejected, "semantic source installation"
                        ):
                            operation()
                        self.assertEqual(calls, [])
                        self.assertEqual(self.snapshot(), before)
                    code = (
                        "from tether.semantic_journal import SemanticAdmission; "
                        "from tether.admission import Rejected; "
                        f"app=SemanticAdmission({self.path!r}, **{config!r}); "
                        "\ntry: app.pending_batch(" + repr(TASK) + ")"
                        "\nexcept Rejected: pass"
                        "\nelse: raise SystemExit('foreign source exported')"
                        "\nfinally: app.close()"
                    )
                    result = subprocess.run(
                        [sys.executable, "-c", code],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.app.db.execute(
                    f"UPDATE intent_config SET {field}=?",
                    ("Atest" if field == "app_id" else "acct-test",),
                )
                self.app.db.commit()
        self.assertEqual(self.app.pending_batch(TASK), batch)

    def test_atomic_candidate_available_without_export(self) -> None:
        self.assertEqual(self.retain(), "admitted")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM revisions").fetchone()[0], 1
            )
            self.assertEqual(
                db.execute("SELECT count(*) FROM intent_candidates").fetchone()[0], 1
            )
        first = self.app.snapshot_batch(TASK)
        self.assertEqual(self.app.pending_batch(TASK), first)
        self.assertEqual(self.retain(), "duplicate")
        self.assertEqual(self.app.snapshot_batch(TASK), first)

    def test_missed_predecessor_exports_recover_full_delete_chain(self) -> None:
        self.retain()
        self.retain(2, "edit", "replacement")
        self.retain(3, "delete", "")
        batch = self.app.snapshot_batch(TASK)
        value = json.loads(batch)
        self.assertEqual(
            [item["event"]["kind"] for item in value["intents"]],
            ["create", "edit", "delete"],
        )
        self.assertEqual(value["version"], "runspindle.intent-batch.v1")
        self.assertNotIn(b"synthetic", batch)
        # Core must atomically suppress obsolete executable revisions. No send here.
        self.assertEqual(
            batch, encode_batch([canonical(item) for item in value["intents"]])
        )
        with self.assertRaises(Rejected):
            self.retain(4, "edit", "resurrect")

    def test_independent_batch_vectors(self) -> None:
        fixture = json.loads(
            (ROOT / "conformance/intent-batch-v1/vectors.json").read_text()
        )
        for revision, row in enumerate(fixture["vectors"], 1):
            self.retain(
                revision,
                row["name"],
                ("synthetic café", "replacement", "")[revision - 1],
            )
            batch = self.app.snapshot_batch(TASK)
            expected = json.dumps(
                row["batch"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
            self.assertEqual(batch, expected)
            self.assertEqual(hashlib.sha256(batch).hexdigest(), row["batch_sha256"])

    def test_event_identity_cannot_repeat_under_new_delivery_namespace(self) -> None:
        self.retain()
        before = self.snapshot()
        changed = event(2, "edit", "replacement")
        changed["event_id"] = "Ev1"
        raw = canonical(changed)
        sha = hashlib.sha256(raw).hexdigest()
        previous = next(iter(self.allowed.values()))
        self.allowed[sha] = replace(
            previous,
            event_digest=sha,
            revision=2,
            operation_id="operation-2",
            delivery_namespace="another-namespace",
        )
        with self.assertRaises(Rejected):
            self.app.ingest(raw, None)
        self.assertEqual(self.snapshot(), before)

    def competing_source(self) -> tuple[bytes, str]:
        from tether.intent import expected_task_id

        changed = event()
        changed["message_id"] = "different-message"
        raw: bytes = canonical(changed)
        source = {
            key: changed[key]
            for key in (
                "actor_id",
                "workspace_id",
                "channel_id",
                "thread_id",
                "message_id",
            )
        }
        source.update(app_id="Atest", account_id="acct-test")
        task = expected_task_id(source)
        sha = hashlib.sha256(raw).hexdigest()
        self.allowed[sha] = Grant(
            IDENTITY,
            sha,
            task,
            1,
            "other-operation",
            "policy-1",
            "host-test",
            1,
            "other-legacy-grant",
            "another-namespace",
        )
        return raw, task

    def unique_references(self, envelope: dict[str, Any]) -> IntentReferences:
        suffix = envelope["binding"]["task_id"].split(":")[-1]
        return IntentReferences("v3-" + suffix, "delivery-" + suffix)

    def test_global_event_identity_rejects_other_source_task_and_namespace(
        self,
    ) -> None:
        self.app.references = self.unique_references
        self.retain()
        before = self.snapshot()
        raw, task = self.competing_source()
        with self.assertRaises(Rejected):
            self.app.ingest(raw, None)
        self.assertEqual(self.snapshot(), before)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM deliveries WHERE event='Ev1'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM intent_candidates WHERE task=?", (task,)
                ).fetchone()[0],
                0,
            )
        # Exact same namespace/event/digest remains an ordinary duplicate.
        self.assertEqual(self.retain(), "duplicate")
        self.assertEqual(self.snapshot(), before)

    def test_preexisting_global_conflict_blocks_snapshot_without_repair(self) -> None:
        self.app.references = self.unique_references
        self.retain()
        raw, competing = self.competing_source()
        # Reproduce pre-fix store state deliberately; do not modify guards used
        # by the actual snapshot under test.
        with patch.object(self.app, "_require_event_owner", lambda *args: None):
            self.assertEqual(self.app.ingest(raw, None), "admitted")
        before = self.snapshot()
        for task in (TASK, competing):
            with self.assertRaises(Rejected):
                self.app.snapshot_batch(task)
            with self.assertRaises(Rejected):
                self.app.pending_batch(task)
        with self.assertRaises(Rejected):
            self.retain()
        self.assertEqual(self.snapshot(), before)

    def test_global_event_guard_mutant_fails_independent_regression(self) -> None:
        with patch.object(
            SemanticAdmission, "_require_event_owner", lambda *args: None
        ):
            result = unittest.TestResult()
            JournalTests(
                "test_global_event_identity_rejects_other_source_task_and_namespace"
            ).run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertTrue(result.failures, "global event guard mutant escaped regression")

    def test_pending_none_describes_snapshot_not_concurrent_drain(self) -> None:
        self.retain()
        first = self.app.snapshot_batch(TASK)
        self.app.reconcile_retention(first, receipt)
        original = self.app.snapshot_batch

        def racing_snapshot(task: str) -> bytes:
            captured = original(task)
            self.retain(2, "edit", "replacement")
            return captured

        with patch.object(self.app, "snapshot_batch", racing_snapshot):
            self.assertIsNone(self.app.pending_batch(TASK))
        # The later revision remains pending and is never acknowledged by rev1.
        self.assertEqual(
            len(json.loads(self.app.pending_batch(TASK) or b"{}")["intents"]), 2
        )

    def test_missing_or_reused_references_roll_back_all_admission(self) -> None:
        before = self.snapshot()
        self.app.references = None
        with self.assertRaises(Rejected):
            self.retain()
        self.assertEqual(self.snapshot(), before)
        self.app.references = lambda envelope: IntentReferences(
            "legacy-grant", "delivery"
        )
        with self.assertRaises(Rejected):
            self.retain()
        self.assertEqual(self.snapshot(), before)

    def test_reserved_final_delete_capacity(self) -> None:
        self.retain()
        for revision in range(2, 65):
            self.retain(revision, "edit", f"revision-{revision}")
        before = self.snapshot()
        with self.assertRaises(Rejected):
            self.retain(65, "edit", "beyond-cap")
        self.assertEqual(self.snapshot(), before)
        self.retain(65, "delete", "")
        self.assertEqual(len(json.loads(self.app.snapshot_batch(TASK))["intents"]), 65)

    def test_legacy_and_wrong_config_fail_without_retrofit(self) -> None:
        old_path = str(Path(self.tmp.name) / "legacy.sqlite")
        old = Admission(old_path)
        old.close()
        old_bytes = Path(old_path).read_bytes()
        with self.assertRaises(SchemaRejected):
            make_app(old_path, {})
        self.assertEqual(Path(old_path).read_bytes(), old_bytes)
        self.retain()
        before = self.snapshot()
        with self.assertRaises(Rejected):
            SemanticAdmission(self.path, app_id="other", account_id="acct-test")
        self.assertEqual(self.snapshot(), before)

    def test_readback_exact_prefix_late_receipt_never_acks_new_head(self) -> None:
        self.retain()
        first = self.app.snapshot_batch(TASK)
        self.retain(2, "edit", "replacement")
        latest = self.app.snapshot_batch(TASK)
        self.assertEqual(self.app.reconcile_retention(first, receipt), "retained")
        self.assertEqual(self.app.pending_batch(TASK), latest)
        self.assertEqual(self.app.reconcile_retention(first, receipt), "duplicate")
        self.assertEqual(self.app.reconcile_retention(latest, receipt), "retained")
        self.assertIsNone(self.app.pending_batch(TASK))
        self.retain(3, "delete", "")
        self.assertIsNotNone(self.app.pending_batch(TASK))

    def test_lost_wrong_unavailable_receipts_leave_exact_pending(self) -> None:
        self.retain()
        batch = self.app.snapshot_batch(TASK)
        before = self.snapshot()
        for key, value in (
            ("workflow_id", "other"),
            ("revision", True),
            ("batch_sha256", "0" * 64),
            ("status", "executed"),
        ):
            wrong = receipt(batch)
            wrong[key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.app.reconcile_retention(batch, lambda supplied: wrong)
            self.assertEqual(self.snapshot(), before)
        with self.assertRaises(Rejected):
            self.app.reconcile_retention(batch)

        def lost(_: bytes) -> dict[str, Any]:
            raise OSError("synthetic lost reply")

        with self.assertRaises(Rejected):
            self.app.reconcile_retention(batch, lost)
        self.assertEqual(self.app.pending_batch(TASK), batch)
        self.assertEqual(self.app.reconcile_retention(batch, receipt), "retained")

    def test_ingress_during_readback_does_not_ack_newer_revision(self) -> None:
        self.retain()
        batch = self.app.snapshot_batch(TASK)

        def readback(supplied: bytes) -> dict[str, Any]:
            self.retain(2, "edit", "replacement")
            return receipt(supplied)

        self.assertEqual(self.app.reconcile_retention(batch, readback), "retained")
        self.assertEqual(
            len(json.loads(self.app.pending_batch(TASK) or b"{}")["intents"]), 2
        )

    def test_corrupt_receipt_cannot_hide_pending_work(self) -> None:
        self.retain()
        batch = self.app.snapshot_batch(TASK)
        self.app.reconcile_retention(batch, receipt)
        self.app.db.execute("UPDATE intent_observations SET workflow_id='wrong'")
        with self.assertRaises(Rejected):
            self.app.pending_batch(TASK)

    def test_corrupt_candidate_or_retained_digest_rejected(self) -> None:
        self.retain()
        self.app.db.execute("UPDATE revisions SET digest=?", ("0" * 64,))
        before = self.snapshot()
        with self.assertRaises(Rejected):
            self.app.snapshot_batch(TASK)
        self.assertEqual(self.snapshot(), before)

    def test_fresh_process_recovery_and_crash_before_commit(self) -> None:
        self.retain()
        self.retain(2, "edit", "replacement")
        self.retain(3, "delete", "")
        expected = self.app.snapshot_batch(TASK)
        script = """
import sys
from tests.test_semantic_journal import make_app,TASK
app=make_app(sys.argv[1],{})
try:sys.stdout.buffer.write(app.snapshot_batch(TASK))
finally:app.close()
"""
        for mode in ([], ["-O"]):
            result = subprocess.run(
                [sys.executable, *mode, "-c", script, self.path],
                cwd=ROOT,
                capture_output=True,
                timeout=20,
                check=True,
            )
            self.assertEqual(result.stdout, expected)
        crash_path = str(Path(self.tmp.name) / "crash.sqlite")
        script = """
import os,sys
from tests.test_semantic_journal import make_app,retain_event
allowed={};app=make_app(sys.argv[1],allowed)
original=app._retained_extension
def crash(raw,envelope,duplicate):
 original(raw,envelope,duplicate)
 os._exit(71)
app._retained_extension=crash
retain_event(app,allowed)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, crash_path],
            cwd=ROOT,
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 71)
        reopened = make_app(crash_path, {})
        try:
            self.assertEqual(
                reopened.db.execute("SELECT count(*) FROM revisions").fetchone()[0], 0
            )
            self.assertEqual(
                reopened.db.execute(
                    "SELECT count(*) FROM intent_candidates"
                ).fetchone()[0],
                0,
            )
        finally:
            reopened.close()

    def test_signed_create_uses_shared_verifier_and_revisions_stay_deny_only(
        self,
    ) -> None:
        from tests.test_slack_ingress import (
            NOW,
            ROUTE,
            SECRET,
            callback,
            headers,
            normalized,
            wire,
        )
        from tether.intent import expected_task_id
        from tether.semantic_ingress import SignedSemanticIngress

        source = dict(
            app_id=ROUTE.app_id,
            account_id="acct-test",
            actor_id=ROUTE.actor_id,
            workspace_id=ROUTE.workspace_id,
            channel_id=ROUTE.channel_id,
            thread_id=ROUTE.thread_ts,
            message_id="1900000000.000002",
        )
        task = expected_task_id(source)
        raw_digest = hashlib.sha256(canonical(normalized())).hexdigest()
        grant = Grant(
            ROUTE.identity,
            raw_digest,
            task,
            1,
            "operation-1",
            "policy-1",
            "host-test",
            1,
            "legacy-grant",
            "slack-test",
        )
        calls: list[str] = []

        def authorize(identity: Identity, digest: str) -> Grant | None:
            calls.append(digest)
            return grant if digest == raw_digest else None

        app = SignedSemanticIngress(
            str(Path(self.tmp.name) / "signed.sqlite"),
            SECRET,
            ROUTE,
            lambda: NOW,
            account_id="acct-test",
            references=references,
            authorize=authorize,
        )
        try:
            raw = wire(callback())
            self.assertEqual(app.ingest(raw, headers(raw)), "admitted")
            self.assertEqual(app.ingest(raw, headers(raw)), "duplicate")
            semantic = app.admission
            self.assertIsInstance(semantic, SemanticAdmission)
            # Explicit runtime type check also gives the typed journal API.
            if not isinstance(semantic, SemanticAdmission):
                self.fail("wrong store family")
            self.assertEqual(
                len(json.loads(semantic.snapshot_batch(task))["intents"]), 1
            )
            count = len(calls)
            for subtype in ("message_changed", "message_deleted"):
                unsupported = wire(callback(subtype=subtype))
                with self.assertRaises(Rejected):
                    app.ingest(unsupported, headers(unsupported))
            with self.assertRaises(Rejected):
                app.ingest(raw, headers(raw, secret=b"wrong-synthetic-secret"))
            self.assertEqual(len(calls), count)
        finally:
            app.close()

    def test_atomic_hook_removal_mutant_is_observed(self) -> None:
        with patch.object(SemanticAdmission, "_retained_extension", lambda *args: None):
            result = unittest.TestResult()
            JournalTests("test_atomic_candidate_available_without_export").run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertTrue(
            result.failures,
            "missing atomic journal hook escaped independent SQL assertion",
        )


if __name__ == "__main__":
    unittest.main()
