"""Real HMAC/SQLite negative evidence, with independent no-positive-effect scans."""

import hashlib
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from tests.test_slack_ingress import (
    NOW,
    ROUTE,
    SECRET,
    approval,
    callback,
    headers,
    normalized,
    wire,
)
from tether.admission import Rejected
from tether.slack_ingress import SignedSlackIngress, SlackMessageVerifier
from tether.source_observation import (
    SignedSlackSourceObserver,
    SourceKey,
    SourceObservationStore,
)

ROOT = Path(__file__).resolve().parents[1]
STAMP = "1900000000.000002"
CANARY = "synthetic-source-content-canary"


def deletion(event_id: str = "EvDELETE1", stamp: str = STAMP) -> dict[str, Any]:
    value = callback()
    value["event_id"] = event_id
    value["event"] = {
        "type": "message",
        "subtype": "message_deleted",
        "hidden": True,
        "channel": ROUTE.channel_id,
        "deleted_ts": stamp,
    }
    return value


def change(event_id: str = "EvCHANGE1") -> dict[str, Any]:
    value = deletion(event_id)
    value["event"] = {
        "type": "message",
        "subtype": "message_changed",
        "hidden": True,
        "channel": ROUTE.channel_id,
        "message": {
            "type": "message",
            "user": ROUTE.actor_id,
            "ts": STAMP,
            "thread_ts": ROUTE.thread_ts,
            "text": CANARY,
            "edited": {"user": "UEDITOR", "ts": "1900000001.000003"},
        },
    }
    return value


def dump(path: Path) -> str:
    db = sqlite3.connect(path)
    try:
        return "\n".join(db.iterdump())
    finally:
        db.close()


class SourceObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="tether-source-observation-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.admission_path = self.root / "admission.db"
        self.path = self.root / "fences.db"
        self.ingress = SignedSlackIngress(
            str(self.admission_path),
            SECRET,
            ROUTE,
            lambda: NOW,
            lambda *_: approval(normalized()),
        )
        self.addCleanup(self.ingress.close)
        raw = wire(callback())
        self.assertEqual(self.ingress.ingest(raw, headers(raw)), "admitted")
        self.original_dump = dump(self.admission_path)
        self.authorize = Mock(return_value=True)
        self.observer = SignedSlackSourceObserver(
            str(self.path),
            SlackMessageVerifier(SECRET, ROUTE, lambda: NOW),
            ROUTE,
            self.ingress.admission,
            self.authorize,
        )
        self.addCleanup(self.observer.close)
        self.source = SourceKey(
            ROUTE.app_id, ROUTE.workspace_id, ROUTE.channel_id, STAMP
        )
        network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("forbidden network")
        )
        self.network = network.start()
        self.addCleanup(network.stop)

    def tearDown(self) -> None:
        self.assertEqual(dump(self.admission_path), self.original_dump)
        self.network.assert_not_called()

    def observe(self, value: dict[str, Any]) -> str:
        raw = wire(value)
        return self.observer.observe(raw, headers(raw))

    def count(self, table: str) -> int:
        db = sqlite3.connect(self.path)
        try:
            return int(db.execute("SELECT count(*) FROM " + table).fetchone()[0])
        finally:
            db.close()

    def test_actorless_delete_retains_only_negative_historical_link(self) -> None:
        self.assertEqual(self.observer.store.state(self.source), "unknown")
        value = deletion()
        value["private_untrusted_text"] = CANARY
        self.assertEqual(self.observe(value), "fenced")
        self.assertEqual(self.observer.store.state(self.source), "fenced")
        request = self.authorize.call_args.args[0]
        self.assertEqual(request["effect_scope"], "retain_deny_only_source_fence")
        self.assertEqual(request["original"]["original_actor_id"], ROUTE.actor_id)
        self.assertNotIn("actor_id", request["observation"])
        self.assertEqual(
            request["observation"]["body_sha256"],
            hashlib.sha256(wire(value)).hexdigest(),
        )
        self.assertEqual(self.count("source_fences"), 1)
        self.assertEqual(self.count("source_events"), 1)
        self.assertNotIn(CANARY, dump(self.path))
        self.assertNotIn(CANARY.encode(), self.path.read_bytes())

    def test_changed_editor_is_not_author_and_metadata_only_also_fences(self) -> None:
        self.assertEqual(self.observe(change()), "fenced")
        value = change("EvMETA2")
        value["event"]["message"].pop("edited")
        value["event"]["message"]["text"] = "synthetic request"
        value["event"]["message"]["metadata"] = {"language": "synthetic"}
        self.assertEqual(self.observe(value), "fenced")
        stored = dump(self.path)
        self.assertNotIn("UEDITOR", stored)
        self.assertNotIn(CANARY, stored)
        self.assertEqual(self.count("source_fences"), 1)
        self.assertEqual(self.count("source_events"), 2)

    def test_order_replay_conflict_and_trigger_retention(self) -> None:
        self.assertEqual(self.observe(deletion()), "fenced")
        first = dump(self.path)
        self.assertEqual(self.observe(deletion()), "duplicate")
        self.assertEqual(dump(self.path), first)
        self.assertEqual(self.observe(change()), "fenced")
        with self.assertRaises(Rejected):
            self.observe(change("EvDELETE1"))
        self.assertEqual(self.count("source_events"), 2)
        for table in ("source_fences", "source_events"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.observer.store.db.execute("DELETE FROM " + table)
        self.assertEqual(self.observer.store.state(self.source), "fenced")

    def test_unknown_original_never_creates_fence_or_positive_eligibility(self) -> None:
        unknown = replace(self.source, message_ts="1900000099.000001")
        with self.assertRaises(Rejected):
            self.observe(deletion(stamp=unknown.message_ts))
        self.assertEqual(self.observer.store.state(unknown), "unknown")
        self.assertEqual(self.count("source_fences"), 0)
        self.authorize.assert_not_called()

    def test_wrong_scope_actor_and_thread_hints_have_no_records(self) -> None:
        bad = []
        for key, value in (
            ("channel", "COTHER"),
            ("user", ROUTE.actor_id),
            ("thread_ts", "1900000009.000001"),
            ("hidden", False),
        ):
            item = deletion()
            item["event"][key] = value
            bad.append(item)
        for key, value in (
            ("user", "UOTHER"),
            ("thread_ts", "1900000009.000001"),
            ("team", "TOTHER"),
        ):
            item = change()
            item["event"]["message"][key] = value
            bad.append(item)
        previous = deletion()
        previous["event"]["previous_message"] = {"ts": STAMP, "user": "UOTHER"}
        bad.append(previous)
        app = deletion()
        app["api_app_id"] = "AOTHER"
        bad.append(app)
        for item in bad:
            with self.assertRaises((Rejected, ValueError)):
                self.observe(item)
        self.assertEqual(self.count("source_events"), 0)
        self.authorize.assert_not_called()

    def test_nested_channel_hints_reject_before_authorization(self) -> None:
        for factory in (change, deletion):
            item = factory()
            if factory is change:
                item["event"]["message"]["channel"] = "COTHER"
            else:
                item["event"]["previous_message"] = {"ts": STAMP, "channel": "COTHER"}
            with self.assertRaises(Rejected):
                self.observe(item)
        self.authorize.assert_not_called()
        self.assertEqual(self.count("source_events"), 0)
        item = change()
        item["event"]["message"]["channel"] = ROUTE.channel_id
        self.assertEqual(self.observe(item), "fenced")

    def test_ephemeral_and_uri_store_paths_reject_before_open(self) -> None:
        for path in (
            "",
            ":memory:",
            "file::memory:",
            "file::memory:?cache=shared",
            "file:synthetic?mode=memory&cache=shared",
            "FILE:synthetic",
        ):
            with patch("tether.source_observation.open_store") as opened:
                with self.assertRaises(Rejected):
                    SourceObservationStore(path, lambda _: None)
                opened.assert_not_called()

    def test_invalid_signature_and_default_deny(self) -> None:
        raw = wire(deletion())
        with self.assertRaises(Rejected):
            self.observer.observe(raw, headers(raw, secret=b"wrong-synthetic"))
        self.authorize.assert_not_called()
        self.observer.store.authorize = None
        with self.assertRaises(Rejected):
            self.observe(deletion())
        self.assertEqual(self.count("source_fences"), 0)

    def test_callback_mutation_and_exception_fail_closed(self) -> None:
        def mutate(request: dict[str, Any]) -> bool:
            request["effect_scope"] = "invented_positive_authority"
            return True

        self.observer.store.authorize = mutate
        with self.assertRaises(Rejected):
            self.observe(deletion())
        self.observer.store.authorize = Mock(side_effect=ValueError(CANARY))
        with self.assertRaises(Rejected) as caught:
            self.observe(deletion())
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(self.count("source_events"), 0)

    def test_authority_revoked_during_real_writer_lock_wait(self) -> None:
        blocker = sqlite3.connect(
            self.path, isolation_level=None, check_same_thread=False
        )
        revoked = threading.Event()
        released = threading.Event()
        calls = 0

        def release() -> None:
            time.sleep(0.15)
            revoked.set()
            blocker.rollback()
            released.set()

        worker: threading.Thread | None = None

        def authorize(request: dict[str, Any]) -> bool:
            nonlocal calls, worker
            calls += 1
            if calls == 1:
                blocker.execute("BEGIN IMMEDIATE")
                worker = threading.Thread(target=release)
                worker.start()
                return True
            self.assertTrue(self.observer.store.db.in_transaction)
            return not revoked.is_set()

        self.observer.store.authorize = authorize
        try:
            with self.assertRaises(Rejected):
                self.observe(deletion())
        finally:
            released.wait(2)
            if worker is not None:
                worker.join(2)
            blocker.close()
        self.assertEqual(calls, 2)
        self.assertEqual(self.count("source_fences"), 0)

    def test_capacity_rejects_new_events_but_preserves_fences_and_replay(self) -> None:
        with patch("tether.source_observation.MAX_RECORDS", 2):
            self.observe(deletion())
            self.observe(change())
            before = dump(self.path)
            with self.assertRaisesRegex(Rejected, "capacity"):
                self.observe(change("EvEXTRA3"))
            self.assertEqual(dump(self.path), before)
            self.assertEqual(self.observe(deletion()), "duplicate")
            self.assertEqual(self.observer.store.state(self.source), "fenced")

    def child(self, mode: str) -> subprocess.CompletedProcess[str]:
        script = """import os,sys
from tests.test_source_observation import *
a=SignedSlackIngress(sys.argv[1],SECRET,ROUTE,lambda:NOW)
o=SignedSlackSourceObserver(sys.argv[2],SlackMessageVerifier(SECRET,ROUTE,lambda:NOW),ROUTE,a.admission,lambda request:True)
mode=sys.argv[3]
if mode in ('crash','cancel','crash_after_commit'):
 original=o.store.db
 class Interrupted:
  def __getattr__(self,name):return getattr(original,name)
  def commit(self):
   original.commit()
   if mode=='crash_after_commit':os._exit(38)
  def execute(self,sql,*args):
   result=original.execute(sql,*args)
   if mode in ('crash','cancel') and sql.startswith('INSERT INTO source_fences'):
    if mode=='crash':os._exit(37)
    raise KeyboardInterrupt()
   return result
 o.store.db=Interrupted()
try:
 if mode=='read':
  if o.store.state(SourceKey(ROUTE.app_id,ROUTE.workspace_id,ROUTE.channel_id,STAMP))!='fenced':raise AssertionError('lost fence')
 else:
  raw=wire(deletion());o.observe(raw,headers(raw))
except KeyboardInterrupt:
 if mode!='cancel':raise
finally:o.close();a.close()
"""
        return subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.admission_path),
                str(self.path),
                mode,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_crash_and_cancellation_between_inserts_leave_no_partial_fence(
        self,
    ) -> None:
        self.assertEqual(self.child("crash").returncode, 37)
        self.assertEqual(self.count("source_fences"), 0)
        self.assertEqual(self.count("source_events"), 0)
        cancelled = self.child("cancel")
        self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
        self.assertEqual(self.count("source_fences"), 0)
        self.assertEqual(self.count("source_events"), 0)
        self.assertEqual(self.observe(deletion()), "fenced")
        read = self.child("read")
        self.assertEqual(read.returncode, 0, read.stderr)

    def test_crash_after_commit_retains_fence_and_exact_replay(self) -> None:
        crashed = self.child("crash_after_commit")
        self.assertEqual(crashed.returncode, 38, crashed.stderr)
        self.assertEqual(self.count("source_fences"), 1)
        self.assertEqual(self.count("source_events"), 1)
        before = dump(self.path)
        self.assertEqual(self.observe(deletion()), "duplicate")
        self.assertEqual(dump(self.path), before)

    def test_concurrent_process_observations_retain_once(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.child, ("write", "write")))
        for result in results:
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.count("source_fences"), 1)
        self.assertEqual(self.count("source_events"), 1)
        self.assertEqual(self.observer.store.state(self.source), "fenced")

    def test_unverified_direct_store_write_is_denied(self) -> None:
        from tether.source_observation import SourceObservation

        original = self.observer._resolve(self.source)
        if original is None:
            self.fail("missing fixture original")
        observation = SourceObservation(
            self.source, "EvUNVERIFIED", "a" * 64, "message_deleted"
        )
        with self.assertRaises(Rejected):
            self.observer.store.record(observation, original, object())
        self.assertEqual(self.count("source_fences"), 0)

    def test_mutation_omitting_durable_fence_is_observed(self) -> None:
        target = self.root / "mutation"
        shutil.copytree(
            ROOT / "tether",
            target / "tether",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copytree(
            ROOT / "tests",
            target / "tests",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        path = target / "tether/source_observation.py"
        source = path.read_text()
        self.assertIn("            if fence is None:\n", source)
        path.write_text(
            source.replace(
                "            if fence is None:\n", "            if False:\n", 1
            )
        )
        run = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-m",
                "unittest",
                "tests.test_source_observation.SourceObservationTests.test_actorless_delete_retains_only_negative_historical_link",
            ],
            cwd=target,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("FAIL:", run.stderr)
        self.assertNotIn("ImportError", run.stderr)


if __name__ == "__main__":
    unittest.main()
