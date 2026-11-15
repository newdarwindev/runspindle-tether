"""Real SQLite lock contention with synthetic revocable admission grants."""

import json
import os
import selectors
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_admission import authenticate, event, grant, proof
from tether.admission import Admission, canonical

ROOT = Path(__file__).resolve().parents[1]
CHILD = r"""
import json, sys
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch
import socket
from test_admission import authenticate, grant, proof
from tether.admission import Admission, Rejected, canonical
path, config, encoded = sys.argv[1:]
value = json.loads(encoded)
calls = []
def authorize(identity, digest):
    config_value = json.loads(Path(config).read_text())
    calls.append(config_value)
    if config_value == "revoked": return None
    if config_value == "unavailable": raise RuntimeError("PRIVATE_CANARY")
    if config_value == "cancelled": raise KeyboardInterrupt()
    return replace(grant(value), **config_value)
with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")) as network:
    app = Admission(path, authenticate, authorize)
    try:
        print("ready", flush=True)
        if sys.stdin.readline().strip() != "go": raise RuntimeError("missing start")
        def trace(sql):
            if sql == "BEGIN IMMEDIATE": print("locking", flush=True)
        app.db.set_trace_callback(trace)
        try: outcome = app.ingest(canonical(value), proof(canonical(value)))
        except Rejected as error:
            outcome = "rejected"
            if error.__context__ is not None: raise RuntimeError("private exception context")
        except KeyboardInterrupt: outcome = "cancelled"
        print(json.dumps({"outcome": outcome, "calls": len(calls),
            "transaction": app.db.in_transaction, "network": network.call_count}), flush=True)
    finally: app.close()
"""


class AdmissionAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.network_patch = patch.object(
            socket.socket, "connect", side_effect=AssertionError("forbidden network")
        )
        self.network = self.network_patch.start()
        self.addCleanup(self.network_patch.stop)
        self.addCleanup(self.network.assert_not_called)

    def run_contended(
        self, kind: str, change: object
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        folder = self.root / str(len(list(self.root.iterdir())))
        folder.mkdir()
        database = folder / "admission.db"
        config = folder / "authority.json"
        config.write_text("{}")
        value = event()
        app = Admission(str(database), authenticate, lambda *_: grant(event()))
        try:
            if kind != "create":
                raw = canonical(event())
                self.assertEqual(app.ingest(raw, proof(raw)), "admitted")
                if kind in ("edit", "delete"):
                    value = event(
                        2, kind=kind, text="" if kind == "delete" else "edited"
                    )
        finally:
            app.close()
        observer = sqlite3.connect(database, isolation_level=None)
        self.addCleanup(observer.close)
        before = list(observer.iterdump())
        env = dict(
            os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), str(ROOT / "tests")])
        )
        child = subprocess.Popen(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                CHILD,
                str(database),
                str(config),
                json.dumps(value),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        selector = selectors.DefaultSelector()
        try:
            if child.stdout is None or child.stdin is None:
                raise RuntimeError("child pipes unavailable")
            output = child.stdout
            selector.register(output, selectors.EVENT_READ)

            def line() -> str:
                self.assertTrue(selector.select(5), "child handshake timed out")
                return output.readline().strip()

            self.assertEqual(line(), "ready")
            observer.execute("BEGIN IMMEDIATE")
            child.stdin.write("go\n")
            child.stdin.flush()
            self.assertEqual(line(), "locking")
            # The competing real SQLite writer owns the transaction. The child
            # cannot complete before this connection releases its write lock.
            self.assertFalse(selector.select(0.05), "admission bypassed write lock")
            config.write_text(json.dumps(change))
            observer.execute("COMMIT")
            stdout, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertNotIn("PRIVATE_CANARY", stdout + stderr)
            result = json.loads(stdout)
            self.assertFalse(result["transaction"])
            self.assertEqual(result["network"], 0)
            after = list(observer.iterdump())
            return result, before, after
        finally:
            if observer.in_transaction:
                observer.rollback()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
            selector.close()

    def test_revocation_during_lock_wait_rejects_create_edit_delete_and_replay(
        self,
    ) -> None:
        for kind in ("create", "edit", "delete", "replay"):
            with self.subTest(kind=kind):
                result, before, after = self.run_contended(kind, "revoked")
                self.assertEqual(
                    after, before, "revoked authority changed durable state"
                )
                self.assertEqual(result["outcome"], "rejected")
                self.assertEqual(result["calls"], 2)

    def test_unchanged_grant_survives_lock_wait_and_replay(self) -> None:
        for kind in ("create", "edit", "delete", "replay"):
            with self.subTest(kind=kind):
                result, before, after = self.run_contended(kind, {})
                self.assertEqual(
                    result["outcome"], "duplicate" if kind == "replay" else "admitted"
                )
                self.assertEqual(result["calls"], 2)
                if kind == "replay":
                    self.assertEqual(after, before)
                else:
                    self.assertNotEqual(after, before)

    def test_changed_grant_after_lock_denies_without_rebinding(self) -> None:
        for change in (
            {"task_id": "task-other"},
            {"operation_id": "operation-other"},
            {"policy_revision": "policy-other"},
            {"host_id": "host-other"},
            {"lease_epoch": 2},
            {"grant_ref": "grant-other"},
            {"delivery_namespace": "namespace-other"},
            {"revision": 2},
            {"event_digest": "0" * 64},
            {"lease_epoch": True},
        ):
            with self.subTest(change=change):
                result, before, after = self.run_contended("create", change)
                self.assertEqual(result["outcome"], "rejected")
                self.assertEqual(result["calls"], 2)
                self.assertEqual(after, before)

    def test_recheck_error_and_cancellation_roll_back_without_private_context(
        self,
    ) -> None:
        for change in ("unavailable", "cancelled"):
            with self.subTest(change=change):
                result, before, after = self.run_contended("create", change)
                self.assertEqual(
                    result["outcome"],
                    "cancelled" if change == "cancelled" else "rejected",
                )
                self.assertEqual(result["calls"], 2)
                self.assertEqual(after, before)

    def test_removing_post_lock_recheck_is_detected_by_durable_effect_observer(
        self,
    ) -> None:
        mutant = self.root / "mutant"
        (mutant / "tether").mkdir(parents=True)
        (mutant / "tests").mkdir()
        for name in ("__init__.py", "admission.py", "sanitization.py", "schema.py"):
            shutil.copyfile(ROOT / "tether" / name, mutant / "tether" / name)
        for name in ("test_admission.py", "test_admission_authority.py"):
            shutil.copyfile(ROOT / "tests" / name, mutant / "tests" / name)
        source = mutant / "tether/admission.py"
        original = source.read_text()
        needle = "if verified_grant() != grant:"
        self.assertEqual(original.count(needle), 1)
        source.write_text(original.replace(needle, "if False:  # deliberate mutation"))
        env = dict(
            os.environ, PYTHONPATH=os.pathsep.join([str(mutant), str(mutant / "tests")])
        )
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-m",
                "unittest",
                "test_admission_authority.AdmissionAuthorityTests.test_revocation_during_lock_wait_rejects_create_edit_delete_and_replay",
            ],
            cwd=mutant,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("revoked authority changed durable state", result.stderr)
        self.assertIn("FAILED (failures=4)", result.stderr)
        self.assertNotIn("ERROR", result.stderr)

    def test_rejected_attempt_can_be_admitted_by_a_fresh_process_with_new_authority(
        self,
    ) -> None:
        result, before, after = self.run_contended("create", "revoked")
        self.assertEqual(result["outcome"], "rejected")
        self.assertEqual(before, after)
        databases = list(self.root.glob("*/admission.db"))
        self.assertEqual(len(databases), 1)
        script = """
import socket, sys
from unittest.mock import patch
from tests.test_admission import authenticate, event, grant, proof
from tether.admission import Admission, canonical
with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")) as network:
    app = Admission(sys.argv[1], authenticate, lambda *_: grant(event()))
    try:
        raw = canonical(event())
        print(app.ingest(raw, proof(raw)))
        print(app.ingest(raw, proof(raw)))
        if network.call_count: raise RuntimeError("unexpected outbound call")
    finally: app.close()
"""
        fresh = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(databases[0]),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertEqual(fresh.stdout.splitlines(), ["admitted", "duplicate"])
        with sqlite3.connect(databases[0]) as observer:
            for table in ("revisions", "heads", "sources", "deliveries"):
                self.assertEqual(
                    observer.execute(f"SELECT COUNT(*) FROM {table}").fetchone(), (1,)
                )
