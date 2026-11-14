"""Real SQLite/ingress, synthetic HMAC transport and authority, no network."""
import copy
from dataclasses import replace
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tether.admission import Admission, Grant, Identity, Rejected, canonical

ROOT = Path(__file__).resolve().parents[1]
SECRET = b"synthetic-only-transport-canary"
IDENTITY = Identity("actor-1", "workspace-1", "channel-1", "thread-1")


def event(revision=1, **changes):
    value = dict(version="runspindle.tether.ingress.v1", event_id=f"event-{revision}",
                 message_id="message-1", actor_id="actor-1", workspace_id="workspace-1",
                 channel_id="channel-1", thread_id="thread-1", revision=revision,
                 kind="create" if revision == 1 else "edit", text="synthetic", mirrored=False)
    value.update(changes)
    return value


def grant(value):
    return Grant(IDENTITY, hashlib.sha256(canonical(value)).hexdigest(), "task-1",
                 value["revision"], f"operation-{value['revision']}", "policy-1",
                 "host-1", 1, "grant-1", "synthetic")


def proof(raw):
    return hmac.new(SECRET, raw, hashlib.sha256).hexdigest()


def authenticate(raw, signature):
    return IDENTITY if hmac.compare_digest(proof(raw), signature) else None


class Ingress(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "admission.db")
        self.allowed = {}
        self.app = Admission(self.path, authenticate, lambda identity, digest: self.allowed.get(digest))
        self.addCleanup(self.app.close)
        # Independently observed forbidden outbound effects, not implementation counters.
        self.network = patch.object(socket.socket, "connect", side_effect=AssertionError("forbidden network"))
        self.calls = self.network.start()
        self.addCleanup(self.network.stop)

    def allow(self, value):
        g = grant(value)
        self.allowed[g.event_digest] = g
        return canonical(value)

    def ingest(self, value):
        raw = self.allow(value)
        return self.app.ingest(raw, proof(raw))

    def state(self):
        with sqlite3.connect(self.path) as db:
            return list(db.iterdump())

    def rejected_without_effects(self, value, signature=None):
        raw = self.allow(value)
        before = self.state()
        with self.assertRaises(Rejected):
            self.app.ingest(raw, proof(raw) if signature is None else signature)
        self.assertEqual(before, self.state())
        self.calls.assert_not_called()

    def test_authenticated_create_edit_delete_and_wire_mapping(self):
        for value in [event(), event(2), event(3, kind="delete", text="")]:
            self.assertEqual(self.ingest(value), "admitted")
        envelopes = self.app.envelopes()
        self.assertEqual([e["binding"]["revision"] for e in envelopes], [1, 2, 3])
        self.assertEqual(envelopes[0], {
            "version": "runspindle.envelope.v1", "message_type": "admission_request",
            "message_id": "event-1",
            "binding": dict(task_id="task-1", revision=1, operation_id="operation-1",
                            policy_revision="policy-1", host_id="host-1", workspace_id="workspace-1", lease_epoch=1),
            "payload": dict(delivery_namespace="synthetic", delivery_id="event-1",
                            predecessor_revision=None, normalized_digest=hashlib.sha256(canonical(event())).hexdigest(),
                            grant_ref="grant-1")})
        self.assertEqual(envelopes[2]["payload"]["predecessor_revision"], 2)
        self.assertNotIn("synthetic-only-transport-canary", str(self.state()))
        self.calls.assert_not_called()

    def test_forgery_wrong_scope_transport_failure_zero_effects(self):
        for field in ("actor_id", "workspace_id", "channel_id", "thread_id"):
            self.rejected_without_effects(event(**{field: "wrong"}))
        self.rejected_without_effects(event(), "bad-signature")

    def test_missing_expired_revoked_unavailable_authority(self):
        raw = canonical(event())
        for resolver in [None, lambda *_: None, lambda *_: (_ for _ in ()).throw(OSError("unavailable"))]:
            self.app.authorize = resolver
            before = self.state()
            with self.assertRaises(Rejected):
                self.app.ingest(raw, proof(raw))
            self.assertEqual(before, self.state())
        self.app.authorize = lambda *_: grant(event())
        self.app.authenticate = None
        with self.assertRaises(Rejected):
            self.app.ingest(raw, proof(raw))
        self.assertEqual(self.app.envelopes(), [])

    def test_authority_digest_identity_and_revision_are_bound(self):
        raw = canonical(event())
        for change in [dict(event_digest="0" * 64), dict(identity=replace(IDENTITY, actor_id="wrong")),
                       dict(revision=2), dict(lease_epoch=True)]:
            self.app.authorize = lambda *_, change=change: replace(grant(event()), **change)
            before = self.state()
            with self.assertRaises(Rejected):
                self.app.ingest(raw, proof(raw))
            self.assertEqual(before, self.state())

    def test_out_of_order_duplicate_stale_and_tombstone(self):
        self.rejected_without_effects(event(3, kind="delete", text=""))
        self.rejected_without_effects(event(2))
        self.ingest(event())
        before = self.state()
        self.assertEqual(self.ingest(event()), "duplicate")
        self.assertEqual(before, self.state())
        self.rejected_without_effects(event(text="conflict"))
        self.ingest(event(2))
        self.rejected_without_effects(event(event_id="late-create"))
        self.ingest(event(3, kind="delete", text=""))
        self.rejected_without_effects(event(4))
        self.rejected_without_effects(event(2, event_id="late-edit"))
        self.assertEqual(len(self.app.envelopes()), 3)

    def test_task_cannot_switch_source_or_source_switch_task(self):
        self.ingest(event())
        self.rejected_without_effects(event(2, message_id="another-message"))
        raw = self.allow(event(event_id="another-event"))
        g = grant(event(event_id="another-event"))
        self.allowed[g.event_digest] = replace(g, task_id="another-task")
        with self.assertRaises(Rejected):
            self.app.ingest(raw, proof(raw))
        self.assertEqual(len(self.app.envelopes()), 1)

    def test_mirrored_flag_and_readback_suppression_survive_restart(self):
        self.rejected_without_effects(event(mirrored=True))
        self.app.record_mirror("workspace-1", "channel-1", "thread-1", "message-1")
        self.rejected_without_effects(event())
        self.fresh_process(event(), "rejected")

    def fresh_process(self, value, expected):
        script = '''
import json, sys
from test_admission import authenticate, grant, proof
from tether.admission import Admission, Rejected, canonical
value=json.loads(sys.argv[2]); raw=canonical(value)
app=Admission(sys.argv[1], authenticate, lambda *_: grant(value))
try:
    try: result=app.ingest(raw, proof(raw))
    except Rejected: result="rejected"
    if result != sys.argv[3]:
        raise RuntimeError("unexpected ingress result: " + result)
finally: app.close()
'''
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), str(ROOT / "tests")]))
        subprocess.run([sys.executable, *(["-O"] if sys.flags.optimize else []), "-c", script, self.path, json.dumps(value), expected],
                       env=env, check=True, timeout=20)

    def test_fresh_process_duplicate_edit_delete_and_replay(self):
        self.ingest(event())
        self.fresh_process(event(), "duplicate")
        self.fresh_process(event(2), "admitted")
        self.fresh_process(event(3, kind="delete", text=""), "admitted")
        self.fresh_process(event(4), "rejected")
        self.assertEqual(len(self.app.envelopes()), 3)

    def test_sql_failure_rolls_back_all_tables(self):
        self.app.db.execute("CREATE TRIGGER fail_write BEFORE INSERT ON revisions BEGIN SELECT RAISE(ABORT, 'injected'); END")
        before = self.state()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ingest(event())
        self.assertEqual(before, self.state())

    def test_strict_bytes_and_counter_validation(self):
        raw = self.allow(event())
        malformed = [raw + b" ", b'\xef\xbb\xbf' + raw,
                     raw[:-1] + b',"revision":1}', b"[", b"x" * 1048577]
        for field, value in [("revision", True), ("revision", 1.0), ("revision", 2**64),
                             ("revision", 0), ("version", "unknown"), ("extra", "x")]:
            malformed.append(canonical(dict(event(), **{field: value})))
        for data in malformed:
            with self.assertRaises(Rejected):
                self.app.ingest(data, proof(data))
        self.assertEqual(self.app.envelopes(), [])

    def test_deliberate_scope_mutation_is_detected_by_effect_observer(self):
        # Load a disposable mutated source copy, never alter the checked-out module.
        source = (ROOT / "tether/admission.py").read_text()
        needle = "if claimed != identity:"
        self.assertEqual(source.count(needle), 1)
        mutated = Path(self.tmp.name) / "mutant.py"
        mutated.write_text(source.replace(needle, "if False:  # deliberate mutation"))
        spec = importlib.util.spec_from_file_location("admission_mutant", mutated)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(module)
        fake = module.Identity("actor-1", "workspace-1", "channel-1", "thread-1")
        value = event(actor_id="forged")
        raw = canonical(value)
        trusted = module.Grant(fake, hashlib.sha256(raw).hexdigest(), "task-1", 1,
                               "operation-1", "policy-1", "host-1", 1, "grant-1", "synthetic")
        app = module.Admission(str(Path(self.tmp.name) / "mutant.db"), lambda *_: fake, lambda *_: trusted)
        self.addCleanup(app.close)
        app.ingest(raw, proof(raw))
        with sqlite3.connect(Path(self.tmp.name) / "mutant.db") as observer:
            forbidden = observer.execute("SELECT COUNT(*) FROM revisions").fetchone()[0]
        self.assertEqual(forbidden, 1, "mutation must cause independently visible forbidden effect")

    def test_concurrent_process_conflict_admits_once(self):
        script = '''
import json, sys
from test_admission import authenticate, grant, proof
from tether.admission import Admission, Rejected, canonical
value=json.loads(sys.argv[2]); raw=canonical(value)
app=Admission(sys.argv[1], authenticate, lambda *_: grant(value))
try:
    try: print(app.ingest(raw, proof(raw)))
    except Rejected: print("rejected")
finally: app.close()
'''
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), str(ROOT / "tests")]))
        children = []
        try:
            for eid in ("race-a", "race-b"):
                children.append(subprocess.Popen(
                    [sys.executable, *(["-O"] if sys.flags.optimize else []), "-c", script, self.path, json.dumps(event(event_id=eid))],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            results = []
            for child in children:
                stdout, stderr = child.communicate(timeout=20)
                self.assertEqual(child.returncode, 0, stderr)
                results.append(stdout.strip())
            self.assertEqual(sorted(results), ["admitted", "rejected"])
            self.assertEqual(len(self.app.envelopes()), 1)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=20)

    def test_cancellation_rolls_back_and_retry_succeeds(self):
        real = self.app.db

        class InterruptingConnection:
            def execute(self, sql, args=()):
                if sql.startswith("INSERT INTO revisions"):
                    raise KeyboardInterrupt("synthetic cancellation")
                return real.execute(sql, args)

        before = self.state()
        self.app.db = InterruptingConnection()
        try:
            with self.assertRaises(KeyboardInterrupt):
                self.ingest(event())
        finally:
            self.app.db = real
        self.assertEqual(before, self.state())
        self.assertEqual(self.ingest(event()), "admitted")
