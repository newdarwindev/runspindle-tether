"""Actual component/SQLite evidence with synthetic authenticated events only."""

import hashlib
import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_admission import IDENTITY, authenticate, event, grant, proof
from tests.test_provider_journal import PAYLOAD, DurableFake, authorize, envelope, route
from tether.admission import Admission, Rejected, canonical
from tether.feedback import FeedbackGrant, FeedbackStore
from tether.journal import ProviderJournal

ROOT = Path(__file__).resolve().parents[1]


def retention(identity: Any, event_sha: str, target_sha: str) -> FeedbackGrant:
    return FeedbackGrant(
        identity, event_sha, target_sha, "retention-policy-1", "retention-grant-1"
    )


def target_authority(raw: bytes, payload: Any, target: dict[str, Any]) -> bool:
    # Explicit synthetic Core/artifact verifier; never default production authority.
    return (
        raw == envelope()
        and payload == PAYLOAD
        and target["artifact_sha256"]
        == hashlib.sha256(PAYLOAD.attachments[0].content).hexdigest()
    )


class FeedbackTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        admission = Admission(
            str(self.root / "admission.db"),
            authenticate,
            lambda i, d: grant(event())
            if i == IDENTITY and d == grant(event()).event_digest
            else None,
        )
        self.addCleanup(admission.close)
        admission.ingest(canonical(event()), proof(canonical(event())))
        self.journal = ProviderJournal(
            str(self.root / "journal.db"), admission, authorize, route
        )
        self.addCleanup(self.journal.close)
        self.provider = DurableFake(str(self.root / "provider.db"))
        self.addCleanup(self.provider.close)
        self.journal.send(envelope(), PAYLOAD, self.provider)
        observed = self.journal.lookup(envelope(), PAYLOAD, self.provider)
        self.assertEqual(observed.state, "destination_confirmed")
        self.message = observed.message_id
        self.target = self.journal.retained_target(
            envelope(), PAYLOAD, str(self.message)
        )
        self.path = str(self.root / "feedback.db")
        self.app = FeedbackStore(
            self.path, self.journal, authenticate, retention, target_authority
        )
        self.addCleanup(self.app.close)
        self.calls_before = self.provider.db.execute(
            "SELECT count(*) FROM calls"
        ).fetchone()[0]
        deny = patch.object(
            socket, "socket", side_effect=AssertionError("network forbidden")
        )
        self.socket = deny.start()
        self.addCleanup(deny.stop)
        self.addCleanup(self.socket.assert_not_called)
        self.addCleanup(self.check_provider)

    def check_provider(self) -> None:
        self.assertEqual(
            self.provider.db.execute("SELECT count(*) FROM calls").fetchone()[0],
            self.calls_before,
        )

    def raw(self, revision: int = 1, **changes: Any) -> bytes:
        value = dict(
            version="runspindle.tether.feedback.v1",
            namespace="synthetic",
            event_id=f"feedback-event-{revision}",
            feedback_id="feedback-1",
            revision=revision,
            predecessor=None if revision == 1 else revision - 1,
            actor_id="actor-1",
            workspace_id="workspace-1",
            channel_id="channel-1",
            thread_id="thread-1",
            kind="create" if revision == 1 else "edit",
            judgment="positive",
            correction=None,
            target=self.target,
        )
        value.update(changes)
        return canonical(value)

    def ingest(self, raw: bytes) -> str:
        # No subprocess model/optimizer or transport may be started by retention.
        with patch.object(
            subprocess, "Popen", side_effect=AssertionError("execution forbidden")
        ) as spawned:
            result = self.app.ingest(raw, proof(raw), envelope(), PAYLOAD)
            spawned.assert_not_called()
            return result

    def test_retained_replay_edit_delete_and_restart(self) -> None:
        self.assertEqual(self.ingest(self.raw()), "retained")
        self.assertEqual(self.ingest(self.raw()), "duplicate")
        self.assertEqual(
            self.ingest(
                self.raw(2, judgment="correction", correction="Synthetic correction")
            ),
            "retained",
        )
        self.assertEqual(
            self.ingest(self.raw(3, kind="delete", judgment=None)), "retained"
        )
        evidence = self.app.evidence("synthetic", "feedback-1")
        self.assertEqual(evidence["state"], "deleted")
        self.assertEqual(len(evidence["revisions"]), 3)
        self.assertFalse(evidence["collection_allowed"])
        self.assertFalse(evidence["training_allowed"])
        self.assertEqual(evidence["revisions"][0]["event"]["target"], self.target)
        code = """
import json,sys,socket
from unittest.mock import patch
from tether.feedback import FeedbackStore
from tether.journal import ProviderJournal
from tether.admission import canonical
from tests.test_admission import authenticate,proof
from tests.test_feedback import retention,target_authority
from tests.test_provider_journal import PAYLOAD,envelope
with patch.object(socket,'socket',side_effect=AssertionError('network')):
 j=ProviderJournal(sys.argv[1]); f=FeedbackStore(sys.argv[2],j,authenticate,retention,target_authority)
 evidence=f.evidence('synthetic','feedback-1')
 raw=canonical(evidence['revisions'][0]['event'])
 if f.ingest(raw,proof(raw),envelope(),PAYLOAD) != 'duplicate': raise ValueError('replay')
 print(json.dumps(f.evidence('synthetic','feedback-1'),sort_keys=True))
 f.close(); j.close()
"""
        child = subprocess.run(
            [sys.executable, "-c", code, str(self.root / "journal.db"), self.path],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), evidence)
        with self.assertRaises(Rejected):
            self.ingest(self.raw(4))

    def test_absent_and_forged_authority_never_retains_or_fences(self) -> None:
        self.ingest(self.raw())
        conflict = self.raw(judgment="negative")
        with self.assertRaises(Rejected):
            self.app.ingest(conflict, "forged", envelope(), PAYLOAD)
        for field in ("authenticate", "authorize_retention", "verify_target"):
            saved = getattr(self.app, field)
            setattr(self.app, field, None)
            with self.assertRaises(Rejected):
                self.ingest(conflict)
            setattr(self.app, field, saved)
        self.assertEqual(
            self.app.evidence("synthetic", "feedback-1")["state"], "active"
        )

    def test_conflict_fence_survives_exhausted_evidence_budget(self) -> None:
        self.ingest(self.raw())
        with patch("tether.feedback.MAX_EVENTS", 0):
            self.assertEqual(self.ingest(self.raw(judgment="negative")), "conflict")
        evidence = self.app.evidence("synthetic", "feedback-1")
        self.assertEqual(evidence["state"], "conflicted")
        self.assertEqual(len(evidence["revisions"]), 1)
        with self.assertRaises(Rejected):
            self.ingest(self.raw(2))
        self.assertEqual(
            self.app.db.execute("SELECT count(*) FROM feedback_deliveries").fetchone()[
                0
            ],
            1,
        )

    def test_exact_target_and_bool_revision_rejection(self) -> None:
        for changes in (
            {"revision": True},
            {"target": {**self.target, "artifact_revision": True}},
            {"target": {**self.target, "artifact_sha256": "0" * 64}},
            {"actor_id": "forged"},
            {"target": {**self.target, "message_id": "missing"}},
        ):
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.ingest(self.raw(**changes))
        with self.assertRaises(Rejected):
            self.app.ingest(
                self.raw(),
                proof(self.raw()),
                envelope(),
                replace(PAYLOAD, text="different"),
            )
        self.assertEqual(
            self.app.db.execute("SELECT count(*) FROM feedback_heads").fetchone()[0], 0
        )

    def test_callback_errors_are_sanitized_and_revocation_rechecked(self) -> None:
        def fail(*_: Any) -> Any:
            raise ValueError("SECRET_CANARY")

        self.app.verify_target = fail
        with self.assertRaises(Rejected) as caught:
            self.ingest(self.raw())
        self.assertNotIn("SECRET_CANARY", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        calls = 0

        def revoked(*_: Any) -> bool:
            nonlocal calls
            calls += 1
            return calls == 1

        self.app.verify_target = revoked
        with self.assertRaises(Rejected):
            self.ingest(self.raw())
        self.assertEqual(calls, 2)
        self.assertEqual(
            self.app.db.execute("SELECT count(*) FROM feedback_heads").fetchone()[0], 0
        )
        self.assertNotIn("SECRET_CANARY", str(list(self.app.db.iterdump())))

    def test_unconfirmed_and_conflicted_transport_cannot_be_target(self) -> None:
        self.journal.db.execute("UPDATE provider_attempts SET observed=NULL")
        with self.assertRaises(Rejected):
            self.ingest(self.raw())
        self.journal.db.execute(
            "UPDATE provider_attempts SET observed=?,conflict=1", (self.message,)
        )
        with self.assertRaises(Rejected):
            self.ingest(self.raw())

    def test_event_id_reuse_conflicts_without_overwriting_either_history(self) -> None:
        self.ingest(self.raw())
        self.ingest(self.raw(feedback_id="feedback-2", event_id="independent"))
        self.assertEqual(self.ingest(self.raw(feedback_id="feedback-2")), "conflict")
        for identity in ("feedback-1", "feedback-2"):
            evidence = self.app.evidence("synthetic", identity)
            self.assertEqual(evidence["state"], "conflicted")
            self.assertEqual(len(evidence["revisions"]), 1)

    def test_conflict_fence_mutation_is_observed_in_sqlite(self) -> None:
        self.ingest(self.raw())
        source = (ROOT / "tether/feedback.py").read_text()
        anchor = "SET conflict=1,conflict_digest=COALESCE"
        self.assertEqual(source.count(anchor), 1)
        path = self.root / "mutant.py"
        path.write_text(
            source.replace(anchor, "SET conflict=0,conflict_digest=COALESCE")
        )
        spec = importlib.util.spec_from_file_location("tether.mutant_feedback", path)
        if spec is None or spec.loader is None:
            self.fail("mutation loader unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        self.addCleanup(sys.modules.pop, spec.name)
        spec.loader.exec_module(module)

        def authorize_mutant(identity: Any, event_sha: str, target_sha: str) -> Any:
            return module.FeedbackGrant(
                identity,
                event_sha,
                target_sha,
                "retention-policy-1",
                "retention-grant-1",
            )

        mutant = module.FeedbackStore(
            self.path, self.journal, authenticate, authorize_mutant, target_authority
        )
        self.addCleanup(mutant.close)
        raw = self.raw(judgment="negative")
        self.assertEqual(
            mutant.ingest(raw, proof(raw), envelope(), PAYLOAD), "conflict"
        )
        self.assertEqual(
            self.app.evidence("synthetic", "feedback-1")["state"],
            "active",
            "mutant must expose missing conflict fence through real store",
        )

    def test_oversized_and_noncanonical_inputs_cannot_poison_history(self) -> None:
        self.ingest(self.raw())
        invalid = [
            self.raw() + b" ",
            self.raw().replace(b'"revision":1', b'"revision":1,"revision":1'),
            self.raw(correction="x" * 262144, judgment="correction"),
        ]
        for raw in invalid:
            with self.subTest(size=len(raw)), self.assertRaises(Rejected):
                self.ingest(raw)
        self.assertEqual(
            self.app.evidence("synthetic", "feedback-1")["state"], "active"
        )

    def test_concurrent_connections_retain_one_copy(self) -> None:
        raw = self.raw()

        def work() -> str:
            journal = ProviderJournal(str(self.root / "journal.db"))
            app = FeedbackStore(
                self.path, journal, authenticate, retention, target_authority
            )
            try:
                return app.ingest(raw, proof(raw), envelope(), PAYLOAD)
            finally:
                app.close()
                journal.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(work), pool.submit(work)
            results = sorted((first.result(timeout=10), second.result(timeout=10)))
        self.assertEqual(results, ["duplicate", "retained"])
        self.assertEqual(
            len(self.app.evidence("synthetic", "feedback-1")["revisions"]), 1
        )
        self.assertNotIn(proof(raw), str(list(self.app.db.iterdump())))

    def test_historical_target_does_not_become_new_revision_or_authority(self) -> None:
        admission = self.journal.admission
        self.assertIsNotNone(admission)
        if admission is None:
            self.fail("fixture admission missing")
        newer = event(2)
        admission.authorize = (
            lambda i, d: grant(newer)
            if i == IDENTITY and d == grant(newer).event_digest
            else None
        )
        admission.ingest(canonical(newer), proof(canonical(newer)))
        # The separate explicit artifact verifier permits this historical target.
        self.assertEqual(self.ingest(self.raw()), "retained")
        evidence = self.app.evidence("synthetic", "feedback-1")
        self.assertEqual(
            evidence["revisions"][0]["event"]["target"]["task_revision"], 1
        )
        self.assertEqual(evidence["core_acceptance"], "not_established")
        self.assertFalse(evidence["collection_allowed"] or evidence["training_allowed"])

    def test_target_verifier_cannot_rewrite_authenticated_event(self) -> None:
        def attempt_repair(raw: bytes, payload: Any, target: dict[str, Any]) -> bool:
            target.update(self.target)
            return True

        self.app.verify_target = attempt_repair
        raw = self.raw(target={**self.target, "artifact_sha256": "0" * 64})
        with self.assertRaises(Rejected):
            self.ingest(raw)
        self.assertEqual(
            self.app.db.execute("SELECT count(*) FROM feedback_heads").fetchone()[0], 0
        )

    def test_ephemeral_or_uri_database_names_rejected_before_connect(self) -> None:
        paths: tuple[Any, ...] = (
            "",
            ":memory:",
            "file::memory:",
            "file::memory:?cache=shared",
            "file:feedback?mode=memory&cache=shared",
            "file:feedback.sqlite",
            None,
            b":memory:",
            True,
        )
        with patch(
            "tether.feedback.sqlite3.connect",
            side_effect=AssertionError("connection must not occur"),
        ) as connect:
            for path in paths:
                with self.subTest(path=path), self.assertRaises(Rejected):
                    FeedbackStore(
                        path, self.journal, authenticate, retention, target_authority
                    )
            connect.assert_not_called()
