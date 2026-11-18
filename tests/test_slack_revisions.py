"""Controlled signed callbacks; real HMAC/SQLite, no live Slack authority."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_slack_ingress import (
    NOW,
    ROUTE,
    SECRET,
    callback,
    headers,
    normalized,
    wire,
)
from tether.admission import Grant, Identity, Rejected, canonical
from tether.intent import expected_task_id
from tether.semantic_journal import IntentReferences
from tether.slack_revisions import SignedRevisionIngress, _order, _version


def changed(
    previous: dict[str, Any] | None = None, revision: int = 2
) -> dict[str, Any]:
    previous = copy.deepcopy(previous or callback()["event"])
    previous.pop("channel", None)
    current = copy.deepcopy(previous)
    current["text"] = f"synthetic edit {revision}"
    current["edited"] = {
        "user": ROUTE.actor_id,
        "ts": f"1900000000.{revision + 10:06d}",
    }
    value = callback()
    value["event_id"] = f"EvEDIT{revision}"
    value["event"] = dict(
        type="message",
        subtype="message_changed",
        hidden=True,
        channel=ROUTE.channel_id,
        ts="1900000010.000000",
        message=current,
        previous_message=previous,
    )
    return value


class SignedRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "revisions.sqlite")
        self.allowed: dict[str, Grant] = {}
        source = dict(
            app_id=ROUTE.app_id,
            account_id="acct-synthetic",
            actor_id=ROUTE.actor_id,
            workspace_id=ROUTE.workspace_id,
            channel_id=ROUTE.channel_id,
            thread_id=ROUTE.thread_ts,
            message_id="1900000000.000002",
        )
        self.task = expected_task_id(source)
        self.app = self.open()
        self.addCleanup(lambda: self.app.close())
        self.network = patch("socket.socket", side_effect=AssertionError("no network"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def open(self) -> SignedRevisionIngress:
        return SignedRevisionIngress(
            self.path,
            SECRET,
            ROUTE,
            lambda: NOW,
            account_id="acct-synthetic",
            authorize=lambda identity, digest: self.allowed.get(digest),
            references=lambda env: IntentReferences(
                "v3-" + str(env["binding"]["revision"]),
                "delivery-" + str(env["binding"]["revision"]),
            ),
        )

    def approve(self, value: dict[str, Any], revision: int) -> None:
        edit = revision > 1
        text = value["event"]["message"]["text"] if edit else value["event"]["text"]
        event = normalized(
            event_id=value["event_id"],
            revision=revision,
            kind="edit" if edit else "create",
            text=text,
        )
        digest = hashlib.sha256(canonical(event)).hexdigest()
        self.allowed[digest] = Grant(
            ROUTE.identity,
            digest,
            self.task,
            revision,
            f"op-{revision}",
            "policy",
            "host",
            1,
            f"raw-{revision}",
            "slack-install",
        )

    def send(self, value: dict[str, Any], revision: int) -> str:
        self.approve(value, revision)
        raw = wire(value)
        return self.app.ingest(raw, headers(raw))

    def dump(self) -> str:
        return "\n".join(self.app.admission.db.iterdump())

    def deny(self, value: dict[str, Any], revision: int) -> None:
        before = self.dump()
        with self.assertRaises((Rejected, ValueError)):
            self.send(value, revision)
        self.assertEqual(before, self.dump())

    def test_chain_retry_and_reopen(self) -> None:
        self.send(callback(), 1)
        second = changed()
        self.send(second, 2)
        third = changed(second["event"]["message"], 3)
        self.send(third, 3)
        before = self.dump()
        self.assertEqual(self.send(second, 2), "duplicate")
        self.assertEqual(before, self.dump())
        self.app.close()
        self.app = self.open()
        self.assertEqual(self.send(second, 2), "duplicate")
        batch = self.app.admission.snapshot_batch(self.task)
        self.assertEqual(len(json.loads(batch)["intents"]), 3)
        self.assertNotIn(b"synthetic edit", batch)

    def test_ambiguous_editor_and_source_denied(self) -> None:
        self.send(callback(), 1)
        paths = [
            ("message", "edited", "user"),
            ("message", "user"),
            ("previous_message", "user"),
            ("message", "ts"),
            ("message", "thread_ts"),
        ]
        for path in paths:
            value = changed()
            target = value["event"]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = "UOTHER"
            self.deny(value, 2)
        for field in ["edited", "user"]:
            value = changed()
            del value["event"]["message"][field]
            self.deny(value, 2)
        for field in ["bot_id", "subtype", "files", "blocks", "app_id"]:
            value = changed()
            value["event"]["message"][field] = []
            self.deny(value, 2)

    def test_predecessor_order_and_retry(self) -> None:
        value = changed()
        self.deny(value, 2)
        self.send(callback(), 1)
        wrong = copy.deepcopy(value)
        wrong["event"]["previous_message"]["text"] = "different"
        self.deny(wrong, 2)
        wrong = copy.deepcopy(value)
        wrong["event"]["message"]["edited"]["ts"] = "1900000000.000002"
        self.deny(wrong, 2)
        self.send(value, 2)
        stale = changed(revision=3)
        self.deny(stale, 3)

    def test_callback_conflict_delete_and_signature(self) -> None:
        self.send(callback(), 1)
        value = changed()
        self.send(value, 2)
        altered = copy.deepcopy(value)
        altered["event_time"] = NOW + 1
        self.deny(altered, 2)
        delete = callback(subtype="message_deleted", deleted_ts="1900000000.000002")
        self.deny(delete, 1)
        raw = wire(changed(value["event"]["message"], 3))
        before = self.dump()
        with self.assertRaises(Rejected):
            self.app.ingest(raw, headers(raw, secret=b"wrong"))
        self.assertEqual(before, self.dump())

    def test_deleted_previous_author_is_not_deleter(self) -> None:
        self.send(callback(), 1)
        value = callback()
        value["event_id"] = "EvDELETEDORIGINALAUTHOR"
        previous = copy.deepcopy(callback()["event"])
        value["event"] = dict(
            type="message",
            subtype="message_deleted",
            hidden=True,
            channel=ROUTE.channel_id,
            ts="1900000010.000000",
            event_ts="1900000010.000000",
            deleted_ts=previous["ts"],
            previous_message=previous,
        )
        # A framework may expose previous_message.user, but it proves authorship,
        # not who deleted the message. Even a valid signature grants no actor.
        self.assertEqual(previous["user"], ROUTE.actor_id)
        before = self.dump()
        raw = wire(value)
        with patch.object(
            self.app.admission,
            "authorize",
            side_effect=AssertionError("must not resolve deletion authority"),
        ) as authorize:
            with self.assertRaises(Rejected):
                self.app.ingest(raw, headers(raw))
            authorize.assert_not_called()
        self.assertEqual(before, self.dump())

    def test_revocation_and_atomic_hook_rollback(self) -> None:
        raw = wire(callback())
        with self.assertRaises(Rejected):
            self.app.ingest(raw, headers(raw))
        before = self.dump()
        store = self.app.admission
        original = store._retained_extension

        def fail(*args: Any) -> None:
            original(*args)
            raise RuntimeError("controlled precommit crash")

        with patch.object(store, "_retained_extension", side_effect=fail):
            with self.assertRaises(RuntimeError):
                self.send(callback(), 1)
        self.assertEqual(before, self.dump())
        self.send(callback(), 1)

    def test_provider_head_corruption_fails_closed(self) -> None:
        self.send(callback(), 1)
        self.app.admission.db.execute(
            "UPDATE slack_versions SET content_sha256=?", ("0" * 64,)
        )
        self.deny(changed(), 2)

    def test_competing_prepared_edit_rolls_back(self) -> None:
        from tether.slack_revisions import _observe

        self.send(callback(), 1)
        second = changed()
        self.approve(second, 2)
        raw, proof = self.app.admission.prepare(
            _observe(second, ROUTE), hashlib.sha256(wire(second)).hexdigest()
        )
        other = self.open()
        try:
            competing = copy.deepcopy(second)
            competing["event_id"] = "EvCOMPETING"
            competing["event"]["message"]["text"] = "winning edit"
            self.approve(competing, 2)
            body = wire(competing)
            other.ingest(body, headers(body))
            before = self.dump()
            with self.assertRaises(Rejected):
                self.app.admission.ingest(raw, proof)
            self.assertEqual(before, self.dump())
        finally:
            other.close()

    def test_reentrant_authorizer_denied(self) -> None:
        self.approve(callback(), 1)
        raw = wire(callback())
        original = self.app.admission.authorize
        if original is None:
            self.fail("fixture authority callback is required")
        attempts = []

        def authorize(identity: Identity, digest: str) -> Grant | None:
            with self.assertRaises(Rejected):
                self.app.ingest(raw, headers(raw))
            attempts.append(True)
            return original(identity, digest)

        self.app.admission.authorize = authorize
        self.app.ingest(raw, headers(raw))
        self.assertTrue(attempts)
        self.app.admission.authorize = original
        self.assertEqual(self.app.ingest(raw, headers(raw)), "duplicate")

    def test_previous_edit_token_and_wrapper_not_interchangeable(self) -> None:
        self.send(callback(), 1)
        second = changed()
        self.send(second, 2)
        third = changed(second["event"]["message"], 3)
        wrong = copy.deepcopy(third)
        wrong["event"]["previous_message"]["edited"]["ts"] = "1900000000.000011"
        self.deny(wrong, 3)
        wrong = copy.deepcopy(third)
        del wrong["event"]["message"]["edited"]
        self.deny(wrong, 3)
        third["event"]["ts"] = "1800000000.000000"
        self.send(third, 3)

    def test_nested_channel_and_metadata_only_denied(self) -> None:
        self.send(callback(), 1)
        for field in ("message", "previous_message"):
            value = changed()
            value["event"][field]["channel"] = "COTHER"
            self.deny(value, 2)
        second = changed()
        self.send(second, 2)
        value = changed(second["event"]["message"], 3)
        value["event"]["message"]["edited"]["ts"] = second["event"]["message"][
            "edited"
        ]["ts"]
        self.deny(value, 3)

    def test_fresh_process_retains_provider_and_candidate(self) -> None:
        self.send(callback(), 1)
        self.send(changed(), 2)
        code = """
import json, sys
from tests.test_slack_ingress import SECRET, ROUTE, NOW
from tether.slack_revisions import SignedRevisionIngress
app = SignedRevisionIngress(sys.argv[1], SECRET, ROUTE, lambda: NOW, account_id='acct-synthetic')
rows = app.admission.db.execute('SELECT scope,revision,version_ts FROM slack_versions').fetchall()
assert len(rows) == 1 and rows[0][1:] == ('2','1900000000.000012')
assert len(app.admission._provider_head(rows[0][0])) == 1
assert len(json.loads(app.admission.snapshot_batch(sys.argv[2]))['intents']) == 2
app.close()
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, self.path, self.task],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_provider_hook_detected(self) -> None:
        from tether.semantic_journal import SemanticAdmission

        store = self.app.admission
        with patch.object(
            store,
            "_retained_extension",
            side_effect=lambda *args: SemanticAdmission._retained_extension(
                store, *args
            ),
        ):
            self.send(callback(), 1)
        # A mutated hook cannot fabricate provider continuity from semantic history.
        self.assertEqual(
            store.db.execute("SELECT count(*) FROM slack_versions").fetchone()[0], 0
        )
        self.deny(changed(), 2)

    def test_exact_integer_timestamp(self) -> None:
        self.assertEqual(
            _order("9007199254740992.000002") - _order("9007199254740992.000001"), 1
        )
        with self.assertRaises(ValueError):
            _version("01900000000.000001")


if __name__ == "__main__":
    unittest.main()
