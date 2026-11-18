"""Synthetic signed reaction intake; no external provider effects."""

import hashlib
import json
import unittest
from typing import Any

from tests.test_slack_feedback import Harness
from tests.test_slack_feedback import SignedFeedbackTests as _Setup
from tests.test_slack_ingress import ROUTE, callback, headers, wire
from tether.admission import Rejected, canonical


class ReactionTests(unittest.TestCase):
    h: Harness

    setUp = _Setup.setUp
    effects = _Setup.effects

    def reaction(self, removed: bool = False, **changes: Any) -> bytes:
        value = callback()
        value["event_id"] = "EvRemoved" if removed else "EvAdded"
        value["event"] = dict(
            type="reaction_removed" if removed else "reaction_added",
            user=ROUTE.actor_id,
            reaction="thumbsup",
            event_ts="1900000000.000004",
            item=dict(
                type="message", channel=ROUTE.channel_id, ts=self.h.target.message_id
            ),
        )
        value["event"].update(changes)
        return wire(value)

    def identity(self) -> str:
        return (
            "reaction:"
            + hashlib.sha256(
                canonical(
                    [
                        self.h.app.namespace,
                        ROUTE.actor_id,
                        self.h.target.message_id,
                        "thumbs_up",
                    ]
                )
            ).hexdigest()
        )

    def test_reaction_retention_and_retry(self) -> None:
        raw = self.reaction()
        self.assertEqual(self.h.app.react(raw, headers(raw)), "retained")
        self.assertEqual(self.h.app.react(raw, headers(raw)), "duplicate")
        row = self.h.app.store.db.execute(
            "SELECT body FROM feedback_revisions"
        ).fetchone()
        self.assertIn(b'"judgment":"thumbs_up"', row[0])

    def test_reaction_remove_before_or_after_add(self) -> None:
        app = self.h.make(authorize_invalidation=lambda _: True)
        self.addCleanup(app.close)
        remove = self.reaction(True)
        app.react(remove, headers(remove))
        self.assertTrue(app.store.invalidated(app.namespace, self.identity()))
        add = self.reaction()
        with self.assertRaises(Rejected):
            app.react(add, headers(add))

    def test_reaction_removal_revokes(self) -> None:
        app = self.h.make(authorize_invalidation=lambda _: True)
        self.addCleanup(app.close)
        add, remove = self.reaction(), self.reaction(True)
        app.react(add, headers(add))
        app.react(remove, headers(remove))
        self.assertTrue(app.store.invalidated(app.namespace, self.identity()))
        with self.assertRaises(Rejected):
            app.react(add, headers(add))

    def test_reaction_wrong_bindings_and_signature(self) -> None:
        changes: list[dict[str, Any]] = [
            dict(user="UOTHER"),
            dict(reaction="heart"),
            dict(
                item=dict(
                    type="message", channel=ROUTE.channel_id, ts="1900000000.999999"
                )
            ),
            dict(
                item=dict(
                    type="file", channel=ROUTE.channel_id, ts=self.h.target.message_id
                )
            ),
        ]
        for change in changes:
            raw = self.reaction(**change)
            with self.assertRaises(Rejected):
                self.h.app.react(raw, headers(raw))
        raw = self.reaction()
        with self.assertRaises(Rejected):
            self.h.app.react(raw + b" ", headers(raw))
        with self.assertRaises(Rejected):
            self.h.app.ingest(raw, headers(raw))

    def target_mutation(self, cause: str) -> None:
        from tests.test_feedback_invalidation import mutation

        app = self.h.make(authorize_invalidation=lambda _: True)
        self.addCleanup(app.close)
        add = self.reaction()
        app.react(add, headers(add))
        value = json.loads(mutation(cause, message=self.h.target.message_id))
        if cause == "message_changed":
            value["event"]["message"].update(
                user="UBOT", bot_id="BOUTPUT", subtype="bot_message"
            )
        raw = wire(value)
        self.assertEqual(app.invalidate_target(raw, headers(raw)), "invalidated")
        with self.assertRaises(Rejected):
            app.react(add, headers(add))
        self.assertEqual(
            app.store.evidence(app.namespace, self.identity())["state"], "invalidated"
        )

    def test_bot_target_edit_revokes_reaction(self) -> None:
        self.target_mutation("message_changed")

    def test_target_delete_revokes_reaction(self) -> None:
        self.target_mutation("message_deleted")

    def test_target_deleted_before_reaction_blocks_first_add(self) -> None:
        from tests.test_feedback_invalidation import mutation

        app = self.h.make(authorize_invalidation=lambda _: True)
        self.addCleanup(app.close)
        raw = mutation("message_deleted", message=self.h.target.message_id)
        app.invalidate_target(raw, headers(raw))
        add = self.reaction()
        with self.assertRaises(Rejected):
            app.react(add, headers(add))
        self.assertEqual(
            app.store.db.execute("SELECT count(*) FROM feedback_revisions").fetchone()[
                0
            ],
            0,
        )

    def test_target_fence_racing_retention_is_rechecked(self) -> None:
        from tests.test_feedback_invalidation import mutation

        sibling = self.h.make(authorize_invalidation=lambda _: True)
        self.addCleanup(sibling.close)
        raw = mutation("message_deleted", message=self.h.target.message_id)
        first = True
        original = self.h.app.store.authorize_retention
        if original is None:
            self.fail("fixture authority callback is required")

        def retain(*args: Any) -> Any:
            nonlocal first
            if first:
                first = False
                sibling.invalidate_target(raw, headers(raw))
            return original(*args)

        self.h.app.store.authorize_retention = retain
        add = self.reaction()
        with self.assertRaises(Rejected):
            self.h.app.react(add, headers(add))
        self.assertEqual(
            self.h.app.store.db.execute(
                "SELECT count(*) FROM feedback_revisions"
            ).fetchone()[0],
            0,
        )

    def test_target_mutation_exact_identity_and_authority(self) -> None:
        from tests.test_feedback_invalidation import mutation

        app = self.h.make(authorize_invalidation=lambda _: True)
        self.addCleanup(app.close)
        wrong = mutation("message_deleted", message="1900000000.123456")
        with self.assertRaises(Rejected):
            app.invalidate_target(wrong, headers(wrong))
        raw = mutation("message_changed", message=self.h.target.message_id)
        with self.assertRaises(Rejected):
            self.h.app.invalidate_target(raw, headers(raw))

    def test_reaction_no_implicit_consent(self) -> None:
        app = self.h.make(authorize_retention=None)
        self.addCleanup(app.close)
        raw = self.reaction()
        with self.assertRaises(Rejected):
            app.react(raw, headers(raw))
        raw = self.reaction(True)
        with self.assertRaises(Rejected):
            self.h.app.react(raw, headers(raw))


del _Setup

if __name__ == "__main__":
    unittest.main()
