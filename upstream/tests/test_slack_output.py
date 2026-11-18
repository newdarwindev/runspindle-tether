"""Actual original SlackBridge/Manager/SQLModel, synthetic single-attempt client."""

import asyncio
import importlib
import os
import tempfile
import unittest
from unittest.mock import patch

from runspindle_tether.authority import AuthorityGate, Denied, VerifiedAction, digest
from runspindle_tether.upstream_outbox import DeliveryCancelled, Outbox
from runspindle_tether.upstream_runtime import Sidecar
from runspindle_tether.upstream_slack_output import SlackOutput

original = importlib.import_module("agent_tether.slack.bot")
config = importlib.import_module("agent_tether").BridgeConfig
upstream_db = importlib.import_module("tether.db")


class SlackOutputTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("TETHER_AGENT_DATA_DIR")
        os.environ["TETHER_AGENT_DATA_DIR"] = self.temp.name
        upstream_db.reset_engine()
        upstream_db.init_db()
        self.payload = {
            "text": "synthetic final",
            "turn_id": "turn",
            "platform": "slack",
        }
        self.action = VerifiedAction(
            "event",
            "actor",
            "workspace",
            "channel",
            "thread",
            "message",
            "session",
            "host",
            7,
            "output",
            digest(self.payload),
        )
        self.bridge = original.SlackBridge(
            "synthetic-unused-token", "channel", config=config(data_dir=self.temp.name)
        )
        self.bridge._thread_ts["session"] = "thread"
        self.posts: list[tuple[str, str, str]] = []
        self.allowed = True
        self.outcome = "unknown"

        async def observe(action: VerifiedAction, payload: object) -> str:
            return self.outcome

        async def send(channel: str, thread: str, text: str) -> object:
            self.posts.append((channel, thread, text))
            raise TimeoutError("SECRET_CANARY")

        self.box = Outbox(lambda _: self.allowed, observe)
        self.client = SlackOutput(self.bridge, self.box, lambda _: self.allowed, send)

        async def deny(action: VerifiedAction, payload: object) -> object:
            raise Denied("input not qualified here")

        self.gate = AuthorityGate(
            lambda *args: self.action, lambda _: self.allowed, deny, self.client.execute
        )
        self.sidecar = Sidecar(self.gate)
        self.sidecar.manager.register_bridge("slack", self.bridge)

    def tearDown(self) -> None:
        upstream_db.reset_engine()
        if self.old is None:
            os.environ.pop("TETHER_AGENT_DATA_DIR", None)
        else:
            os.environ["TETHER_AGENT_DATA_DIR"] = self.old
        self.temp.cleanup()

    async def invoke(self) -> object:
        return await self.gate.dispatch(
            b"synthetic-original-authenticated",
            (),
            lambda: self.sidecar.final_output(
                "session", "synthetic final", "turn", "slack"
            ),
        )

    async def test_actual_original_output_and_unknown_readback_no_repost(self) -> None:
        with patch.object(original.logger, "exception") as logger:
            await self.invoke()
            self.outcome = "confirmed"
            await self.invoke()
        self.assertEqual(self.posts, [("channel", "thread", "synthetic final")])
        logger.assert_not_called()

    async def test_unscoped_original_method_cannot_send(self) -> None:
        await self.bridge.on_output("session", "synthetic final", {})
        self.assertEqual(self.posts, [])

    async def test_current_destination_mutation_before_post_is_denied(self) -> None:
        def revoke(action: VerifiedAction) -> bool:
            self.bridge._thread_ts["session"] = "different"
            return True

        self.client.authorize = revoke
        await self.invoke()
        self.assertEqual(self.posts, [])

    async def test_original_scope_cannot_escape_to_child_task_or_late_call(
        self,
    ) -> None:
        async def route() -> None:
            await asyncio.create_task(
                self.bridge.on_output("session", "synthetic final", {})
            )

        self.assertEqual(
            await self.client.execute(self.action, self.payload, route), "unknown"
        )
        await self.bridge.on_output("session", "synthetic final", {})
        self.assertEqual(self.posts, [])

    async def test_wrong_text_extra_fields_and_duplicate_sdk_call_are_denied(
        self,
    ) -> None:
        async def route() -> None:
            await self.client.chat_postMessage(
                channel="channel", thread_ts="thread", text="different"
            )
            await self.bridge.on_output("session", "synthetic final", {})

        await self.client.execute(self.action, self.payload, route)
        self.assertEqual(self.posts, [])

    async def test_current_authority_failure_is_not_logged_by_original_bridge(
        self,
    ) -> None:
        def fail(action: VerifiedAction) -> bool:
            raise ValueError("SECRET_CANARY")

        self.client.authorize = fail
        with patch.object(original.logger, "exception") as logger:
            await self.invoke()
        logger.assert_not_called()
        self.assertEqual(self.posts, [])

    async def test_interrupt_after_transport_entry_retains_unknown_and_scope_closes(
        self,
    ) -> None:
        async def interrupted(channel: str, thread: str, text: str) -> object:
            self.posts.append((channel, thread, text))
            raise asyncio.CancelledError("SECRET_CANARY")

        self.client.send_once = interrupted
        with self.assertRaises(DeliveryCancelled) as caught:
            await self.invoke()
        self.assertIsNone(caught.exception.__context__)
        await self.invoke()
        await self.bridge.on_output("session", "synthetic final", {})
        self.assertEqual(len(self.posts), 1)

    async def test_active_client_cannot_be_silently_replaced(self) -> None:
        with self.assertRaises(Denied):
            SlackOutput(self.bridge, self.box, lambda _: True, self.client.send_once)
        self.assertEqual(self.posts, [])

    async def test_extra_sdk_fields_cannot_expand_output(self) -> None:
        async def route() -> None:
            await self.client.chat_postMessage(
                channel="channel",
                thread_ts="thread",
                text="synthetic final",
                username="other",
            )

        await self.client.execute(self.action, self.payload, route)
        self.assertEqual(self.posts, [])

    async def test_original_channel_change_before_scope_is_denied(self) -> None:
        self.bridge._channel_id = "another-channel"
        with self.assertRaises(Denied):
            await self.invoke()
        self.assertEqual(self.posts, [])
