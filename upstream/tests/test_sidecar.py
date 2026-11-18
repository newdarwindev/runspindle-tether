import asyncio
import dataclasses
import importlib
import unittest
from typing import Any, Awaitable, Callable

from runspindle_tether.authority import AuthorityGate, Denied, VerifiedAction, digest
from runspindle_tether.upstream_runtime import Sidecar

BridgeCallbacks = importlib.import_module("agent_tether").BridgeCallbacks
BridgeManager = importlib.import_module("agent_tether").BridgeManager
BridgeTurnAccumulator = importlib.import_module(
    "tether.bridges.turn_accumulator"
).BridgeTurnAccumulator


class SidecarTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.effects: list[tuple[VerifiedAction, object]] = []
        self.allowed = True
        self.action = VerifiedAction(
            "event1",
            "actor",
            "workspace",
            "channel",
            "thread",
            "message",
            "session",
            "host",
            7,
            "send_input",
            digest({"text": "approved"}),
        )

        def authenticate(
            raw: bytes, headers: tuple[tuple[str, str], ...]
        ) -> VerifiedAction:
            if raw != b"original-signed-event" or headers != (
                ("signature", "verified-fixture"),
            ):
                raise Denied("signature mismatch")
            return self.action

        async def execute(action: VerifiedAction, payload: object) -> object:
            self.effects.append((action, payload))
            return True

        self.gate = AuthorityGate(authenticate, lambda _: self.allowed, execute)
        self.sidecar = Sidecar(self.gate)

    async def invoke(self, callback: Callable[[], Awaitable[object]]) -> object:
        return await self.gate.dispatch(
            b"original-signed-event", (("signature", "verified-fixture"),), callback
        )

    async def test_actual_upstream_types_and_one_native_owner(self) -> None:
        self.assertIsInstance(self.sidecar.manager, BridgeManager)
        self.assertIsInstance(self.sidecar.callbacks, BridgeCallbacks)
        self.assertIsInstance(self.sidecar.turns, BridgeTurnAccumulator)
        await self.invoke(
            lambda: self.sidecar.callbacks.send_input("session", "approved")
        )
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.effects[0][0].host_id, "host")
        self.assertEqual(self.effects[0][0].lease_epoch, 7)
        with self.assertRaises(Denied):
            await self.sidecar.callbacks.create_session(directory="/tmp")
        with self.assertRaises(Denied):
            await self.sidecar.callbacks.attach_external("other")

    async def test_missing_actor_context_and_autoapproval_denied(self) -> None:
        with self.assertRaises(Denied):
            await self.sidecar.callbacks.send_input("session", "approved")
        with self.assertRaises(Denied):
            await self.sidecar.callbacks.respond_to_permission(
                "session", "request", True
            )
        self.assertEqual(self.effects, [])

    async def test_exact_action_content_and_session(self) -> None:
        for session, text in [("other", "approved"), ("session", "changed")]:
            with self.assertRaises(Denied):
                await self.invoke(lambda: self.sidecar.send_input(session, text))
        self.allowed = False
        with self.assertRaises(Denied):
            await self.invoke(lambda: self.sidecar.send_input("session", "approved"))
        self.assertEqual(self.effects, [])

    async def test_original_event_verified_before_callback(self) -> None:
        with self.assertRaises(Denied):
            await self.gate.dispatch(
                b"copied-json",
                (),
                lambda: self.sidecar.send_input("session", "approved"),
            )
        self.assertEqual(self.effects, [])

    async def test_context_cannot_escape_into_child_task(self) -> None:
        async def callback() -> None:
            await asyncio.create_task(self.sidecar.send_input("session", "approved"))

        with self.assertRaises(Denied):
            await self.invoke(callback)
        self.assertEqual(self.effects, [])

    async def test_one_effect_per_callback_and_unknown_not_retried(self) -> None:
        async def uncertain(action: VerifiedAction, payload: object) -> object:
            self.effects.append((action, payload))
            raise TimeoutError("ambiguous")

        self.gate.execute = uncertain

        async def callback() -> None:
            with self.assertRaises(TimeoutError):
                await self.sidecar.send_input("session", "approved")
            with self.assertRaises(Denied):
                await self.sidecar.send_input("session", "approved")

        await self.invoke(callback)
        self.assertEqual(len(self.effects), 1)

    async def test_actual_upstream_output_accumulation_and_route(self) -> None:
        observed: list[object] = []

        class Boundary:
            async def on_output(
                self, session: str, text: str, metadata: dict[str, Any]
            ) -> None:
                observed.append((session, text, metadata))

        self.sidecar.manager.register_bridge("synthetic", Boundary())

        async def output_execute(
            action: VerifiedAction,
            payload: object,
            route: Callable[[], Awaitable[object]],
        ) -> object:
            self.effects.append((action, payload))
            return await route()

        self.gate.output_execute = output_execute
        payload = {
            "text": "approved final",
            "turn_id": "turn1",
            "platform": "synthetic",
        }
        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest(payload)
        )
        await self.invoke(
            lambda: self.sidecar.final_output(
                "session", "approved final", "turn1", "synthetic"
            )
        )
        self.assertEqual(
            observed, [("session", "approved final", {"turn_id": "turn1"})]
        )
        self.assertEqual(
            len(self.effects), 1
        )  # Authoritative output executor observed.

    async def test_output_exception_is_unknown_not_delivered_or_retried(self) -> None:
        observed: list[object] = []

        class Boundary:
            async def on_output(self, *args: object) -> None:
                observed.append(args)
                raise TimeoutError("lost acknowledgement")

        self.sidecar.manager.register_bridge("synthetic", Boundary())

        async def output_execute(
            action: VerifiedAction,
            payload: object,
            route: Callable[[], Awaitable[object]],
        ) -> object:
            self.effects.append((action, payload))
            return await route()

        self.gate.output_execute = output_execute
        payload = {
            "text": "approved final",
            "turn_id": "turn1",
            "platform": "synthetic",
        }
        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest(payload)
        )
        with self.assertRaises(TimeoutError):
            await self.invoke(
                lambda: self.sidecar.final_output(
                    "session", "approved final", "turn1", "synthetic"
                )
            )
        self.assertEqual(len(observed), 1)

    async def test_queries_and_discovery_default_deny(self) -> None:
        for callback in (
            self.sidecar.callbacks.list_sessions,
            self.sidecar.callbacks.get_usage,
            self.sidecar.callbacks.check_directory,
            self.sidecar.callbacks.list_external_sessions,
            self.sidecar.callbacks.get_external_history,
            self.sidecar.callbacks.sync_session,
        ):
            with self.assertRaises(Denied):
                await callback()

    async def test_incomplete_actor_or_invalid_lease_is_rejected(self) -> None:
        original = self.action
        for change in (
            {"actor_id": ""},
            {"workspace_id": ""},
            {"lease_epoch": True},
            {"payload_sha256": "not-a-hash"},
            {"action": "start_new_agent"},
        ):
            self.action = dataclasses.replace(original, **change)
            with self.assertRaises(Denied):
                await self.invoke(
                    lambda: self.sidecar.send_input("session", "approved")
                )
        self.assertEqual(self.effects, [])

    async def test_scope_is_gone_after_original_callback_returns(self) -> None:
        async def no_effect() -> None:
            return None

        await self.invoke(no_effect)
        with self.assertRaises(Denied):
            await self.sidecar.send_input("session", "approved")
        self.assertEqual(self.effects, [])

    async def test_output_without_executor_and_nonoutput_route_are_denied(self) -> None:
        calls: list[str] = []

        async def route() -> object:
            calls.append("route")
            return None

        async def output_execute(
            action: VerifiedAction,
            payload: object,
            operation: Callable[[], Awaitable[object]],
        ) -> object:
            calls.append("executor")
            return await operation()

        self.gate.output_execute = output_execute
        with self.assertRaises(Denied):
            await self.invoke(
                lambda: self.gate.effect(
                    "send_input", "session", {"text": "approved"}, route
                )
            )
        self.assertEqual(calls, [])
        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest({"text": "approved"})
        )
        self.gate.output_execute = None
        with self.assertRaises(Denied):
            await self.invoke(
                lambda: self.gate.effect(
                    "output", "session", {"text": "approved"}, route
                )
            )
        self.assertEqual(calls, [])

    async def test_durable_output_boundary_denies_replay_after_unknown(self) -> None:
        import sqlite3
        import tempfile

        calls: list[str] = []
        payload = {
            "text": "approved final",
            "turn_id": "turn1",
            "platform": "synthetic",
        }
        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest(payload)
        )

        class Boundary:
            async def on_output(self, *args: object) -> None:
                calls.append("provider")
                raise TimeoutError("lost acknowledgement")

        with tempfile.TemporaryDirectory() as root:
            path = root + "/authoritative.sqlite"
            with sqlite3.connect(path) as db:
                db.execute(
                    "CREATE TABLE effects(event TEXT PRIMARY KEY, identity TEXT, state TEXT)"
                )

            async def output_execute(
                action: VerifiedAction,
                value: object,
                route: Callable[[], Awaitable[object]],
            ) -> object:
                # Test-only durable authority fixture, not a production replacement queue.
                with sqlite3.connect(path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    if db.execute(
                        "SELECT 1 FROM effects WHERE event=?", (action.event_id,)
                    ).fetchone():
                        raise Denied("previous effect requires independent readback")
                    db.execute(
                        "INSERT INTO effects VALUES(?,?,?)",
                        (
                            action.event_id,
                            digest(dataclasses.asdict(action)),
                            "unknown",
                        ),
                    )
                return await route()

            for first in (True, False):
                freshgate = AuthorityGate(
                    self.gate.authenticate,
                    self.gate.authorize,
                    self.gate.execute,
                    output_execute,
                )
                fresh = Sidecar(freshgate)
                fresh.manager.register_bridge("synthetic", Boundary())
                with self.assertRaises(TimeoutError if first else Denied):
                    await freshgate.dispatch(
                        b"original-signed-event",
                        (("signature", "verified-fixture"),),
                        lambda: fresh.final_output(
                            "session", "approved final", "turn1", "synthetic"
                        ),
                    )
            with sqlite3.connect(path) as db:
                self.assertEqual(
                    db.execute("SELECT state FROM effects").fetchall(), [("unknown",)]
                )
        self.assertEqual(calls, ["provider"])

    async def test_deferred_output_route_cannot_survive_invocation(self) -> None:
        saved: list[Callable[[], Awaitable[object]]] = []
        calls: list[str] = []

        async def route() -> object:
            calls.append("provider")
            return None

        async def executor(
            action: VerifiedAction,
            payload: object,
            operation: Callable[[], Awaitable[object]],
        ) -> object:
            saved.append(operation)
            return None

        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest({})
        )
        self.gate.output_execute = executor
        await self.invoke(lambda: self.gate.effect("output", "session", {}, route))
        self.allowed = False
        with self.assertRaises(Denied):
            await saved[0]()
        with self.assertRaises(Denied):
            await asyncio.ensure_future(saved[0]())
        self.assertEqual(calls, [])

    async def test_output_executor_child_task_cannot_dispatch(self) -> None:
        calls: list[str] = []

        async def route() -> object:
            calls.append("provider")
            return None

        async def executor(
            action: VerifiedAction,
            payload: object,
            operation: Callable[[], Awaitable[object]],
        ) -> object:
            return await asyncio.ensure_future(operation())

        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest({})
        )
        self.gate.output_execute = executor
        with self.assertRaises(Denied):
            await self.invoke(lambda: self.gate.effect("output", "session", {}, route))
        self.assertEqual(calls, [])

    async def test_authority_revoked_inside_executor_blocks_actual_route(self) -> None:
        calls: list[str] = []

        async def route() -> object:
            calls.append("provider")
            return None

        async def executor(
            action: VerifiedAction,
            payload: object,
            operation: Callable[[], Awaitable[object]],
        ) -> object:
            self.allowed = False
            return await operation()

        self.action = dataclasses.replace(
            self.action, action="output", payload_sha256=digest({})
        )
        self.gate.output_execute = executor
        with self.assertRaises(Denied):
            await self.invoke(lambda: self.gate.effect("output", "session", {}, route))
        self.assertEqual(calls, [])
