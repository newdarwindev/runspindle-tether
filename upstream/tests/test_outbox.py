"""Original upstream SQLModel/SQLite, synthetic provider; no application startup."""

import asyncio
import dataclasses
import importlib
import os
import tempfile
import unittest
from typing import Any

from sqlmodel import select

from runspindle_tether.authority import Denied, VerifiedAction, digest
from runspindle_tether.upstream_outbox import (
    CONFLICT,
    UNKNOWN,
    DeliveryCancelled,
    Outbox,
)

upstream_db = importlib.import_module("tether.db")
BridgeDelivery = importlib.import_module("tether.models").BridgeDelivery


class OutboxTests(unittest.IsolatedAsyncioTestCase):
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
        self.allowed = True
        self.posts = 0
        self.outcome = "unknown"

        async def observe(action: VerifiedAction, payload: object) -> str:
            return self.outcome

        self.box = Outbox(lambda _: self.allowed, observe)

    def tearDown(self) -> None:
        upstream_db.reset_engine()
        if self.old is None:
            os.environ.pop("TETHER_AGENT_DATA_DIR", None)
        else:
            os.environ["TETHER_AGENT_DATA_DIR"] = self.old
        self.temp.cleanup()

    async def send(self) -> None:
        self.posts += 1
        raise TimeoutError("SECRET_CANARY")

    def rows(self) -> list[Any]:
        with upstream_db.get_session() as db:
            return list(db.exec(select(BridgeDelivery)).all())

    async def test_original_table_unknown_committed_before_send_and_reopen_no_repost(
        self,
    ) -> None:
        async def route() -> None:
            self.assertEqual(self.rows()[0].status, UNKNOWN)
            await self.send()

        self.assertEqual(await self.box(self.action, self.payload, route), "unknown")
        upstream_db.reset_engine()
        fresh = Outbox(lambda _: True, self.box.observe)
        self.outcome = "confirmed"
        self.assertEqual(await fresh(self.action, self.payload, self.send), "confirmed")
        self.assertEqual(self.posts, 1)
        self.assertEqual(len(self.rows()), 1)
        self.assertNotIn("SECRET_CANARY", repr(self.rows()))

    async def test_original_worker_cannot_claim_reserved_unknown(self) -> None:
        await self.box(self.action, self.payload, self.send)
        # Import singleton only after explicit test temporary HOME/database binding.
        store = importlib.import_module("tether.store").store
        row = self.rows()[0]
        for status in (
            UNKNOWN,
            "runspindle_confirmed",
            "runspindle_rejected",
            CONFLICT,
        ):
            with upstream_db.get_session() as db:
                retained = db.get(BridgeDelivery, row.id)
                retained.status = status
                db.add(retained)
                db.commit()
            self.assertIsNone(store.claim_bridge_delivery(row.id))
            self.assertEqual(
                store.claim_pending_bridge_deliveries("session", "runspindle"), []
            )
        self.assertEqual(self.posts, 1)

    async def test_changed_actor_destination_or_bytes_never_resends(self) -> None:
        await self.box(self.action, self.payload, self.send)
        for field in ("actor_id", "channel_id", "thread_id", "session_id", "host_id"):
            with self.subTest(field=field), self.assertRaises(Denied):
                await self.box(
                    dataclasses.replace(self.action, **{field: "other"}),
                    self.payload,
                    self.send,
                )
        other = dict(self.payload, text="changed")
        with self.assertRaises(Denied):
            await self.box(
                dataclasses.replace(self.action, payload_sha256=digest(other)),
                other,
                self.send,
            )
        self.assertEqual(self.posts, 1)

    async def test_denial_missing_record_and_capacity_never_send(self) -> None:
        self.allowed = False
        with self.assertRaises(Denied):
            await self.box(self.action, self.payload, self.send)
        self.assertEqual(self.rows(), [])
        self.allowed = True
        with self.assertRaises(Denied):
            await self.box.reconcile(self.action, self.payload)
        self.assertEqual(self.posts, 0)

    async def test_cancel_retains_unknown_without_replay(self) -> None:
        async def cancel() -> None:
            self.posts += 1
            raise asyncio.CancelledError("SECRET_CANARY")

        with self.assertRaises(DeliveryCancelled) as caught:
            await self.box(self.action, self.payload, cancel)
        self.assertNotIn("SECRET_CANARY", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(self.rows()[0].status, UNKNOWN)
        self.assertEqual(
            await self.box(self.action, self.payload, self.send), "unknown"
        )
        self.assertEqual(self.posts, 1)

    async def test_conflicting_readback_is_sticky_no_cached_success(self) -> None:
        self.outcome = "confirmed"
        self.assertEqual(
            await self.box(self.action, self.payload, self.send), "confirmed"
        )
        self.outcome = "unknown"
        self.assertEqual(await self.box.reconcile(self.action, self.payload), "unknown")
        self.outcome = "rejected"
        self.assertEqual(await self.box.reconcile(self.action, self.payload), "unknown")
        self.assertEqual(self.rows()[0].status, CONFLICT)
        self.outcome = "confirmed"
        self.assertEqual(await self.box.reconcile(self.action, self.payload), "unknown")

    async def test_callback_revocation_rejects_settlement(self) -> None:
        async def revoked(action: VerifiedAction, payload: object) -> str:
            self.allowed = False
            return "confirmed"

        self.box.observe = revoked
        with self.assertRaises(Denied):
            await self.box(self.action, self.payload, self.send)
        self.assertEqual(self.rows()[0].status, UNKNOWN)
        self.assertEqual(self.posts, 1)

    async def test_authorizer_mutation_before_effect_is_denied(self) -> None:
        calls = 0

        def mutate(action: VerifiedAction) -> bool:
            nonlocal calls
            calls += 1
            if calls == 4:
                self.payload["text"] = "changed"
            return True

        self.box.authorize = mutate
        with self.assertRaises(Denied):
            await self.box(self.action, self.payload, self.send)
        self.assertEqual(self.posts, 0)
        self.assertEqual(self.rows()[0].status, UNKNOWN)

    async def test_observer_mutation_cannot_settle_different_payload(self) -> None:
        async def mutate(action: VerifiedAction, payload: Any) -> str:
            payload["text"] = "changed"
            return "confirmed"

        self.box.observe = mutate
        with self.assertRaises(Denied):
            await self.box(self.action, self.payload, self.send)
        self.assertEqual(self.rows()[0].status, UNKNOWN)

    async def test_readback_interrupt_has_no_secret_exception_chain(self) -> None:
        async def cancel(action: VerifiedAction, payload: object) -> str:
            raise KeyboardInterrupt("SECRET_CANARY")

        self.box.observe = cancel
        with self.assertRaises(DeliveryCancelled) as caught:
            await self.box(self.action, self.payload, self.send)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(self.rows()[0].status, UNKNOWN)

    async def test_capacity_is_checked_in_reservation_transaction(self) -> None:
        from unittest.mock import patch

        with patch("runspindle_tether.upstream_outbox.CAPACITY", 1):
            await self.box(self.action, self.payload, self.send)
            other = dataclasses.replace(self.action, event_id="event-2")
            with self.assertRaises(Denied):
                await self.box(other, self.payload, self.send)
            self.assertEqual(self.posts, 1)
            self.assertEqual(len(self.rows()), 1)

    async def test_uninitialized_upstream_database_not_created(self) -> None:
        from pathlib import Path

        upstream_db.reset_engine()
        new = Path(self.temp.name) / "absent"
        os.environ["TETHER_AGENT_DATA_DIR"] = str(new)
        with self.assertRaises(Denied):
            await self.box(self.action, self.payload, self.send)
        self.assertFalse(new.exists())

    async def test_actual_sidecar_routes_once_and_original_table_owns_replay(
        self,
    ) -> None:
        from runspindle_tether.authority import AuthorityGate
        from runspindle_tether.upstream_runtime import Sidecar

        async def denied(*args: object) -> object:
            raise Denied("not an input test")

        gate = AuthorityGate(
            lambda *args: self.action, lambda action: self.allowed, denied, self.box
        )
        sidecar = Sidecar(gate)
        owner = self

        class Boundary:
            async def on_output(
                self, session: str, text: str, metadata: dict[str, Any]
            ) -> None:
                await owner.send()

        sidecar.manager.register_bridge("slack", Boundary())

        async def invoke() -> None:
            await gate.dispatch(
                b"synthetic-authenticated-input",
                (),
                lambda: sidecar.final_output(
                    "session", "synthetic final", "turn", "slack"
                ),
            )

        await invoke()
        self.assertEqual(self.posts, 1)
        self.outcome = "confirmed"
        await invoke()
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.rows()[0].status, "runspindle_confirmed")

    async def test_concurrent_duplicate_does_not_route_again(self) -> None:
        started, release = asyncio.Event(), asyncio.Event()

        async def paused() -> None:
            self.posts += 1
            started.set()
            await release.wait()

        first = asyncio.create_task(self.box(self.action, self.payload, paused))
        await asyncio.wait_for(started.wait(), timeout=2)
        try:
            self.assertEqual(
                await self.box(self.action, self.payload, self.send), "unknown"
            )
        finally:
            release.set()
            await first
        self.assertEqual(self.posts, 1)

    async def test_fresh_process_reads_original_row_without_reposting(self) -> None:
        import subprocess
        import sys

        await self.box(self.action, self.payload, self.send)
        code = """import asyncio,json,sys
sys.path[:0] = json.loads(sys.argv[1])
from runspindle_tether.authority import VerifiedAction
from runspindle_tether.upstream_outbox import Outbox
async def read(action,payload): return 'confirmed'
async def forbidden(): raise AssertionError('repost attempted')
action=VerifiedAction(**json.loads(sys.argv[2]))
payload=json.loads(sys.argv[3])
result=asyncio.run(Outbox(lambda _:True,read)(action,payload,forbidden))
if result != 'confirmed': raise AssertionError(result)
"""
        import json

        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                code,
                json.dumps(
                    [
                        str(
                            __import__("pathlib").Path(upstream_db.__file__).parents[2]
                        ),
                        *sys.path,
                    ]
                ),
                json.dumps(dataclasses.asdict(self.action)),
                json.dumps(self.payload),
            ],
            env=dict(os.environ),
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.rows()[0].status, "runspindle_confirmed")

    async def test_authorizer_and_storage_errors_do_not_leak_chain(self) -> None:
        from unittest.mock import patch

        def bad(action: VerifiedAction) -> bool:
            raise ValueError("SECRET_CANARY")

        self.box.authorize = bad
        with self.assertRaises(Denied) as caught:
            await self.box(self.action, self.payload, self.send)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("SECRET_CANARY", str(caught.exception))
        self.box.authorize = lambda _: True
        with patch.object(
            self.box, "_session", side_effect=RuntimeError("SECRET_CANARY")
        ):
            with self.assertRaises(Denied) as caught:
                await self.box(self.action, self.payload, self.send)
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn("SECRET_CANARY", str(caught.exception))
        self.assertEqual(self.posts, 0)

    async def test_original_lifecycle_loss_requires_external_retirement_denial(
        self,
    ) -> None:
        await self.box(self.action, self.payload, self.send)
        store = importlib.import_module("tether.store").store
        store.clear_all_data()
        self.assertEqual(self.rows(), [])
        # Missing history never authorizes reconciliation or a retired operation.
        with self.assertRaises(Denied):
            await self.box.reconcile(self.action, self.payload)
        self.allowed = False
        with self.assertRaises(Denied):
            await self.box(self.action, self.payload, self.send)
        self.assertEqual(self.posts, 1)
