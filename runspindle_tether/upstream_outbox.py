"""Exact-effect policy over the original upstream BridgeDelivery table.

Isolated upstream process only. Database lifecycle remains with upstream; this
adapter neither creates a database nor starts its retry worker. Reserved statuses
cannot be claimed by that worker. Original model/schema, no parallel ledger.
"""

from __future__ import annotations

import importlib
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from sqlalchemy import text
from sqlmodel import select

from .authority import Denied, VerifiedAction, digest

get_session = importlib.import_module("tether.db").get_session
BridgeDelivery = importlib.import_module("tether.models").BridgeDelivery
settings = importlib.import_module("tether.settings").settings

UNKNOWN = "runspindle_unknown"
CONFIRMED = "runspindle_confirmed"
REJECTED = "runspindle_rejected"
CONFLICT = "runspindle_conflict"
STATES = {UNKNOWN, CONFIRMED, REJECTED, CONFLICT}
CAPACITY = 1024


class DeliveryCancelled(BaseException):
    """Submission may have happened; fresh authority and readback are required."""


class Outbox:
    def __init__(
        self,
        authorize: Callable[[VerifiedAction], bool],
        observe: Callable[[VerifiedAction, object], Awaitable[str]],
    ) -> None:
        self.authorize, self.observe = authorize, observe

    def _allowed(self, action: VerifiedAction) -> None:
        if self.authorize(action) is not True:
            raise Denied("current output authority denied")

    @staticmethod
    def _session() -> Any:
        # Upstream owns schema initialization/migration. Never bootstrap here.
        path = Path(settings.data_dir()) / "sessions.db"
        if not path.is_file() or path.is_symlink():
            raise Denied("existing upstream database required")
        return get_session()

    def _current(
        self, action: VerifiedAction, payload: object, key: str, raw: str
    ) -> None:
        self._allowed(action)
        if self._binding(action, payload) != (key, raw):
            raise Denied("output changed during authority callback")

    @staticmethod
    def _binding(action: VerifiedAction, payload: object) -> tuple[str, str]:
        if type(action) is not VerifiedAction or action.action != "output":
            raise Denied("verified output action required")
        if (
            any(
                type(value) is not str or not value or len(value) > 512
                for value in (
                    action.event_id,
                    action.actor_id,
                    action.workspace_id,
                    action.channel_id,
                    action.thread_id,
                    action.message_id,
                    action.session_id,
                    action.host_id,
                )
            )
            or type(action.lease_epoch) is not int
            or action.lease_epoch < 0
        ):
            raise Denied("bounded exact actor and owner identity required")
        if digest(payload) != action.payload_sha256:
            raise Denied("output commitment mismatch")
        raw = json.dumps(
            {"action": asdict(action), "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(raw.encode()) > 65536:
            raise Denied("output reservation capacity")
        # The event is an existing owner-issued operation, not a retry-generated ID.
        key = "runspindle:" + digest([action.workspace_id, action.event_id])
        return key, raw

    @staticmethod
    def _check(row: Any, action: VerifiedAction, raw: str) -> None:
        if (
            row.payload != raw
            or row.session_id != action.session_id
            or row.platform != "runspindle"
            or row.method != "exact_output"
            or row.status not in STATES
            or row.attempts != 1
        ):
            raise Denied("retained delivery binding conflict")

    def _reserve(self, action: VerifiedAction, key: str, raw: str) -> bool:
        with self._session() as db:
            db.exec(text("BEGIN IMMEDIATE"))
            row = db.exec(
                select(BridgeDelivery).where(BridgeDelivery.delivery_key == key)
            ).first()
            self._allowed(action)
            if row is not None:
                self._check(row, action, raw)
                return False
            count = db.exec(
                text(
                    "SELECT count(*) FROM bridge_deliveries WHERE platform='runspindle' "
                )
            ).scalar_one()
            if count >= CAPACITY:
                raise Denied("retained delivery capacity; no eviction")
            db.add(
                BridgeDelivery(
                    id="rs_" + uuid.uuid4().hex,
                    session_id=action.session_id,
                    platform="runspindle",
                    delivery_key=key,
                    method="exact_output",
                    payload=raw,
                    status=UNKNOWN,
                    attempts=1,
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )
            self._allowed(action)
            db.commit()
            return True

    async def _public(self, operation: Callable[[], Awaitable[str]]) -> str:
        interrupted = False
        try:
            return await operation()
        except Exception:
            pass
        except BaseException:
            interrupted = True
        # Raise outside the handler: neither DB parameters nor callback exception
        # chains cross this public boundary. Unknown reservations remain retained.
        if interrupted:
            raise DeliveryCancelled("output interrupted; reconcile required")
        raise Denied("output authority, binding or storage unavailable")

    async def __call__(
        self,
        action: VerifiedAction,
        payload: object,
        route: Callable[[], Awaitable[object]],
    ) -> str:
        return await self._public(lambda: self._submit(action, payload, route))

    async def reconcile(self, action: VerifiedAction, payload: object) -> str:
        return await self._public(lambda: self._reconcile(action, payload))

    async def _submit(
        self,
        action: VerifiedAction,
        payload: object,
        route: Callable[[], Awaitable[object]],
    ) -> str:
        key, raw = self._binding(action, payload)
        self._current(action, payload, key, raw)
        fresh = self._reserve(action, key, raw)
        self._current(action, payload, key, raw)
        interrupted = False
        if fresh:
            try:
                self._current(action, payload, key, raw)
                await route()
            except Exception:
                # No exception text is logged or retained. Send return is not proof.
                pass
            except BaseException:
                interrupted = True
        if interrupted:
            raise DeliveryCancelled("output interrupted; reconcile required")
        return await self.reconcile(action, payload)

    async def _reconcile(self, action: VerifiedAction, payload: object) -> str:
        key, raw = self._binding(action, payload)
        self._current(action, payload, key, raw)
        with self._session() as db:
            row = db.exec(
                select(BridgeDelivery).where(BridgeDelivery.delivery_key == key)
            ).first()
            if row is None:
                raise Denied("missing retained delivery")
            self._check(row, action, raw)
        interrupted = False
        try:
            outcome = await self.observe(action, payload)
        except Exception:
            outcome = "unknown"
        except BaseException:
            interrupted = True
            outcome = "unknown"
        if interrupted:
            raise DeliveryCancelled("readback interrupted; reconcile required")
        self._current(action, payload, key, raw)
        if type(outcome) is not str or outcome not in (
            "confirmed",
            "rejected",
            "unknown",
        ):
            outcome = "unknown"
        with self._session() as db:
            db.exec(text("BEGIN IMMEDIATE"))
            row = db.exec(
                select(BridgeDelivery).where(BridgeDelivery.delivery_key == key)
            ).first()
            if row is None:
                raise Denied("missing retained delivery")
            self._check(row, action, raw)
            self._current(action, payload, key, raw)
            state = {"confirmed": CONFIRMED, "rejected": REJECTED, "unknown": UNKNOWN}[
                outcome
            ]
            if row.status == CONFLICT or (
                row.status != UNKNOWN and state != UNKNOWN and state != row.status
            ):
                row.status = CONFLICT
                outcome = "unknown"
            elif state != UNKNOWN:
                row.status = state
            db.add(row)
            self._current(action, payload, key, raw)
            db.commit()
        return outcome
