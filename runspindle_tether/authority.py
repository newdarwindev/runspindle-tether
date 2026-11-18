"""Actor-preserving pre-effect seam; upstream callbacks alone convey no authority."""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Awaitable, Callable


class Denied(RuntimeError):
    pass


def digest(value: object) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class VerifiedAction:
    """Constructed only by the injected original-event authentication boundary."""

    event_id: str
    actor_id: str
    workspace_id: str
    channel_id: str
    thread_id: str
    message_id: str
    session_id: str
    host_id: str
    lease_epoch: int
    action: str
    payload_sha256: str


@dataclass
class _Invocation:
    action: VerifiedAction
    task: object
    consumed: bool = False
    active: bool = True


class AuthorityGate:
    def __init__(
        self,
        authenticate: Callable[..., VerifiedAction],
        authorize: Callable[..., bool],
        execute: Callable[..., Awaitable[object]],
        output_execute: Callable[
            [VerifiedAction, object, Callable[[], Awaitable[object]]], Awaitable[object]
        ]
        | None = None,
    ) -> None:
        self.authenticate, self.authorize, self.execute = (
            authenticate,
            authorize,
            execute,
        )
        self.output_execute = output_execute
        self._current: contextvars.ContextVar[_Invocation | None] = (
            contextvars.ContextVar("actor", default=None)
        )

    async def dispatch(
        self,
        original_bytes: bytes,
        headers: tuple[tuple[str, str], ...],
        callback: Callable[[], Awaitable[object]],
    ) -> object:
        verified = self.authenticate(original_bytes, headers)
        if type(verified) is not VerifiedAction:
            raise Denied("authenticated original actor context required")
        if any(
            type(x) is not str or not x or len(x) > 512
            for x in (
                verified.event_id,
                verified.actor_id,
                verified.workspace_id,
                verified.channel_id,
                verified.thread_id,
                verified.message_id,
                verified.session_id,
                verified.host_id,
            )
        ):
            raise Denied("complete bounded actor and owner identity required")
        if (
            verified.action
            not in ("send_input", "stop_session", "permission", "output")
            or type(verified.payload_sha256) is not str
            or re.fullmatch("[0-9a-f]{64}", verified.payload_sha256) is None
        ):
            raise Denied("exact supported action and digest required")
        if type(verified.lease_epoch) is not int or verified.lease_epoch < 0:
            raise Denied("exact lease epoch required")
        invocation = _Invocation(verified, asyncio.current_task())
        token = self._current.set(invocation)
        try:
            return await callback()
        finally:
            invocation.active = False
            self._current.reset(token)

    async def effect(
        self,
        action: str,
        session_id: str,
        payload: object,
        operation: Callable[[], Awaitable[object]] | None = None,
    ) -> object:
        current = self._current.get()
        if (
            current is None
            or not current.active
            or current.consumed
            or current.task is not asyncio.current_task()
        ):
            raise Denied("one original-event invocation required")
        expected = current.action
        if (action, session_id, digest(payload)) != (
            expected.action,
            expected.session_id,
            expected.payload_sha256,
        ):
            raise Denied("action/session/content mismatch")
        current.consumed = True
        if self.authorize(expected) is not True:
            raise Denied("current Core authority denied")
        # Only the authoritative output boundary may invoke an outbound route.
        if operation is not None:
            if action != "output" or self.output_execute is None:
                raise Denied("authoritative output executor required")
            route_used = False

            async def scoped_route() -> object:
                nonlocal route_used
                if (
                    route_used
                    or self._current.get() is not current
                    or not current.active
                    or current.task is not asyncio.current_task()
                    or digest(payload) != expected.payload_sha256
                ):
                    raise Denied("output route escaped its original invocation")
                route_used = True
                if self.authorize(expected) is not True:
                    raise Denied("output authority revoked before actual dispatch")
                if self._current.get() is not current or not current.active:
                    raise Denied("output invocation changed during authorization")
                return await operation()

            return await self.output_execute(expected, payload, scoped_route)
        if action == "output":
            raise Denied(
                "output requires its authoritative executor and deferred route"
            )
        return await self.execute(expected, payload)
