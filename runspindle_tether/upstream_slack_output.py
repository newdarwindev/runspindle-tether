"""Pre-effect gate installed on the actual original SlackBridge client seam.

Trusted isolated process only. Never starts Slack, obtains tokens, or enables SDK
retries. The injected transport must perform at most one external attempt.
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, NoReturn

from .authority import Denied, VerifiedAction, digest
from .upstream_outbox import Outbox

SlackBridge = importlib.import_module("agent_tether.slack.bot").SlackBridge


async def _startup_denied(*args: object, **kwargs: object) -> NoReturn:
    """No SDK construction may replace the scoped client in this process."""
    try:
        raise Denied("upstream Slack startup is not qualified")
    except Denied as error:
        error.__context__ = error.__cause__ = None
        raise


def protect_slack_startup() -> None:
    """Irreversibly deny ordinary start on existing/future original bridges.

    Trusted composition must call this before publishing handlers or retaining
    original bound methods. It does not stop an already started bridge, undo
    network effects, or defend against arbitrary Python class mutation.
    """
    SlackBridge.start = _startup_denied


@dataclass
class _Output:
    action: VerifiedAction
    text: str
    task: object
    used: bool = False
    active: bool = True


class SlackOutput:
    def __init__(
        self,
        bridge: Any,
        outbox: Outbox,
        authorize: Callable[[VerifiedAction], bool],
        send_once: Callable[[str, str, str], Awaitable[object]],
    ) -> None:
        if type(bridge) is not SlackBridge or bridge._client is not None:
            raise Denied("inactive original SlackBridge required")
        # Install before exposing the scoped client; repeated installation is safe.
        protect_slack_startup()
        self.bridge, self.outbox = bridge, outbox
        self.authorize, self.send_once = authorize, send_once
        self._scope: contextvars.ContextVar[_Output | None] = contextvars.ContextVar(
            "original-slack-output", default=None
        )
        bridge._client = self

    def _valid(self, output: _Output) -> bool:
        action = output.action
        return (
            output.active
            and output.task is asyncio.current_task()
            and self.bridge._client is self
            and self.bridge._channel_id == action.channel_id
            and self.bridge._thread_ts.get(action.session_id) == action.thread_id
        )

    async def execute(
        self,
        action: VerifiedAction,
        payload: object,
        route: Callable[[], Awaitable[object]],
    ) -> str:
        if (
            type(payload) is not dict
            or set(payload) != {"text", "turn_id", "platform"}
            or payload["platform"] != "slack"
            or type(payload["text"]) is not str
            or action.action != "output"
            or digest(payload) != action.payload_sha256
        ):
            raise Denied("exact Slack final output required")
        output = _Output(action, payload["text"], asyncio.current_task())
        if not self._valid(output):
            raise Denied("original Slack destination changed")
        if self._scope.get() is not None:
            raise Denied("nested output scope denied")
        token = self._scope.set(output)
        try:
            result: object = await self.outbox(action, payload, route)
            if not isinstance(result, str):
                raise Denied("invalid outbox outcome")
            return result
        finally:
            output.active = False
            self._scope.reset(token)

    async def chat_postMessage(self, **kwargs: object) -> None:
        """Only supported original SDK method; failures cannot reach upstream logger."""
        output = self._scope.get()
        if output is None or output.used or not self._valid(output):
            return
        # Latch before any callback. A callback cannot reopen a second route.
        output.used = True
        try:
            action = output.action
            expected = {
                "channel": action.channel_id,
                "thread_ts": action.thread_id,
                "text": output.text,
            }
            if kwargs != expected or any(type(x) is not str for x in kwargs.values()):
                return
            if self.authorize(action) is not True or not self._valid(output):
                return
            await self.send_once(action.channel_id, action.thread_id, output.text)
        except Exception:
            # The original on_output logs any escaping exception, including its
            # traceback. Keep all provider/callback failure text inside this seam;
            # Outbox's independent observer decides unknown/confirmed/rejected.
            return
