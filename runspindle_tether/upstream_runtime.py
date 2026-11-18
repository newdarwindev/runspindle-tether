"""Actual upstream routing/accumulation with narrow Runspindle authority hooks.

Load in a separate process where `tether` names the pinned upstream application.
No upstream global application/store singleton or agent runner is initialized.
"""
from __future__ import annotations

from agent_tether import BridgeCallbacks, BridgeManager
from tether.bridges.turn_accumulator import BridgeTurnAccumulator
from .authority import AuthorityGate, Denied


class Sidecar:
    def __init__(self, gate: AuthorityGate):
        self.gate = gate
        self.manager = BridgeManager()
        self.turns = BridgeTurnAccumulator()
        self.callbacks = BridgeCallbacks(
            create_session=self.denied, send_input=self.send_input,
            stop_session=self.stop_session, respond_to_permission=self.permission,
            list_sessions=self.denied, get_usage=self.denied,
            check_directory=self.denied, list_external_sessions=self.denied,
            get_external_history=self.denied, attach_external=self.denied,
            sync_session=self.denied,
        )

    async def denied(self, *args, **kwargs):
        raise Denied('unqualified session/discovery/history callback')

    async def send_input(self, session_id: str, text: str) -> None:
        if type(text) is not str or len(text.encode()) > 65536:
            raise Denied('bounded input text required')
        await self.gate.effect('send_input', session_id, {'text': text})

    async def stop_session(self, session_id: str) -> None:
        await self.gate.effect('stop_session', session_id, {})

    async def permission(self, session_id: str, request_id: str, allow: bool, message: str | None = None) -> bool:
        if type(allow) is not bool or type(request_id) is not str or not 1 <= len(request_id) <= 512 or (message is not None and (type(message) is not str or len(message.encode()) > 4096)):
            raise Denied('exact permission decision required')
        result = await self.gate.effect('permission', session_id, {'request_id': request_id, 'allow': allow, 'message': message})
        return result is True

    async def final_output(self, session_id: str, text: str, turn_id: str, platform: str) -> None:
        """Only explicitly authorized final text; no thinking/tool/raw stream forwarding."""
        if type(text) is not str or len(text.encode()) > 65536 or any(type(x) is not str or not 1 <= len(x) <= 512 for x in (turn_id, platform)):
            raise Denied('bounded exact final output required')
        bridge = self.manager.get_bridge(platform)
        if bridge is None:
            raise Denied('no managed bridge registered')
        # This callback must perform original-output privacy and exact-effect authorization.
        proof = {'text': text, 'turn_id': turn_id, 'platform': platform}
        async def route():
            flush = self.turns.final_output(session_id, text, {}, turn_id=turn_id)
            if flush is None:
                return None
            # Callback return is not independent delivery evidence. No mark_final_sent
            # here; the authoritative effect boundary owns deduplication and readback.
            return await self.manager.route_output(session_id, flush.text, platform, flush.metadata)
        await self.gate.effect('output', session_id, proof, route)
