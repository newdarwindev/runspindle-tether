"""Original HMAC verifier to exact upstream action; no network or native runner."""

from __future__ import annotations

import unittest
from dataclasses import replace

from runspindle_tether.authority import AuthorityGate, Denied, VerifiedAction, digest
from runspindle_tether.signed_parent import OwnerBinding, SignedInputAuthenticator
from tests.test_slack_ingress import NOW, ROUTE, SECRET, callback, headers, wire
from tether.admission import Rejected
from tether.slack_ingress import SlackMessageVerifier


class SignedParentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.auth = SignedInputAuthenticator(
            SlackMessageVerifier(SECRET, ROUTE, lambda: NOW),
            OwnerBinding("session", "host", 7),
        )
        self.effects: list[tuple[VerifiedAction, object]] = []

        async def execute(action: VerifiedAction, payload: object) -> object:
            self.effects.append((action, payload))
            return None

        self.gate = AuthorityGate(
            self.auth,
            lambda action: action.host_id == "host" and action.lease_epoch == 7,
            execute,
        )

    async def test_actual_verified_actor_and_owner_reach_effect(self) -> None:
        raw = wire(callback(text="  approved input  "))
        verified = self.auth.verify(raw, headers(raw))
        self.assertEqual(verified.text, "approved input")
        self.assertEqual(verified.action.actor_id, ROUTE.actor_id)
        self.assertEqual(
            verified.action.payload_sha256, digest({"text": "approved input"})
        )
        await self.gate.dispatch(
            raw,
            headers(raw),
            lambda: self.gate.effect("send_input", "session", {"text": verified.text}),
        )
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.effects[0][0], verified.action)

    async def test_signature_actor_scope_and_mutations_deny_before_effect(self) -> None:
        for change in (
            {"user": "UOTHER"},
            {"channel": "COTHER"},
            {"thread_ts": "1900000000.999999"},
            {"subtype": "message_changed"},
            {"bot_id": "BOTHER"},
        ):
            raw = wire(callback(**change))
            with self.assertRaises(Rejected):
                await self.gate.dispatch(
                    raw,
                    headers(raw),
                    lambda: self.gate.effect(
                        "send_input", "session", {"text": "synthetic request"}
                    ),
                )
        raw = wire(callback())
        with self.assertRaises(Rejected):
            self.auth.verify(raw, headers(raw, secret=b"wrong"))
        with self.assertRaises(Rejected):
            self.auth.verify(raw, headers(raw, stamp=NOW - 301))
        self.assertEqual(self.effects, [])

    async def test_changed_payload_and_stale_owner_deny(self) -> None:
        raw = wire(callback())
        with self.assertRaises(Denied):
            await self.gate.dispatch(
                raw,
                headers(raw),
                lambda: self.gate.effect("send_input", "session", {"text": "changed"}),
            )
        self.auth.owner = replace(self.auth.owner, lease_epoch=6)
        with self.assertRaises(Denied):
            await self.gate.dispatch(
                raw,
                headers(raw),
                lambda: self.gate.effect(
                    "send_input", "session", {"text": "synthetic request"}
                ),
            )
        self.assertEqual(self.effects, [])

    async def test_no_command_owner_or_verifier_fallback(self) -> None:
        for text in ("!new", "  !stop  ", "   "):
            raw = wire(callback(text=text))
            with self.assertRaises(Denied):
                self.auth.verify(raw, headers(raw))
        for owner in (
            OwnerBinding("", "host", 7),
            OwnerBinding("session", "host", True),
        ):
            with self.assertRaises(Denied):
                SignedInputAuthenticator(self.auth.verifier, owner)
        self.assertEqual(self.effects, [])
