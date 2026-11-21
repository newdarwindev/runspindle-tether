"""Original HMAC verifier to exact upstream action; no network or native runner."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from runspindle_tether.authority import AuthorityGate, Denied, VerifiedAction, digest
from runspindle_tether.signed_parent import OwnerBinding, SignedInputAuthenticator
from tests.test_slack_ingress import NOW, ROUTE, SECRET, callback, headers, wire
from tether.admission import Grant, Identity, Rejected


def authority(identity: Identity, event_digest: str) -> Grant:
    return Grant(
        identity,
        event_digest,
        "task",
        1,
        "operation",
        "policy",
        "host",
        7,
        "grant",
        "original-slack",
    )


class SignedParentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        parent = tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        self.path = str(Path(parent.name) / "admission.sqlite")
        self.auth = SignedInputAuthenticator.open(
            self.path,
            SECRET,
            ROUTE,
            lambda: NOW,
            OwnerBinding("session", "host", 7),
            authority,
        )
        self.addCleanup(self.auth.close)
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

    async def test_pure_verification_has_no_dispatch_path(self) -> None:
        verifier = SignedInputAuthenticator(self.auth.verifier, self.auth.owner)
        raw = wire(callback())
        self.assertEqual(
            verifier.verify(raw, headers(raw)).action.actor_id, ROUTE.actor_id
        )
        with self.assertRaisesRegex(Denied, "durable signed input admission required"):
            verifier(raw, headers(raw))
        self.assertEqual(self.auth.admission.envelopes(), [])

    async def test_recorded_mirror_does_not_reach_sidecar_callback(self) -> None:
        self.auth.admission.record_mirror(
            ROUTE.workspace_id,
            ROUTE.channel_id,
            ROUTE.thread_ts,
            "1900000000.000002",
        )
        raw = wire(callback())

        async def forbidden() -> object:
            self.fail("recorded mirror reached the upstream callback")

        with self.assertRaisesRegex(Rejected, "mirrored output"):
            await self.gate.dispatch(raw, headers(raw), forbidden)
        self.assertEqual(self.auth.admission.envelopes(), [])
        self.assertEqual(self.effects, [])

    async def test_mismatched_durable_owner_cannot_reach_callback(self) -> None:
        calls = 0

        def changed(identity: Identity, event_digest: str) -> Grant:
            nonlocal calls
            calls += 1
            return replace(
                authority(identity, event_digest),
                host_id="host" if calls == 1 else "other-host",
            )

        auth = SignedInputAuthenticator.open(
            self.path, SECRET, ROUTE, lambda: NOW, self.auth.owner, changed
        )
        self.addCleanup(auth.close)
        gate = AuthorityGate(auth, lambda _: True, self.gate.execute)
        raw = wire(callback())

        async def forbidden() -> object:
            self.fail("different durable owner reached the upstream callback")

        with self.assertRaises(Rejected):
            await gate.dispatch(raw, headers(raw), forbidden)
        self.assertEqual(calls, 2)
        self.assertEqual(auth.admission.envelopes(), [])
        self.assertEqual(self.effects, [])

    async def test_lost_effect_response_and_duplicate_stay_fenced_after_restart(
        self,
    ) -> None:
        root = Path(self.path).parent
        effects_path = root / "effects.sqlite"
        with closing(sqlite3.connect(effects_path)) as ledger, ledger:
            ledger.execute(
                "CREATE TABLE effects(event TEXT, session TEXT, epoch INTEGER)"
            )
        for mode in ("initial", "replay", "replay"):
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "unittest",
                    "tests.test_signed_upstream_parent.SignedParentTests.test_restart_probe",
                ],
                env={
                    **os.environ,
                    "SYNTHETIC_PARENT_ROOT": str(root),
                    "SYNTHETIC_PARENT_MODE": mode,
                },
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        with closing(sqlite3.connect(effects_path)) as ledger:
            self.assertEqual(
                ledger.execute("SELECT * FROM effects").fetchall(),
                [("EvSYNTHETIC1", "session", 7)],
            )
        self.assertEqual(len(self.auth.admission.envelopes()), 1)

    async def test_restart_probe(self) -> None:
        root = os.environ.get("SYNTHETIC_PARENT_ROOT")
        if root is None:
            return
        current = Path(root)
        auth = SignedInputAuthenticator.open(
            str(current / "admission.sqlite"),
            SECRET,
            ROUTE,
            lambda: NOW,
            self.auth.owner,
            authority,
        )
        self.addCleanup(auth.close)

        async def execute(action: VerifiedAction, _: object) -> object:
            with closing(sqlite3.connect(current / "effects.sqlite")) as ledger, ledger:
                ledger.execute(
                    "INSERT INTO effects VALUES (?,?,?)",
                    (action.event_id, action.session_id, action.lease_epoch),
                )
            raise RuntimeError("synthetic lost execution response")

        gate = AuthorityGate(auth, lambda _: True, execute)
        raw = wire(callback())
        initial = os.environ["SYNTHETIC_PARENT_MODE"] == "initial"
        with self.assertRaisesRegex(
            RuntimeError if initial else Denied,
            "lost execution response" if initial else "already retained",
        ):
            await gate.dispatch(
                raw,
                headers(raw),
                lambda: gate.effect(
                    "send_input", "session", {"text": "synthetic request"}
                ),
            )

    async def test_changed_payload_and_stale_owner_deny(self) -> None:
        raw = wire(callback())
        with self.assertRaises(Denied):
            await self.gate.dispatch(
                raw,
                headers(raw),
                lambda: self.gate.effect("send_input", "session", {"text": "changed"}),
            )
        self.auth.owner = replace(self.auth.owner, lease_epoch=6)
        with self.assertRaisesRegex(Denied, "durable signed input admission required"):
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
