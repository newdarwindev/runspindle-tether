"""Real HMAC, existing SQLite consumer, synthetic secrets/authority; no sockets."""

import asyncio
from dataclasses import replace
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import traceback
from typing import Any
import unittest
from unittest.mock import patch

from tether.admission import Grant, Identity, Rejected, canonical
import tether.slack_ingress as ingress
from tether.slack_ingress import Route, SignedSlackIngress

ROOT = Path(__file__).resolve().parents[1]
SECRET = b"synthetic-signing-secret-only-never-an-account"
NOW = 1900000000
ROUTE = Route(
    "ASYNTHETIC", "TSYNTHETIC", "USYNTHETIC", "CSYNTHETIC", "1900000000.000001"
)


def callback(**event_changes: Any) -> dict[str, Any]:
    event = {
        "type": "message",
        "channel": ROUTE.channel_id,
        "user": ROUTE.actor_id,
        "text": "synthetic request",
        "ts": "1900000000.000002",
        "thread_ts": ROUTE.thread_ts,
    }
    event.update(event_changes)
    return {
        "type": "event_callback",
        "api_app_id": ROUTE.app_id,
        "team_id": ROUTE.workspace_id,
        "event_id": "EvSYNTHETIC1",
        "event": event,
        "event_time": NOW,
        "is_ext_shared_channel": False,
        "authorizations": [
            {
                "team_id": ROUTE.workspace_id,
                "user_id": "UBOT",
                "enterprise_id": None,
                "is_bot": True,
                "is_enterprise_install": False,
            }
        ],
    }


def wire(value: dict[str, Any]) -> bytes:
    # Deliberately not the canonical normalized representation consumed by Admission.
    return json.dumps(value, indent=2, ensure_ascii=False).encode()


def headers(
    raw: bytes, stamp: int = NOW, secret: bytes = SECRET
) -> tuple[tuple[str, str], ...]:
    # Independent producer uses hmac.digest, not the implementation's hmac.new.
    signed = hmac.digest(secret, f"v0:{stamp}:".encode() + raw, "sha256").hex()
    return (
        ("Content-Type", "application/json; charset=utf-8"),
        ("X-Slack-Request-Timestamp", str(stamp)),
        ("X-Slack-Signature", "v0=" + signed),
        ("Content-Length", str(len(raw))),
    )


def manual_headers(raw: bytes) -> tuple[tuple[str, str], ...]:
    # Separate HMAC implementation: SHA256 ipad/opad, no hmac module calls.
    key = SECRET.ljust(64, b"\0")
    message = f"v0:{NOW}:".encode() + raw
    inner = hashlib.sha256(bytes(c ^ 0x36 for c in key) + message).digest()
    digest = hashlib.sha256(bytes(c ^ 0x5C for c in key) + inner).hexdigest()
    return (
        ("Content-Type", "application/json"),
        ("X-Slack-Request-Timestamp", str(NOW)),
        ("X-Slack-Signature", "v0=" + digest),
    )


def normalized(**changes: Any) -> dict[str, Any]:
    expected = {
        "version": "runspindle.tether.ingress.v1",
        "event_id": "EvSYNTHETIC1",
        "message_id": "1900000000.000002",
        "actor_id": ROUTE.actor_id,
        "workspace_id": ROUTE.workspace_id,
        "channel_id": ROUTE.channel_id,
        "thread_id": ROUTE.thread_ts,
        "revision": 1,
        "kind": "create",
        "text": "synthetic request",
        "mirrored": False,
    }
    expected.update(changes)
    return expected


def approval(value: dict[str, Any]) -> Grant:
    return Grant(
        ROUTE.identity,
        hashlib.sha256(canonical(value)).hexdigest(),
        "task-synthetic",
        1,
        "operation-synthetic",
        "policy-synthetic",
        "host-synthetic",
        1,
        "grant-synthetic",
        "slack-synthetic-installation",
    )


class SignedIngressTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "admission.db"
        self.allowed: dict[str, Grant] = {}
        self.authority_calls: list[tuple[Identity, str]] = []

        def authorize(identity: Identity, digest: str) -> Grant | None:
            self.authority_calls.append((identity, digest))
            return self.allowed.get(digest)

        self.app = SignedSlackIngress(
            str(self.path), SECRET, ROUTE, lambda: NOW, authorize
        )
        self.addCleanup(self.app.close)
        network = patch.object(
            socket, "socket", side_effect=AssertionError("network forbidden")
        )
        self.network = network.start()
        self.addCleanup(network.stop)
        self.addCleanup(self.network.assert_not_called)

    def allow(self, **changes: Any) -> Grant:
        grant = approval(normalized(**changes))
        self.allowed[grant.event_digest] = grant
        return grant

    def state(self) -> list[str]:
        with sqlite3.connect(self.path) as db:
            return list(db.iterdump())

    def reject(self, raw: bytes, supplied: Any = None, authority: bool = False) -> None:
        before, calls = self.state(), len(self.authority_calls)
        with self.assertRaises(Rejected):
            self.app.ingest(raw, headers(raw) if supplied is None else supplied)
        self.assertEqual(self.state(), before)
        if not authority:
            self.assertEqual(len(self.authority_calls), calls)
        self.network.assert_not_called()

    def test_authenticated_raw_bytes_reach_real_admission_and_exact_envelope(
        self,
    ) -> None:
        grant = self.allow()
        raw = wire(callback())
        self.assertNotEqual(raw, canonical(normalized()))
        self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")
        self.assertEqual(self.authority_calls, [(ROUTE.identity, grant.event_digest)])
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT digest, envelope FROM revisions").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], grant.event_digest)
        result = json.loads(rows[0][1])
        self.assertEqual(result["message_id"], "EvSYNTHETIC1")
        self.assertEqual(
            result["binding"],
            {
                "task_id": grant.task_id,
                "revision": 1,
                "operation_id": grant.operation_id,
                "policy_revision": grant.policy_revision,
                "host_id": grant.host_id,
                "workspace_id": ROUTE.workspace_id,
                "lease_epoch": 1,
            },
        )
        self.assertEqual(result["payload"]["normalized_digest"], grant.event_digest)
        self.assertEqual(
            result["payload"]["delivery_namespace"], grant.delivery_namespace
        )
        for forbidden in [SECRET, b"synthetic request", b"v0="]:
            self.assertNotIn(forbidden, self.path.read_bytes())
        self.assertNotIn(SECRET.decode(), repr(self.app))

    def test_wrong_signature_and_raw_rewrite_never_parse_or_authorize(self) -> None:
        self.allow()
        raw = wire(callback())
        cases = [
            (raw, headers(raw, secret=b"wrong-synthetic-secret")),
            (raw + b"\n", headers(raw)),
            (raw.replace(b"request", b"forged!"), headers(raw)),
            (b"not json", headers(b"not json", secret=b"wrong")),
        ]
        for body, supplied in cases:
            with self.subTest(body=body[:10]):
                with patch.object(
                    ingress, "_json", side_effect=AssertionError("parser forbidden")
                ) as parse:
                    self.reject(body, supplied)
                    parse.assert_not_called()
        self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")

    def test_signature_is_verified_in_constant_time(self) -> None:
        self.allow()
        raw = wire(callback())
        real_compare = hmac.compare_digest
        with patch.object(hmac, "compare_digest", wraps=real_compare) as compare:
            self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")
            compare.assert_called_once()
            self.assertEqual(compare.call_args.args[1], headers(raw)[2][1])

    def test_replay_window_boundaries_both_directions_and_no_clock_fallback(
        self,
    ) -> None:
        self.allow()
        raw = wire(callback())
        for offset in (-301, 301):
            with patch.object(
                ingress, "_json", side_effect=AssertionError("parser forbidden")
            ):
                self.reject(raw, headers(raw, NOW + offset))
        for offset in (-300, 300):
            self.assertIn(
                self.app.ingest(raw, headers(raw, NOW + offset)),
                ("admitted", "duplicate"),
            )
        for value in (None, True, NOW + 0.5, float("nan"), -1, 2**63):
            with patch.object(self.app, "_clock", lambda: value):
                self.reject(raw)
        with patch.object(
            self.app, "_clock", side_effect=RuntimeError("synthetic-clock-canary")
        ):
            error = None
            try:
                self.app.ingest(raw, headers(raw))
            except Rejected as exc:
                error = exc
            self.assertIsNotNone(error)
            self.assertIsNone(error.__context__ if error else None)
            self.assertIsNone(error.__cause__ if error else None)
            self.assertNotIn(
                "synthetic-clock-canary", "".join(traceback.format_exception(error))
            )

    def test_header_duplicates_malformed_framing_and_type_are_rejected(self) -> None:
        raw = wire(callback())
        good = headers(raw)
        bad: list[Any] = [
            dict(good),
            list(good),
            (),
            good + (("x-SLACK-signature", good[2][1]),),
            good + (("Unrelated", "x"), ("UNRELATED", "x")),
            good + (("Content-Encoding", "gzip"),),
            good + (("Transfer-Encoding", "chunked"),),
            good + (("bad name", "x"),),
            good + (("X-Test", "x\r\ny"),),
            good + (("X-Test", "é"),),
            good + (("X-Test", "x" * 16384),),
            good + tuple((f"x-{n}", "x") for n in range(64)),
            good + (("X-Test", 1),),
            good + (("only-name",),),
        ]
        for index, replacements in (
            (0, ["text/plain", "application/json; charset=latin-1"]),
            (1, ["0", "-1", "01", "+1900000000", "1.0", "9" * 20, str(2**63)]),
            (2, ["v1=" + "0" * 64, "v0=" + "A" * 64, "0" * 64, "v0=x"]),
            (3, ["0", "01", str(len(raw) + 1)]),
        ):
            for value in replacements:
                rows = list(good)
                rows[index] = (rows[index][0], value)
                bad.append(tuple(rows))
        for supplied in bad:
            with self.subTest(headers=str(supplied)[:80]):
                self.reject(raw, supplied)
        self.allow()
        self.assertEqual(
            self.app.ingest(raw, tuple((k.lower(), v) for k, v in good)), "admitted"
        )

    def test_raw_body_bounds_and_json_complexity_reject_without_authority(self) -> None:
        for raw in (b"", b"x" * (1048576 + 1), bytearray(b"{}"), "{}"):
            self.reject(raw, headers(b"{}"))  # type: ignore[arg-type]
        for raw in (
            b"{}",
            b"[]",
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":1.1}',
            b'{"a":"\\ud800"}',
            b"\xff",
            b'{"a":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
            b'{"a":' + b"[0," * 1 + b"0," * 10001 + b"0]}",
        ):
            self.reject(raw)
        duplicated = wire(callback()).replace(
            b'"type": "event_callback"',
            b'"type": "event_callback", "type": "event_callback"',
        )
        self.reject(duplicated)

    def test_signed_wrong_installation_actor_channel_thread_never_authorize(
        self,
    ) -> None:
        self.allow()
        for key in ("api_app_id", "team_id", "context_team_id"):
            value = callback()
            value[key] = "WRONG"
            self.reject(wire(value))
        for change in (
            {"user": "UOTHER"},
            {"channel": "COTHER"},
            {"thread_ts": "1900000000.000999"},
            {"team": "TOTHER"},
            {"ts": 1900000000.000001},
            {"thread_ts": None},
        ):
            self.reject(wire(callback(**change)))
        for key, data in (
            ("is_ext_shared_channel", True),
            ("is_ext_shared_channel", 1),
            ("context_enterprise_id", "EOTHER"),
            ("authorizations", []),
            ("authorizations", [{"team_id": "TOTHER"}]),
            (
                "authorizations",
                [{"team_id": ROUTE.workspace_id, "is_enterprise_install": True}],
            ),
        ):
            value = callback()
            value[key] = data
            self.reject(wire(value))

    def test_manual_hmac_cross_workspace_and_enterprise_routing_deny_before_authority(
        self,
    ) -> None:
        self.allow()
        # Both the normal authorizations form and the older absent form must
        # reject contradictory actor workspace and fallback Enterprise fields.
        for include_authorizations in (True, False):
            locations = (
                ("callback", "event", "authorization")
                if include_authorizations
                else ("callback", "event")
            )
            for location in locations:
                for key, data in (
                    ("user_team", "TOTHER"),
                    ("user_team", "EOTHER"),
                    ("team", "TOTHER"),
                    ("team_id", "TOTHER"),
                    ("context_team_id", "TOTHER"),
                    ("enterprise_id", "EOTHER"),
                    ("enterprise_id", ""),
                    ("enterprise", {"id": "EOTHER"}),
                    ("context_enterprise_id", "EOTHER"),
                    ("is_enterprise_install", True),
                    ("is_enterprise_install", "true"),
                    ("is_ext_shared_channel", True),
                ):
                    with self.subTest(
                        location=location,
                        key=key,
                        data=data,
                        auth=include_authorizations,
                    ):
                        value = callback()
                        if not include_authorizations:
                            del value["authorizations"]
                        target = (
                            value
                            if location == "callback"
                            else value["event"]
                            if location == "event"
                            else value["authorizations"][0]
                        )
                        target[key] = data
                        raw = wire(value)
                        self.reject(raw, manual_headers(raw))
        # The manual producer itself must authenticate; negatives cannot pass
        # merely because its signatures are wrong.
        value = callback(
            user_team=ROUTE.workspace_id,
            team=ROUTE.workspace_id,
            enterprise_id=None,
            is_enterprise_install=False,
        )
        value["enterprise_id"] = None
        raw = wire(value)
        self.assertEqual(self.app.ingest(raw, manual_headers(raw)), "admitted")

    def test_bot_edited_deleted_structured_messages_and_url_challenge_are_not_work(
        self,
    ) -> None:
        self.allow()
        for key in (
            "subtype",
            "bot_id",
            "bot_profile",
            "app_id",
            "hidden",
            "edited",
            "deleted_ts",
            "previous_message",
            "message",
            "attachments",
            "files",
            "blocks",
            "metadata",
        ):
            self.reject(wire(callback(**{key: None})))
        for subtype in (
            "message_changed",
            "message_deleted",
            "bot_message",
            "file_share",
            "thread_broadcast",
        ):
            self.reject(wire(callback(subtype=subtype)))
        for value in [
            {"type": "url_verification", "challenge": "synthetic-challenge"},
            {**callback(), "type": "app_rate_limited"},
            callback(type="app_mention"),
            callback(text=5),
            callback(text="x" * 65537),
            callback(user="synthetic"),
        ]:
            self.reject(wire(value))

    def test_root_message_maps_to_itself_only_for_exact_configured_thread(self) -> None:
        value = callback(ts=ROUTE.thread_ts)
        del value["event"]["thread_ts"]
        self.allow(message_id=ROUTE.thread_ts)
        raw = wire(value)
        self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")
        value["event"]["ts"] = "1900000000.000999"
        self.reject(wire(value))

    def test_valid_signature_without_current_authority_has_no_persistent_effect(
        self,
    ) -> None:
        raw = wire(callback())
        self.reject(raw, authority=True)
        grant = self.allow()
        for changes in (
            {"identity": replace(ROUTE.identity, actor_id="UOTHER")},
            {"event_digest": "0" * 64},
            {"revision": 2},
            {"lease_epoch": 0},
        ):
            self.allowed[grant.event_digest] = replace(grant, **changes)
            self.reject(raw, authority=True)
        self.allowed.clear()
        self.reject(raw, authority=True)
        self.app.admission.authorize = None
        self.reject(raw)

    def test_duplicate_retry_and_conflict_are_decided_by_durable_store(self) -> None:
        self.allow()
        raw = wire(callback())
        self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")
        before = self.state()
        for data in (raw, json.dumps(callback(), separators=(",", ":")).encode()):
            supplied = headers(data) + (
                ("X-Slack-Retry-Num", "2"),
                ("X-Slack-Retry-Reason", "http_timeout"),
            )
            self.assertEqual(self.app.ingest(data, supplied), "duplicate")
            self.assertEqual(self.state(), before)
        changed = wire(callback(text="conflicting message"))
        self.allow(text="conflicting message")
        self.reject(changed, authority=True)
        self.allowed.clear()
        self.reject(
            raw, authority=True
        )  # Retry headers never bypass current authority.

    def test_existing_mirror_readback_suppresses_authenticated_echo(self) -> None:
        self.allow()
        self.app.admission.record_mirror(
            ROUTE.workspace_id, ROUTE.channel_id, ROUTE.thread_ts, "1900000000.000002"
        )
        self.reject(wire(callback()), authority=True)
        self.fresh_process("rejected")

    def fresh_process(self, expected: str) -> None:
        script = """
import json, socket, sys
from unittest.mock import patch
from tests.test_slack_ingress import NOW, ROUTE, SECRET, approval, callback, headers, normalized, wire
from tether.admission import Rejected
from tether.slack_ingress import SignedSlackIngress
with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")) as net:
    grant = approval(normalized())
    app = SignedSlackIngress(sys.argv[1], SECRET, ROUTE, lambda: NOW,
         lambda identity, digest: grant if identity == ROUTE.identity and digest == grant.event_digest else None)
    try:
        raw = wire(callback())
        try:
            result = app.ingest(raw, headers(raw))
        except Rejected:
            result = "rejected"
        if result != sys.argv[2]:
            raise AssertionError((result, sys.argv[2]))
        net.assert_not_called()
        print(result)
    finally:
        app.close()
"""
        for flags in ([], ["-O"]):
            result = subprocess.run(
                [sys.executable, *flags, "-c", script, str(self.path), expected],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

    def test_admission_survives_fresh_process_and_independent_row_count(self) -> None:
        self.allow()
        raw = wire(callback())
        self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")
        before = self.state()
        self.fresh_process("duplicate")
        self.assertEqual(self.state(), before)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM revisions").fetchone(), (1,)
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM deliveries").fetchone(), (1,)
            )

    def test_internal_proof_is_instance_and_normalized_byte_bound(self) -> None:
        raw = canonical(normalized())
        self.assertIsNone(self.app._authenticate(raw, ROUTE.identity))
        for proof in (
            ingress._Proof(object(), hashlib.sha256(raw).hexdigest(), ROUTE.identity),
            ingress._Proof(self.app._owner, "0" * 64, ROUTE.identity),
        ):
            self.assertIsNone(self.app._authenticate(raw, proof))
        with self.assertRaises(Rejected):
            self.app.admission.ingest(raw, ROUTE.identity)
        self.assertEqual(self.authority_calls, [])

    def test_clock_cancellation_propagates_without_admission(self) -> None:
        raw = wire(callback())
        before = self.state()
        with patch.object(self.app, "_clock", side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                self.app.ingest(raw, headers(raw))
        self.assertEqual(self.state(), before)
        self.assertEqual(self.authority_calls, [])

    def test_authority_errors_and_invalid_json_expose_no_private_canary(self) -> None:
        canary = "synthetic-private-callback-canary"
        raw = wire(callback())

        def fail(*args: object) -> Grant:
            raise RuntimeError(canary)

        self.app.admission.authorize = fail
        before = self.state()
        for data in (raw, b'{"' + canary.encode() + b'":'):
            error = None
            try:
                self.app.ingest(data, headers(data))
            except Rejected as exc:
                error = exc
            self.assertIsNotNone(error)
            if error is None:
                self.fail("expected rejection")
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertNotIn(canary, repr(error))
            self.assertNotIn(canary, "".join(traceback.format_exception(error)))
            self.assertEqual(self.state(), before)
        self.assertNotIn(canary.encode(), self.path.read_bytes())

    def test_narrower_time_window_and_identity_content_type(self) -> None:
        self.allow()
        self.app._max_skew = 0
        raw = wire(callback())
        for offset in (-1, 1):
            self.reject(raw, headers(raw, NOW + offset))
        supplied = tuple(
            (key, "application/json" if key == "Content-Type" else value)
            for key, value in headers(raw)
        ) + (("Content-Encoding", "identity"),)
        self.assertEqual(self.app.ingest(raw, supplied), "admitted")

    def test_unknown_payload_claims_cannot_supply_authority_or_override_identity(
        self,
    ) -> None:
        value = callback()
        value["grant"] = {"approved": True, "actor_id": "UOTHER", "lease_epoch": 999}
        value["event"]["revision"] = 999
        value["event"]["actor_id"] = "UOTHER"
        raw = wire(value)
        self.reject(raw, authority=True)
        self.allow()
        self.assertEqual(self.app.ingest(raw, headers(raw)), "admitted")
        result = self.app.admission.envelopes()[0]
        self.assertEqual(result["binding"]["revision"], 1)
        self.assertEqual(result["binding"]["lease_epoch"], 1)

    def test_invalid_configuration_creates_no_store(self) -> None:
        path = self.root / "invalid.db"
        cases: list[dict[str, Any]] = [
            {"signing_secret": b""},
            {"signing_secret": "synthetic"},
            {"signing_secret": b"x" * 4097},
            {"max_skew_seconds": True},
            {"max_skew_seconds": 301},
            {"max_skew_seconds": -1},
            {"route": replace(ROUTE, app_id="wrong")},
            {"clock": None},
        ]
        for change in cases:
            args: dict[str, Any] = dict(
                path=str(path), signing_secret=SECRET, route=ROUTE, clock=lambda: NOW
            )
            args.update(change)
            with self.assertRaises(ValueError):
                SignedSlackIngress(**args)
            self.assertFalse(path.exists())

    def test_signature_and_scope_guard_removal_mutations_fail_independent_regressions(
        self,
    ) -> None:
        source = (ROOT / "tether/slack_ingress.py").read_text()
        mutations = [
            (
                'if not hmac.compare_digest(expected, fields["x-slack-signature"]):',
                "if False:",
                "test_wrong_signature_and_raw_rewrite_never_parse_or_authorize",
            ),
            (
                'if event.get("user") != route.actor_id or event.get("channel") != route.channel_id:',
                "if False:",
                "test_signed_wrong_installation_actor_channel_thread_never_authorize",
            ),
            (
                "if abs(now - int(timestamp)) > self._max_skew:",
                "if False:",
                "test_replay_window_boundaries_both_directions_and_no_clock_fallback",
            ),
        ]
        for index, (old, new, method) in enumerate(mutations):
            self.assertEqual(source.count(old), 1)
            path = self.root / f"mutant{index}.py"
            path.write_text(source.replace(old, new, 1))
            name = f"signed_ingress_mutant_{index}"
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                self.fail("mutation loader unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
                # Run the actual regression against mutated source. Keep its
                # matching Route class because exact local types are intentional.
                mutant_route = module.Route(
                    ROUTE.app_id,
                    ROUTE.workspace_id,
                    ROUTE.actor_id,
                    ROUTE.channel_id,
                    ROUTE.thread_ts,
                )
                with patch.dict(
                    globals(),
                    SignedSlackIngress=module.SignedSlackIngress,
                    ingress=module,
                    ROUTE=mutant_route,
                ):
                    result = unittest.TestResult()
                    SignedIngressTests(method).run(result)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(result.errors, [], repr(result.errors))
                self.assertTrue(
                    result.failures, f"mutation {index} escaped independent regression"
                )
            finally:
                del sys.modules[name]


if __name__ == "__main__":
    unittest.main()
