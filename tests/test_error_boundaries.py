"""Synthetic exception canaries, independent SQLite state and provider receipts."""

import asyncio
import importlib.util
import json
import socket
import sqlite3
import sys
import tempfile
import traceback
import unittest
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.test_admission import authenticate, event, grant, proof
from tests.test_feedback import retention, target_authority
from tests.test_provider_journal import PAYLOAD, DurableFake, authorize, envelope, route
from tether.admission import Admission, Rejected, canonical, decode as ingress_decode
from tether.feedback import FeedbackStore, decode as feedback_decode
from tether.journal import ProviderJournal, delivery
from tether.sanitization import Sanitizer, UnsafeProjection
from tether.slack_wire import WireRejected, _json, _string

ROOT = Path(__file__).resolve().parents[1]


def explode(canary: str, kind: type[Exception] = RuntimeError) -> Callable[..., Any]:
    def callback(*args: object, **kwargs: object) -> Any:
        try:
            inner = ValueError(canary + ":cause")
            inner.add_note(canary + ":inner-note")
            raise inner
        except ValueError as cause:
            error = kind(canary + ":args", {"nested": canary})
            error.add_note(canary + ":outer-note")
            raise error from cause

    return callback


def capture(call: Callable[[], object], kind: type[ValueError]) -> ValueError:
    # Unlike assertRaises, keep the actual traceback for ordinary formatting.
    result = None
    try:
        call()
    except kind as error:
        result = error
    if result is None:
        raise AssertionError("expected public rejection")
    return result


class ErrorBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.canary = "synthetic-exception-" + uuid.uuid4().hex
        network = patch.object(
            socket, "socket", side_effect=AssertionError("network forbidden")
        )
        self.network = network.start()
        self.addCleanup(network.stop)
        self.addCleanup(self.network.assert_not_called)
        self.admission = Admission(
            str(self.root / "admission.db"), authenticate, lambda *_: grant(event())
        )
        self.addCleanup(self.admission.close)
        self.journal = ProviderJournal(
            str(self.root / "journal.db"), self.admission, authorize, route
        )
        self.addCleanup(self.journal.close)
        self.provider = DurableFake(str(self.root / "provider.db"))
        self.addCleanup(self.provider.close)

    def state(self, name: str) -> list[str]:
        # Independent read connection, not implementation-reported state.
        with sqlite3.connect(self.root / name) as db:
            return list(db.iterdump())

    def rows(self, name: str, sql: str) -> list[tuple[Any, ...]]:
        with sqlite3.connect(self.root / name) as db:
            return db.execute(sql).fetchall()

    def no_canary(self) -> None:
        for path in self.root.iterdir():
            if path.is_file():
                self.assertNotIn(self.canary.encode(), path.read_bytes(), path.name)
        for path in self.root.glob("*.db"):
            self.assertNotIn(self.canary, repr(self.state(path.name)))

    def public_error(self, error: ValueError, message: str) -> None:
        surfaces = [
            repr(error.args),
            str(error),
            repr(error),
            repr(error.__cause__),
            repr(error.__context__),
            repr(getattr(error, "__notes__", ())),
            "".join(traceback.format_exception(error)),
        ]
        for surface in surfaces:
            self.assertNotIn(self.canary, surface)
        self.assertEqual(error.args, (message,))
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertEqual(getattr(error, "__notes__", ()), ())

    def rejected(
        self,
        call: Callable[[], object],
        message: str,
        kind: type[ValueError] = Rejected,
    ) -> None:
        error = capture(call, kind)
        self.assertIs(type(error), kind)
        self.public_error(error, message)
        self.no_canary()

    def admit(self) -> None:
        raw = canonical(event())
        self.assertEqual(self.admission.ingest(raw, proof(raw)), "admitted")

    def feedback(self) -> tuple[FeedbackStore, bytes]:
        self.admit()
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state, "accepted"
        )
        found = self.journal.lookup(envelope(), PAYLOAD, self.provider)
        self.assertEqual(found.state, "destination_confirmed")
        target = self.journal.retained_target(
            envelope(), PAYLOAD, str(found.message_id)
        )
        app = FeedbackStore(
            str(self.root / "feedback.db"),
            self.journal,
            authenticate,
            retention,
            target_authority,
        )
        self.addCleanup(app.close)
        raw = canonical(
            {
                "version": "runspindle.tether.feedback.v1",
                "namespace": "synthetic",
                "event_id": "feedback-event-1",
                "feedback_id": "feedback-1",
                "revision": 1,
                "predecessor": None,
                "actor_id": "actor-1",
                "workspace_id": "workspace-1",
                "channel_id": "channel-1",
                "thread_id": "thread-1",
                "kind": "create",
                "judgment": "positive",
                "correction": None,
                "target": target,
            }
        )
        return app, raw

    def test_admission_callback_errors_are_fresh_and_leave_no_rows(self) -> None:
        raw = canonical(event())
        before = self.state("admission.db")
        for field, message in (
            ("authenticate", "transport authentication unavailable"),
            ("authorize", "authority unavailable"),
        ):
            for kind in (RuntimeError, Rejected):
                with self.subTest(field=field, kind=kind):
                    with patch.object(
                        self.admission, field, explode(self.canary, kind)
                    ):
                        self.rejected(
                            lambda: self.admission.ingest(raw, proof(raw)), message
                        )
                    self.assertEqual(self.state("admission.db"), before)
        self.assertEqual(self.rows("provider.db", "SELECT * FROM calls"), [])
        self.assertEqual(self.rows("journal.db", "SELECT * FROM provider_attempts"), [])
        self.admit()

    def test_journal_callback_errors_deny_send_and_lookup_without_reservation(
        self,
    ) -> None:
        self.admit()
        before = self.state("journal.db")
        for field in ("authorize", "resolve"):
            for method in (self.journal.send, self.journal.lookup):
                with self.subTest(field=field, method=method.__name__):
                    with patch.object(self.journal, field, explode(self.canary)):
                        self.rejected(
                            lambda: method(envelope(), PAYLOAD, self.provider),
                            "trusted integration unavailable",
                        )
                    self.assertEqual(self.state("journal.db"), before)
        self.assertEqual(self.rows("provider.db", "SELECT * FROM calls"), [])
        self.assertEqual(self.rows("provider.db", "SELECT * FROM effects"), [])

    def test_post_reservation_denial_survives_reopen_and_never_resends(self) -> None:
        self.admit()
        for field in ("authorize", "resolve"):
            with self.subTest(field=field):
                path = self.root / (field + ".db")
                journal = ProviderJournal(str(path), self.admission, authorize, route)
                self.addCleanup(journal.close)
                original = getattr(journal, field)
                calls = 0

                def revoked(*args: Any) -> Any:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        return explode(self.canary)(*args)
                    return original(*args)

                with patch.object(journal, field, revoked):
                    self.rejected(
                        lambda: journal.send(envelope(), PAYLOAD, self.provider),
                        "trusted integration unavailable",
                    )
                self.assertEqual(calls, 2)
                self.assertEqual(
                    self.rows(
                        path.name,
                        "SELECT state,acknowledgement,observed,conflict FROM provider_attempts",
                    ),
                    [("attempted", None, None, 0)],
                )
                reopened = ProviderJournal(str(path), self.admission, authorize, route)
                try:
                    self.assertEqual(
                        reopened.send(envelope(), PAYLOAD, self.provider).state,
                        "unknown",
                    )
                finally:
                    reopened.close()
        self.assertEqual(self.rows("provider.db", "SELECT * FROM effects"), [])
        self.assertEqual(
            self.rows("provider.db", "SELECT action FROM calls"),
            [("readback",), ("readback",)],
        )

    def test_readback_denial_never_promotes_observation_or_repeats_send(self) -> None:
        self.admit()
        self.journal.send(envelope(), PAYLOAD, self.provider)
        before = self.state("journal.db")
        for field in ("authorize", "resolve"):
            for failure_at in (2, 3):
                with self.subTest(field=field, failure_at=failure_at):
                    original = getattr(self.journal, field)
                    calls = 0

                    def revoked(*args: Any) -> Any:
                        nonlocal calls
                        calls += 1
                        if calls == failure_at:
                            return explode(self.canary)(*args)
                        return original(*args)

                    with patch.object(self.journal, field, revoked):
                        self.rejected(
                            lambda: self.journal.lookup(
                                envelope(), PAYLOAD, self.provider
                            ),
                            "trusted integration unavailable",
                        )
                    self.assertEqual(calls, failure_at)
                    self.assertFalse(self.journal.db.in_transaction)
                    self.assertEqual(self.state("journal.db"), before)
        self.assertEqual(
            self.rows(
                "journal.db", "SELECT state,observed,conflict FROM provider_attempts"
            ),
            [("accepted", None, 0)],
        )
        self.assertEqual(
            self.journal.send(envelope(), PAYLOAD, self.provider).state,
            "destination_confirmed",
        )
        self.assertEqual(
            self.rows("provider.db", "SELECT count(*) FROM effects"), [(1,)]
        )
        self.assertEqual(
            self.rows("provider.db", "SELECT count(*) FROM calls WHERE action='send'"),
            [(1,)],
        )

    def test_feedback_callback_errors_preserve_retained_history_without_partial_writes(
        self,
    ) -> None:
        app, initial = self.feedback()
        self.assertEqual(
            app.ingest(initial, proof(initial), envelope(), PAYLOAD), "retained"
        )
        update = json.loads(initial)
        update.update(
            revision=2, predecessor=1, kind="edit", event_id="feedback-event-2"
        )
        raw = canonical(update)
        before = self.state("feedback.db")
        provider_before = self.state("provider.db")
        for field in ("authenticate", "authorize_retention", "verify_target"):
            for failure_at in (1,) if field == "authenticate" else (1, 2):
                with self.subTest(field=field, failure_at=failure_at):
                    original = getattr(app, field)
                    calls = 0

                    def revoked(*args: Any) -> Any:
                        nonlocal calls
                        calls += 1
                        if calls == failure_at:
                            return explode(self.canary)(*args)
                        return original(*args)

                    with patch.object(app, field, revoked):
                        self.rejected(
                            lambda: app.ingest(raw, proof(raw), envelope(), PAYLOAD),
                            "feedback authentication unavailable"
                            if field == "authenticate"
                            else "feedback authority unavailable",
                        )
                    self.assertEqual(calls, failure_at)
                    self.assertFalse(app.db.in_transaction)
                    self.assertEqual(self.state("feedback.db"), before)
                    self.assertEqual(self.state("provider.db"), provider_before)
        self.assertEqual(app.ingest(raw, proof(raw), envelope(), PAYLOAD), "retained")
        self.assertEqual(app.ingest(raw, proof(raw), envelope(), PAYLOAD), "duplicate")

    def test_default_denials_keep_existing_categories_and_no_effects(self) -> None:
        raw = canonical(event())
        for field, value, message in (
            ("authenticate", None, "trusted adapters unavailable"),
            ("authorize", None, "trusted adapters unavailable"),
            ("authenticate", lambda *_: None, "transport authentication failed"),
            ("authorize", lambda *_: None, "authority mismatch"),
        ):
            with patch.object(self.admission, field, value):
                self.rejected(lambda: self.admission.ingest(raw, proof(raw)), message)
        self.admit()
        for field, journal_value, message in (
            ("authorize", None, "trusted integration unavailable"),
            ("resolve", None, "trusted integration unavailable"),
            ("authorize", lambda *_: False, "trusted integration unavailable"),
            ("resolve", lambda *_: None, "destination unavailable"),
        ):
            with patch.object(self.journal, field, journal_value):
                self.rejected(
                    lambda: self.journal.send(envelope(), PAYLOAD, self.provider),
                    message,
                )
        self.assertEqual(self.rows("journal.db", "SELECT * FROM provider_attempts"), [])
        self.assertEqual(self.rows("provider.db", "SELECT * FROM calls"), [])

    def test_feedback_default_denials_preserve_categories(self) -> None:
        app, raw = self.feedback()
        before = self.state("feedback.db")
        for field, value, message in (
            ("authenticate", None, "trusted feedback adapters unavailable"),
            ("authorize_retention", None, "trusted feedback adapters unavailable"),
            ("verify_target", None, "trusted feedback adapters unavailable"),
            ("authenticate", lambda *_: None, "feedback authentication failed"),
            (
                "authorize_retention",
                lambda *_: None,
                "feedback retention or target denied",
            ),
            ("verify_target", lambda *_: False, "feedback retention or target denied"),
        ):
            with patch.object(app, field, value):
                self.rejected(
                    lambda: app.ingest(raw, proof(raw), envelope(), PAYLOAD), message
                )
            self.assertEqual(self.state("feedback.db"), before)

    def test_callback_cancellation_is_not_converted_to_rejection_or_success(
        self,
    ) -> None:
        raw = canonical(event())
        before = self.state("admission.db")
        for kind in (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
            cancellation = kind()
            for field in ("authenticate", "authorize"):
                with patch.object(self.admission, field, side_effect=cancellation):
                    with self.assertRaises(kind) as caught:
                        self.admission.ingest(raw, proof(raw))
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(self.state("admission.db"), before)
        self.admit()
        for field in ("authorize", "resolve"):
            cancellation = asyncio.CancelledError()
            with patch.object(self.journal, field, side_effect=cancellation):
                with self.assertRaises(asyncio.CancelledError) as journal_cancelled:
                    self.journal.send(envelope(), PAYLOAD, self.provider)
            self.assertIs(journal_cancelled.exception, cancellation)
        self.assertEqual(self.rows("provider.db", "SELECT * FROM calls"), [])

    def test_journal_callback_cancellation_keeps_reservation_and_readback_state(
        self,
    ) -> None:
        self.admit()
        for field in ("authorize", "resolve"):
            path = self.root / ("cancel-" + field + ".db")
            journal = ProviderJournal(str(path), self.admission, authorize, route)
            self.addCleanup(journal.close)
            original = getattr(journal, field)
            cancellation = asyncio.CancelledError()
            calls = 0

            def cancel(*args: Any) -> Any:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise cancellation
                return original(*args)

            with patch.object(journal, field, cancel):
                with self.assertRaises(asyncio.CancelledError) as caught:
                    journal.send(envelope(), PAYLOAD, self.provider)
            self.assertIs(caught.exception, cancellation)
            before = self.state(path.name)
            self.assertEqual(
                self.rows(path.name, "SELECT state,observed FROM provider_attempts"),
                [("attempted", None)],
            )
            for failure_at in (2, 3):
                calls = 0

                def cancel_readback(*args: Any) -> Any:
                    nonlocal calls
                    calls += 1
                    if calls == failure_at:
                        raise cancellation
                    return original(*args)

                with patch.object(journal, field, cancel_readback):
                    with self.assertRaises(asyncio.CancelledError):
                        journal.lookup(envelope(), PAYLOAD, self.provider)
                self.assertFalse(journal.db.in_transaction)
                self.assertEqual(self.state(path.name), before)
            self.assertEqual(
                journal.send(envelope(), PAYLOAD, self.provider).state, "unknown"
            )
        self.assertEqual(self.rows("provider.db", "SELECT * FROM effects"), [])
        self.assertEqual(
            self.rows("provider.db", "SELECT count(*) FROM calls WHERE action='send'"),
            [(0,)],
        )

    def test_feedback_cancellation_rolls_back_after_lock(self) -> None:
        app, raw = self.feedback()
        before = self.state("feedback.db")
        provider_before = self.state("provider.db")
        for field in ("authenticate", "authorize_retention", "verify_target"):
            original = getattr(app, field)
            calls = 0
            failure_at = 1 if field == "authenticate" else 2
            cancellation = asyncio.CancelledError()

            def cancel(*args: Any) -> Any:
                nonlocal calls
                calls += 1
                if calls == failure_at:
                    raise cancellation
                return original(*args)

            with patch.object(app, field, cancel):
                with self.assertRaises(asyncio.CancelledError) as caught:
                    app.ingest(raw, proof(raw), envelope(), PAYLOAD)
            self.assertIs(caught.exception, cancellation)
            self.assertFalse(app.db.in_transaction)
            self.assertEqual(self.state("feedback.db"), before)
            self.assertEqual(self.state("provider.db"), provider_before)

    def test_parser_wrappers_discard_nested_exception_metadata(self) -> None:
        for parser, message, kind in (
            (ingress_decode, "invalid event", Rejected),
            (delivery, "invalid delivery envelope", Rejected),
            (feedback_decode, "invalid feedback", Rejected),
            (_json, "invalid JSON response", WireRejected),
        ):
            with self.subTest(parser=parser):
                with patch.object(json, "loads", explode(self.canary, ValueError)):
                    self.rejected(lambda: parser(b"{}"), message, kind)
                cancellation = asyncio.CancelledError()
                with patch.object(json, "loads", side_effect=cancellation):
                    with self.assertRaises(asyncio.CancelledError) as caught:
                        parser(b"{}")
                self.assertIs(caught.exception, cancellation)

    def test_malformed_inputs_are_bounded_without_parser_context(self) -> None:
        inputs = [
            b'{"' + self.canary.encode() + b'":',
            b'{"same":1,"same":2}',
            b'"\\ud800"',
            b"\xff",
            b"[" * 2000 + b"]" * 2000,
            b"{}",
        ]
        for parser, message, kind in (
            (ingress_decode, "invalid event", Rejected),
            (delivery, "invalid delivery envelope", Rejected),
            (feedback_decode, "invalid feedback", Rejected),
            (_json, "invalid JSON response", WireRejected),
        ):
            for raw in inputs:
                if parser is _json and raw == b"{}":
                    self.assertEqual(parser(raw), {})
                    continue
                with self.subTest(parser=parser, raw_length=len(raw)):
                    self.rejected(lambda: parser(raw), message, kind)
        self.assertEqual(ingress_decode(canonical(event())), event())
        self.assertEqual(delivery(envelope()), json.loads(envelope()))
        self.assertEqual(_json(b'{"ok":true}'), {"ok": True})

    def test_sanitizer_and_wire_string_errors_have_no_input_context(self) -> None:
        sanitizer = Sanitizer()
        dirty = self.canary + "\ud800"
        for call, message, kind in (
            (
                lambda: Sanitizer((dirty,)),
                "invalid redaction configuration",
                UnsafeProjection,
            ),
            (lambda: sanitizer.normalize(dirty), "invalid Unicode", UnsafeProjection),
            (
                lambda: sanitizer.normalize(
                    {"url": "https://example.invalid:" + self.canary}
                ),
                "invalid URL",
                UnsafeProjection,
            ),
            (lambda: _string(dirty), "string encoding", WireRejected),
        ):
            self.rejected(call, message, kind)
        matrix = dict(
            mode="events",
            availability="bound",
            supported=[],
            evidence_class="synthetic",
            control=False,
            live_coverage="not_run",
        )
        for key in ("mode", "availability"):
            invalid = dict(matrix, **{key: self.canary})
            self.rejected(
                lambda: sanitizer.project(
                    {
                        "version": "runspindle.projection.v1",
                        "kind": "input",
                        "capabilities": invalid,
                    }
                ),
                "unsupported capability state",
                UnsafeProjection,
            )
        self.assertEqual(_string("safe"), "safe")
        self.assertEqual(
            sanitizer.normalize({"url": "https://example.invalid/path?q=drop"}),
            {"url": "https://example.invalid/path"},
        )

    def test_reintroduced_explicit_and_suppressed_chaining_fail_canary_guard(
        self,
    ) -> None:
        source = (ROOT / "tether/admission.py").read_text()
        old = """        except Exception:
            unavailable = True
        if unavailable:
            raise Rejected("transport authentication unavailable")"""
        self.assertEqual(source.count(old), 1)
        for chain in ("exc", "None"):
            mutant = source.replace(
                old,
                """        except Exception as exc:
            raise Rejected("transport authentication unavailable") from """
                + chain,
                1,
            )
            path = self.root / ("mutant_" + chain + ".py")
            path.write_text(mutant)
            name = "tether_boundary_mutant_" + chain
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                self.fail("mutation loader unavailable")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
                app = module.Admission(
                    str(self.root / (chain + ".db")),
                    explode(self.canary),
                    lambda *_: None,
                )
                try:
                    error = capture(lambda: app.ingest(b"{}", None), module.Rejected)
                    with self.assertRaises(AssertionError):
                        self.public_error(error, "transport authentication unavailable")
                    self.assertIsNotNone(error.__context__)
                    self.assertIn(self.canary, repr(error.__context__))
                    if chain == "exc":
                        self.assertIn(
                            self.canary, "".join(traceback.format_exception(error))
                        )
                finally:
                    app.close()
            finally:
                del sys.modules[name]


if __name__ == "__main__":
    unittest.main()
