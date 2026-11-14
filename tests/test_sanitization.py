"""Independent persisted/output scans for bounded configured synthetic secrets."""

import base64
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import quote

from tests.test_admission import authenticate, event, grant, proof
from tests.test_provider_journal import DEST, PAYLOAD, envelope, route
from tether.admission import Admission, Rejected, canonical
from tether.journal import ProviderJournal
from tether.native_testing import Availability, Binding, Event, Mode, NativeSource
from tether.sanitization import Limits, Sanitizer, UnsafeProjection
from tether.testing import FakeSlack, Payload

ROOT = Path(__file__).resolve().parents[1]
CANARY = "SYNTHETIC_SECRET_CANARY_98471"


def projection() -> dict[str, Any]:
    return {
        "version": "runspindle.projection.v1",
        "kind": "result",
        "message": "untrusted <script>alert(1)</script> " + CANARY,
        "arguments": {
            "nested": [{"Authorization": "Bearer not-in-known-list", "value": CANARY}],
            "password": "not-in-known-list",
            "hiddenReasoning": "not-in-known-list",
            "Client Secret": "not-in-known-list",
        },
        "result": {"value": base64.b64encode(CANARY.encode()).decode()},
        "error": {
            "message": "failure: " + CANARY,
            "stack": [CANARY],
            "link_error": "failed HTTPS://user:unlisted-password@example.test/path?access_token=unlisted#fragment",
        },
        "url": "https://user:unlisted-password@example.test/path/"
        + quote(CANARY)
        + "?access_token=unlisted#fragment",
        "attachments": [
            {
                "filename": CANARY + ".txt",
                "url": "https://example.test/" + CANARY + "?token=anything",
                "caption": CANARY,
                "size": 3,
            }
        ],
    }


class SanitizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.sanitizer = Sanitizer((CANARY,))
        self.app = Admission(
            str(self.base / "admission.db"),
            authenticate,
            lambda *_: grant(event()),
            self.sanitizer,
        )
        self.addCleanup(self.app.close)
        raw = canonical(event())
        self.app.ingest(raw, proof(raw))
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("unexpected network")
        )
        self.calls = self.network.start()
        self.addCleanup(self.network.stop)

    def tearDown(self) -> None:
        self.calls.assert_not_called()

    def scan_files(self) -> None:
        # Independent bytes, not sanitizer's own redaction count/result flag.
        for path in self.base.iterdir():
            if path.is_file():
                self.assertNotIn(CANARY.encode(), path.read_bytes(), str(path))

    def test_nested_errors_urls_attachment_metadata_clean_before_sql_and_render(
        self,
    ) -> None:
        self.assertEqual(
            self.app.persist_projection("task-1", 1, projection()), "persisted"
        )
        raw = self.app.db.execute("SELECT body FROM sanitized_projections").fetchone()[
            0
        ]
        self.assertNotIn(CANARY, raw)
        self.assertNotIn("not-in-known-list", raw)
        self.assertNotIn("unlisted-password", raw)
        self.assertNotIn("access_token=", raw)
        self.assertNotIn(base64.b64encode(CANARY.encode()).decode(), raw)
        value = json.loads(raw)
        self.assertEqual(value["arguments"]["password"], "[redacted]")
        self.assertEqual(value["url"], "https://example.test/path/[redacted]")
        output = self.app.render_projection("task-1", 1)
        self.assertNotIn(CANARY, output)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)
        self.scan_files()

    def test_pretruncate_redaction_handles_canary_crossing_boundary(self) -> None:
        sanitizer = Sanitizer((CANARY,), Limits(string_chars=32))
        value = {
            "version": "runspindle.projection.v1",
            "kind": "error",
            "message": "x" * 25 + CANARY + "end",
        }
        result = sanitizer.project(value)
        self.assertTrue(result["message"].endswith("[truncated]"))
        self.assertNotIn(CANARY[:7], result["message"])
        self.assertNotIn(CANARY, sanitizer.render(value))

    def test_percent_encoded_url_unicode_and_overlapping_secret_variants(self) -> None:
        secret = "cafe\u0301-secret"
        sanitizer = Sanitizer((secret, "long-" + secret))
        normalized = "caf\u00e9-secret"
        value = {
            "version": "runspindle.projection.v1",
            "kind": "error",
            "message": "long-" + normalized,
            "url": "https://example.test/"
            + quote(quote(normalized, safe=""), safe="")
            + "?q=unlisted#frag",
        }
        encoded = json.dumps(sanitizer.project(value), ensure_ascii=False)
        self.assertNotIn(normalized, encoded)
        self.assertNotIn("q=", encoded)
        self.assertNotIn("frag", encoded)

    def test_malformed_cycles_nonfinite_and_resource_limits_reject_without_persisting(
        self,
    ) -> None:
        cycle: list[Any] = []
        cycle.append(cycle)
        deep: object = "leaf"
        for _ in range(20):
            deep = [deep]
        malformed: list[object] = [
            {"version": "unknown", "kind": "error"},
            {"version": "runspindle.projection.v1", "kind": "hidden_reasoning"},
            {"version": "runspindle.projection.v1", "kind": []},
            {"version": "runspindle.projection.v1", "kind": "error", "unknown": "x"},
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "arguments": cycle,
            },
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "arguments": {"password": cycle},
            },
            {"version": "runspindle.projection.v1", "kind": "error", "arguments": deep},
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "arguments": [0] * 3000,
            },
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "message": "x" * 262145,
            },
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "error": float("nan"),
            },
            {"version": "runspindle.projection.v1", "kind": "error", "error": object()},
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "arguments": {1: "invalid"},
            },
            {
                "version": "runspindle.projection.v1",
                "kind": "error",
                "message": "\ud800",
            },
        ]
        before = list(self.app.db.iterdump())
        for value in malformed:
            with self.assertRaises(UnsafeProjection):
                self.app.persist_projection("task-1", 1, value)
            self.assertEqual(list(self.app.db.iterdump()), before)
        self.scan_files()

    def test_unsafe_urls_and_attachment_unknown_fields_reject(self) -> None:
        for url in (
            "javascript:alert(1)",
            "file:///private",
            "https://example.test:bad/",
            "data:text/plain,secret",
        ):
            value = {"version": "runspindle.projection.v1", "kind": "error", "url": url}
            with self.assertRaises(UnsafeProjection):
                self.sanitizer.project(value)
        for attachment in (
            {"content": CANARY},
            {"filename": 3},
            {"size": True},
            {"size": -1},
        ):
            with self.assertRaises(UnsafeProjection):
                self.sanitizer.project(
                    {
                        "version": "runspindle.projection.v1",
                        "kind": "result",
                        "attachments": [attachment],
                    }
                )

    def test_known_secret_keys_collisions_and_marker_reject(self) -> None:
        for arguments in ({CANARY: "value"}, {"cafe\u0301": 1, "caf\u00e9": 2}):
            with self.assertRaises(UnsafeProjection):
                self.sanitizer.project(
                    {
                        "version": "runspindle.projection.v1",
                        "kind": "result",
                        "arguments": arguments,
                    }
                )
        with self.assertRaises(UnsafeProjection):
            Sanitizer(("redacted",)).project(
                {
                    "version": "runspindle.projection.v1",
                    "kind": "error",
                    "message": "redacted",
                }
            )

    def test_projection_requires_admission_and_does_not_overwrite_revisions(
        self,
    ) -> None:
        with self.assertRaises(Rejected):
            self.app.persist_projection("missing-task", 1, projection())
        self.app.persist_projection("task-1", 1, projection())
        self.assertEqual(
            self.app.persist_projection("task-1", 1, projection()), "duplicate"
        )
        with self.assertRaises(Rejected):
            self.app.persist_projection(
                "task-1",
                1,
                {
                    "version": "runspindle.projection.v1",
                    "kind": "result",
                    "message": "different",
                },
            )
        self.scan_files()

    def test_inbound_text_not_persisted_and_secret_authority_metadata_rejected(
        self,
    ) -> None:
        raw_event = event(2, text=CANARY)
        self.app.authorize = lambda *_: grant(raw_event)
        raw = canonical(raw_event)
        self.app.ingest(raw, proof(raw))
        self.app.persist_projection(
            "task-1",
            2,
            {
                "version": "runspindle.projection.v1",
                "kind": "input",
                "message": raw_event["text"],
            },
        )
        self.scan_files()
        for field in (
            "task_id",
            "operation_id",
            "policy_revision",
            "host_id",
            "grant_ref",
            "delivery_namespace",
        ):
            changes: dict[str, Any] = {field: CANARY}
            self.app.authorize = lambda *_, changes=changes: replace(
                grant(event()), **changes
            )
            raw = canonical(event())
            with self.assertRaises(UnsafeProjection):
                self.app.ingest(raw, proof(raw))
        with self.assertRaises(UnsafeProjection):
            self.app.record_mirror("workspace-1", "channel-1", "thread-1", CANARY)
        self.scan_files()

    def test_url_hostname_secret_redacted_before_case_normalization(self) -> None:
        secret = "MixedCaseSecretCanary"
        sanitizer = Sanitizer((secret,))
        url = "https://" + secret + ".example.test/path"
        self.assertEqual(
            sanitizer.normalize({"url": url}),
            {"url": "https://[redacted].example.test/path"},
        )
        self.assertEqual(
            sanitizer.normalize("failure " + url),
            "failure https://[redacted].example.test/path",
        )
        with self.assertRaisesRegex(
            UnsafeProjection, "invalid redaction configuration"
        ):
            Sanitizer(("bad\ud800",))

    def test_resolved_route_rejected_before_reservation_or_provider_effects(
        self,
    ) -> None:
        for field in ("channel_id", "thread_id", "workspace_id"):
            changes: dict[str, Any] = {field: CANARY}
            destination = replace(DEST, **changes)
            journal = ProviderJournal(
                str(self.base / (field + ".db")),
                self.app,
                lambda *_: True,
                lambda *_: destination,
                self.sanitizer,
            )
            fake = FakeSlack(destination, lambda: 100, lambda: "message-1")
            try:
                with self.assertRaises(UnsafeProjection):
                    journal.send(envelope(), PAYLOAD, fake)
                self.assertEqual(fake.requests, [])
                self.assertEqual(fake.records, {})
                self.assertEqual(
                    journal.db.execute(
                        "SELECT COUNT(*) FROM provider_attempts"
                    ).fetchone()[0],
                    0,
                )
            finally:
                journal.close()
        self.scan_files()

    def test_original_and_normalized_secret_spellings_rejected_in_artifact_bytes(
        self,
    ) -> None:
        secret = "cafe\u0301-secret"
        sanitizer = Sanitizer((secret,))
        for spelling in (secret, "caf\u00e9-secret"):
            for value in (
                spelling,
                quote(spelling, safe=""),
                base64.b64encode(spelling.encode()).decode(),
                base64.urlsafe_b64encode(spelling.encode()).decode(),
            ):
                payload = replace(
                    PAYLOAD,
                    attachments=(
                        replace(PAYLOAD.attachments[0], content=value.encode()),
                    ),
                )
                with self.assertRaises(UnsafeProjection):
                    sanitizer.require_payload(payload)
                self.assertEqual(sanitizer.normalize(value), "[redacted]")

    def test_journal_rejects_dirty_bound_content_without_changing_accepted_bytes(
        self,
    ) -> None:
        journal = ProviderJournal(
            str(self.base / "journal.db"),
            self.app,
            lambda *_: True,
            route,
            self.sanitizer,
        )
        fake = FakeSlack(DEST, lambda: 100, lambda: "message-1")
        try:
            inputs = [
                (envelope(), replace(PAYLOAD, text=CANARY)),
                (
                    envelope(),
                    replace(
                        PAYLOAD,
                        attachments=(replace(PAYLOAD.attachments[0], filename=CANARY),),
                    ),
                ),
            ]
            content = CANARY.encode()
            payload = replace(
                PAYLOAD, attachments=(replace(PAYLOAD.attachments[0], content=content),)
            )
            value = json.loads(envelope())
            value["payload"]["sha256"] = hashlib.sha256(content).hexdigest()
            inputs.append((canonical(value), payload))
            value = json.loads(envelope())
            value["payload"]["destination_id"] = CANARY
            inputs.append((canonical(value), PAYLOAD))
            for raw, payload in inputs:
                with self.assertRaises(UnsafeProjection):
                    journal.send(raw, payload, fake)
            self.assertEqual(fake.requests, [])
            self.assertEqual(fake.records, {})
            self.assertEqual(
                journal.db.execute("SELECT COUNT(*) FROM provider_attempts").fetchone()[
                    0
                ],
                0,
            )
            self.scan_files()
        finally:
            journal.close()

    def test_sensitive_provider_receipt_identity_never_reaches_journal_or_result(
        self,
    ) -> None:
        journal = ProviderJournal(
            str(self.base / "journal.db"),
            self.app,
            lambda *_: True,
            route,
            self.sanitizer,
        )
        fake = FakeSlack(DEST, lambda: 100, lambda: CANARY)
        try:
            sent = journal.send(envelope(), PAYLOAD, fake)
            observed = journal.lookup(envelope(), PAYLOAD, fake)
            self.assertEqual(sent.state, "unknown")
            self.assertEqual(observed.state, "unknown")
            self.assertNotIn(CANARY, str(sent) + str(observed))
            self.assertEqual(
                journal.db.execute(
                    "SELECT acknowledgement,observed FROM provider_attempts"
                ).fetchone(),
                (None, None),
            )
            self.scan_files()
        finally:
            journal.close()

    def test_sanitized_projection_can_flow_through_existing_exact_artifact_journal(
        self,
    ) -> None:
        self.app.persist_projection("task-1", 1, projection())
        rendered = self.app.render_projection("task-1", 1)
        payload = replace(PAYLOAD, text=rendered)
        journal = ProviderJournal(
            str(self.base / "journal.db"),
            self.app,
            lambda *_: True,
            route,
            self.sanitizer,
        )
        fake = FakeSlack(DEST, lambda: 100, lambda: "message-1")
        try:
            self.assertEqual(journal.send(envelope(), payload, fake).state, "accepted")
            self.assertEqual(
                journal.lookup(envelope(), payload, fake).state, "destination_confirmed"
            )
            stored = fake.records["message-1"].payload
            self.assertIsNotNone(stored)
            self.assertNotIn(CANARY, str(stored))
            self.scan_files()
        finally:
            journal.close()

    def test_truthful_capability_matrix_and_unavailable_sources_cannot_emit(
        self,
    ) -> None:
        binding = Binding("task-1", "host-1", "session-1", DEST)
        for mode in Mode:
            for availability in Availability:
                source = NativeSource(binding, mode, lambda: 100)
                source.set_availability(availability)
                value = {
                    "version": "runspindle.projection.v1",
                    "kind": "final",
                    "message": CANARY,
                    "capabilities": source.matrix(),
                }
                clean = self.sanitizer.project(value)
                self.assertEqual(clean["capabilities"], source.matrix())
                self.assertEqual(clean["capabilities"]["live_coverage"], "not_run")
                self.assertFalse(clean["capabilities"]["control"])
                fake = FakeSlack(DEST, lambda: 100, lambda: "message-1")
                source.emit(
                    Event(binding, "event-1", 1, 100, "final", Payload("synthetic")),
                    lambda e: fake.send(DEST, "operation-1", e.payload),
                )
                if availability is not Availability.BOUND or mode in (
                    Mode.UNSUPPORTED,
                    Mode.SNAPSHOT_ONLY,
                ):
                    self.assertEqual(fake.requests, [])
                    self.assertEqual(fake.records, {})
        matrix = NativeSource(binding, Mode.EVENTS, lambda: 100).matrix()
        for field, forged_value in (
            ("control", True),
            ("live_coverage", "live"),
            ("supported", ["hidden_reasoning"]),
            ("availability", "live"),
        ):
            forged = dict(matrix)
            forged[field] = forged_value
            with self.assertRaises(UnsafeProjection):
                self.sanitizer.project(
                    {
                        "version": "runspindle.projection.v1",
                        "kind": "final",
                        "capabilities": forged,
                    }
                )

    def test_fresh_process_reopens_only_sanitized_persisted_output(self) -> None:
        self.app.persist_projection("task-1", 1, projection())
        script = """
import sys
from tether.admission import Admission
from tether.sanitization import Sanitizer
app=Admission(sys.argv[1],sanitizer=Sanitizer((sys.argv[2],)))
try:print(app.render_projection("task-1",1))
finally:app.close()
"""
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                script,
                str(self.base / "admission.db"),
                CANARY,
            ],
            env=dict(os.environ, PYTHONPATH=str(ROOT)),
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertIn("[redacted]", result.stdout)
        self.scan_files()

    def test_projection_transaction_failure_and_cancellation_leave_no_output(
        self,
    ) -> None:
        self.app.db.execute(
            "CREATE TRIGGER projection_failure BEFORE INSERT ON sanitized_projections BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
        import sqlite3

        with self.assertRaises(sqlite3.IntegrityError):
            self.app.persist_projection("task-1", 1, projection())
        self.app.db.execute("DROP TRIGGER projection_failure")
        real = self.app.db

        class CancelAtInsert:
            @property
            def in_transaction(self) -> bool:
                return real.in_transaction

            def execute(
                self, sql: str, args: tuple[object, ...] = ()
            ) -> sqlite3.Cursor:
                if sql.startswith("INSERT INTO sanitized_projections"):
                    raise KeyboardInterrupt("synthetic cancellation")
                return real.execute(sql, args)

        with patch.object(self.app, "db", CancelAtInsert()):
            with self.assertRaises(KeyboardInterrupt):
                self.app.persist_projection("task-1", 1, projection())
        self.assertFalse(real.in_transaction)
        self.assertEqual(
            real.execute("SELECT COUNT(*) FROM sanitized_projections").fetchone()[0], 0
        )
        self.scan_files()

    def test_deliberate_bypass_mutation_leaks_into_independently_read_database(
        self,
    ) -> None:
        source = (ROOT / "tether/admission.py").read_text()
        needle = "self.sanitizer.project(value)"
        self.assertEqual(source.count(needle), 1)
        path = self.base / "mutation.py"
        path.write_text(source.replace(needle, "value  # deliberate mutation\n"))
        spec = importlib.util.spec_from_file_location(
            "admission_sanitizer_mutant", path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("mutation loader unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            # Reuse already admitted SQLite state; mutation touches only the sink guard.
            mutant = module.Admission(
                str(self.base / "admission.db"), sanitizer=self.sanitizer
            )
            try:
                mutant.persist_projection("task-1", 1, projection())
            finally:
                mutant.close()
            row = self.app.db.execute(
                "SELECT body FROM sanitized_projections"
            ).fetchone()[0]
            self.assertIn(
                CANARY, row, "independent DB scan must expose sanitizer bypass"
            )
        finally:
            sys.modules.pop(spec.name, None)
