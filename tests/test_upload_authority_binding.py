"""Exact callback binding; independent disposable provider effects, never Slack."""

import asyncio
import importlib
import json
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tether.slack_wire import WireClient, WireRejected

fixtures = importlib.import_module("test_slack_upload")
ROOT = Path(__file__).resolve().parents[1]


class UploadAuthorityBindingTests(unittest.TestCase):
    setUp: Any = fixtures.UploadTests.setUp
    tearDown: Any = fixtures.UploadTests.tearDown
    counts: Any = fixtures.UploadTests.counts
    journal: Any
    service: Any
    path: str
    service_path: str

    def inputs(self) -> tuple[Any, Any]:
        return replace(fixtures.SCOPE), replace(fixtures.INTENT)

    def test_early_scope_body_and_intent_mutations_have_zero_effects(self) -> None:
        for field in ("scope", "body", "intent"):
            with self.subTest(field=field):
                scope, intent = self.inputs()

                def authorize(request: Any) -> bool:
                    if field == "scope":
                        object.__setattr__(request.scope, "channel_id", "C200")
                    elif field == "body":
                        object.__setattr__(request, "body", b"changed")
                    else:
                        object.__setattr__(intent, "text", "changed")
                    return True

                self.journal.authorize = authorize
                with self.assertRaises(ValueError):
                    self.journal.send(scope, intent)
                self.assertEqual(self.counts(), {})
                self.assertEqual(
                    self.journal.db.execute("SELECT count(*) FROM uploads").fetchone()[
                        0
                    ],
                    0,
                )
                self.assertEqual(
                    self.service.db.execute("SELECT count(*) FROM files").fetchone()[0],
                    0,
                )

    def test_mutate_then_deny_raise_or_cancel_never_dispatches(self) -> None:
        for outcome in ("deny", "raise", "cancel"):
            scope, intent = self.inputs()

            def authorize(request: Any) -> bool:
                object.__setattr__(request.scope, "thread_ts", "1700000999.000001")
                if outcome == "raise":
                    raise RuntimeError("synthetic-private-canary")
                if outcome == "cancel":
                    raise KeyboardInterrupt("synthetic-private-canary")
                return False

            self.journal.authorize = authorize
            with self.assertRaises((WireRejected, KeyboardInterrupt)) as caught:
                self.journal.send(scope, intent)
            self.assertNotIn("synthetic-private-canary", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(self.counts(), {})
            self.assertEqual(
                self.journal.db.execute("SELECT count(*) FROM uploads").fetchone()[0], 0
            )

    def test_wire_client_second_authorization_mutation_cannot_allocate(self) -> None:
        scope, intent = self.inputs()
        count = 0

        def authorize(request: Any) -> bool:
            nonlocal count
            count += 1
            if count == 2:
                object.__setattr__(request.scope, "channel_id", "C200")
            return True

        self.journal.authorize = authorize
        result = self.journal.send(scope, intent)
        self.assertEqual(result.state, "unknown")
        self.assertEqual(self.counts(), {})
        self.assertEqual(
            self.journal.db.execute("SELECT phase FROM uploads").fetchone(),
            ("allocating",),
        )

    def test_late_scope_mutation_preserves_unknown_fence_after_restart(self) -> None:
        scope, intent = self.inputs()

        def authorize(request: Any) -> bool:
            if request.action == "complete":
                object.__setattr__(request.scope, "channel_id", "C200")
            return True

        self.journal.authorize = authorize
        with self.assertRaises(WireRejected):
            self.journal.send(scope, intent)
        self.assertEqual(self.counts(), {"allocate": 1, "upload": 1})
        self.assertEqual(
            self.service.db.execute("SELECT channel FROM files").fetchall(), [(None,)]
        )
        script = """
import json, sys
from unittest.mock import patch
import socket
from test_slack_upload import StoredHTTP, SCOPE, INTENT
from tether.slack_upload import UploadJournal
with patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden')) as network:
 service=StoredHTTP(sys.argv[2])
 journal=UploadJournal(sys.argv[1],service,lambda request: True)
 try:
  result=journal.send(SCOPE,INTENT)
  calls=dict(service.db.execute('SELECT action,count(*) FROM calls GROUP BY action'))
  print(json.dumps({'state':result.state,'calls':calls,'channels':service.db.execute('SELECT channel FROM files').fetchall()}))
  network.assert_not_called()
 finally: journal.close(); service.close()
"""
        result = subprocess.run(
            [
                sys.executable,
                "-O",
                "-c",
                "import sys;sys.path.insert(0,'tests');" + script,
                self.path,
                self.service_path,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["state"], "unknown")
        self.assertEqual(receipt["calls"].get("allocate"), 1)
        self.assertEqual(receipt["calls"].get("upload"), 1)
        self.assertEqual(receipt["calls"].get("complete", 0), 0)
        self.assertEqual(receipt["channels"], [[None]])

    def test_direct_wire_request_mutation_is_denied_before_transport(self) -> None:
        scope, intent = self.inputs()
        calls: list[Any] = []

        class Transport:
            def exchange(self, request: Any) -> Any:
                calls.append(request)
                raise AssertionError("unexpected dispatch")

        def authorize(request: Any) -> bool:
            object.__setattr__(request, "url", "https://slack.com/api/other")
            return True

        result = WireClient(Transport(), authorize).allocate(scope, intent)
        self.assertEqual(result.state, "unknown")
        self.assertEqual(calls, [])

    def test_foreign_request_fields_are_not_copied_or_compared(self) -> None:
        invoked: list[str] = []

        class Foreign:
            def __deepcopy__(self, memo: Any) -> Any:
                invoked.append("deepcopy")
                raise AssertionError("foreign copy")

            def __eq__(self, other: Any) -> bool:
                invoked.append("equality")
                raise AssertionError("foreign comparison")

        for name in ("action", "required_scope", "max_response_bytes"):
            scope, intent = self.inputs()

            def authorize(request: Any) -> bool:
                object.__setattr__(request, name, Foreign())
                return True

            self.journal.authorize = authorize
            with self.assertRaises(WireRejected):
                self.journal.send(scope, intent)
        self.assertEqual(invoked, [])
        self.assertEqual(self.counts(), {})

    def test_standard_cancellation_categories_keep_fixed_diagnostics(self) -> None:
        for category in (asyncio.CancelledError, GeneratorExit, SystemExit):
            scope, intent = self.inputs()

            def authorize(request: Any) -> bool:
                raise category("synthetic-private-canary")

            self.journal.authorize = authorize
            with self.assertRaises(category) as caught:
                self.journal.send(scope, intent)
            self.assertEqual(type(caught.exception), category)
            self.assertNotIn("synthetic-private-canary", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
        self.assertEqual(self.counts(), {})

    def test_removed_request_guard_is_detected(self) -> None:
        def bypass(request: Any, authorize: Any) -> bool:
            return authorize(request) is True

        with patch("tether.slack_wire.authorize_request", bypass):
            result = unittest.TestResult()
            UploadAuthorityBindingTests(
                "test_direct_wire_request_mutation_is_denied_before_transport"
            ).run(result)
        self.assertFalse(result.errors, repr(result.errors))
        self.assertTrue(result.failures, "request mutation escaped negative test")
