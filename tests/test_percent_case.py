"""Independent observers for percent-escape case variants of synthetic secrets."""

import json
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from tests.test_admission import authenticate, event, grant, proof
from tether.admission import Admission, canonical
from tether.sanitization import Limits, Sanitizer, UnsafeProjection
from tether.slack_upload import UploadJournal
from tether.slack_wire import FileIntent, Scope
from tether.testing import Attachment, Payload

ROOT = Path(__file__).resolve().parents[1]
SECRET = "Synthetic/Canary+Ω"
VARIANTS = (
    "Synthetic%2FCanary%2B%CE%A9",
    "Synthetic%2fCanary%2b%ce%a9",
    "Synthetic%2fCanary%2B%cE%A9",
    "Synthetic%2FCanary%2b%Ce%a9",
)


def projection() -> dict[str, Any]:
    return {
        "version": "runspindle.projection.v1",
        "kind": "result",
        "message": VARIANTS[1],
        "arguments": {"nested": [{"value": value} for value in VARIANTS]},
        "result": {"value": "prefix " + VARIANTS[2] + " suffix"},
        "error": {"message": VARIANTS[3]},
        "attachments": [{"filename": "result.txt", "caption": VARIANTS[2]}],
    }


class PercentCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="tether-percent-case-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.sanitizer = Sanitizer((SECRET,))
        deny = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network")
        )
        self.network = deny.start()
        self.addCleanup(deny.stop)

    def tearDown(self) -> None:
        self.network.assert_not_called()

    def test_lower_and_mixed_quoted_forms_are_redacted(self) -> None:
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                self.assertEqual(self.sanitizer.normalize(variant), "[redacted]")
                with self.assertRaises(UnsafeProjection):
                    self.sanitizer.require_clean(variant)
        rendered = self.sanitizer.render(projection())
        self.assertIn("[redacted]", rendered)
        for variant in VARIANTS:
            self.assertNotIn(variant, rendered)

    def test_nested_projection_is_clean_in_real_sqlite_and_fresh_process(self) -> None:
        path = self.base / "admission.db"
        admission = Admission(
            str(path), authenticate, lambda *_: grant(event()), self.sanitizer
        )
        try:
            raw = canonical(event())
            self.assertEqual(admission.ingest(raw, proof(raw)), "admitted")
            self.assertEqual(
                admission.persist_projection("task-1", 1, projection()), "persisted"
            )
            self.assertNotIn(VARIANTS[1], admission.render_projection("task-1", 1))
        finally:
            admission.close()
        with sqlite3.connect(path) as independent:
            body = independent.execute(
                "SELECT body FROM sanitized_projections"
            ).fetchone()[0]
        for variant in VARIANTS:
            self.assertNotIn(variant, body)
            self.assertNotIn(variant.encode(), path.read_bytes())
        script = """import json,sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 rows=db.execute('SELECT body FROM sanitized_projections').fetchall()
if len(rows)!=1: raise AssertionError('missing projection')
for value in json.loads(sys.argv[2]):
 if value in rows[0][0]: raise AssertionError('encoded secret persisted')
"""
        child = subprocess.run(
            [sys.executable, "-c", script, str(path), json.dumps(VARIANTS)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_immutable_artifacts_reject_without_rewriting(self) -> None:
        for variant in VARIANTS:
            content = ("prefix " + variant + " suffix").encode()
            payload = Payload(
                "safe", (Attachment("artifact-1", "result.txt", content),)
            )
            with self.assertRaises(UnsafeProjection):
                self.sanitizer.require_payload(payload)
            self.assertEqual(payload.attachments[0].content, content)

    def test_upload_fence_rejects_before_rows_or_provider_effects(self) -> None:
        intent = FileIntent("artifact-1", "result.txt", VARIANTS[2].encode(), "safe")
        scope = Scope(
            "account-1",
            "T100",
            "C100",
            "1700000000.000001",
            "operation-1",
            intent.digest(),
        )
        provider = Mock()
        path = self.base / "upload.db"
        upload = UploadJournal(str(path), provider, lambda _: True, self.sanitizer)
        try:
            with self.assertRaises(UnsafeProjection):
                upload.send(scope, intent)
        finally:
            upload.close()
        provider.exchange.assert_not_called()
        with sqlite3.connect(path) as independent:
            self.assertEqual(
                independent.execute("SELECT count(*) FROM uploads").fetchone(), (0,)
            )
        self.assertNotIn(VARIANTS[2].encode(), path.read_bytes())

    def test_only_hex_digits_change_case_not_ordinary_secret_characters(self) -> None:
        for value in (
            "synthetic%2fCanary%2b%ce%a9",
            "Synthetic%2fcanary%2b%ce%a9",
            "synthetic/Canary+Ω",
        ):
            self.assertEqual(self.sanitizer.normalize(value), value)
            self.sanitizer.require_payload(
                Payload(
                    "safe", (Attachment("artifact-1", "result.txt", value.encode()),)
                )
            )
        # Percent characters in a raw configured value are literal, not decoding.
        literal = Sanitizer(("Literal%AB",))
        self.assertEqual(literal.normalize("Literal%ab"), "Literal%ab")
        self.assertEqual(literal.normalize("Literal%25AB"), "[redacted]")
        self.assertEqual(literal.normalize("Literal%25ab"), "Literal%25ab")
        self.assertEqual(
            self.sanitizer.normalize("Synthetic%252fCanary%252b%25ce%25a9"),
            "Synthetic%252fCanary%252b%25ce%25a9",
        )

    def test_plus_spaces_nfc_and_pretruncate_matching(self) -> None:
        sanitizer = Sanitizer(("Mixed / Ω", "e\u0301/Value"))
        for value in (
            "Mixed+%2f+%ce%a9",
            "Mixed%20%2f%20%cE%a9",
            "e%cc%81%2fValue",
            "%c3%a9%2FValue",
        ):
            self.assertEqual(sanitizer.normalize(value), "[redacted]")
            with self.assertRaises(UnsafeProjection):
                sanitizer.require_payload(
                    Payload(
                        "safe",
                        (Attachment("artifact-1", "result.txt", value.encode()),),
                    )
                )
        bounded = Sanitizer((SECRET,), Limits(string_chars=16))
        self.assertEqual(
            bounded.normalize("prefix " + VARIANTS[1]), "prefix [redacted[truncated]"
        )

    def test_encoded_keys_reject_and_matching_remains_bounded(self) -> None:
        with self.assertRaises(UnsafeProjection):
            self.sanitizer.normalize({VARIANTS[2]: "safe"})
        # Hundreds of case-bearing escape digits must not create 2**N variants.
        secret = "/" * 256
        sanitizer = Sanitizer((secret,))
        self.assertEqual(sanitizer.normalize("%2f%2F" * 128), "[redacted]")
        self.assertLess(
            len(sanitizer._pattern.pattern if sanitizer._pattern else ""), 20000
        )

    def test_mutation_restoring_case_sensitive_escape_matching_is_detected(
        self,
    ) -> None:
        source = (ROOT / "tether/sanitization.py").read_text()
        old = "_quoted_expression(value) if value in quoted else re.escape(value)"
        self.assertIn(old, source)
        target = self.base / "mutation"
        shutil.copytree(
            ROOT / "tether",
            target / "tether",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        shutil.copytree(
            ROOT / "tests",
            target / "tests",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        (target / "tether/sanitization.py").write_text(
            source.replace(old, "re.escape(value)", 1)
        )
        result = subprocess.run(
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-m",
                "unittest",
                "tests.test_percent_case.PercentCaseTests.test_lower_and_mixed_quoted_forms_are_redacted",
                "tests.test_percent_case.PercentCaseTests.test_immutable_artifacts_reject_without_rewriting",
            ],
            cwd=target,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL:", result.stderr)
        self.assertNotIn("ImportError", result.stderr)


if __name__ == "__main__":
    unittest.main()
