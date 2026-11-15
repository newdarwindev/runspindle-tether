"""Contradictory exact shares survive readback loss and process restart."""

import json
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from test_slack_upload import INTENT, MESSAGE, PYTHON, ROOT, SCOPE, StoredHTTP, response

from tether.sanitization import Sanitizer
from tether.slack_upload import UploadJournal
from tether.slack_wire import FileBinding, Request, Response, WireClient

OTHER_MESSAGE = "1700000002.000003"


class SharedHTTP(StoredHTTP):
    """Read a second actual synthetic share from its own SQLite effect rows."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self.split_pages = False
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS extra_shares("
            "file TEXT,team TEXT,channel TEXT,thread TEXT,message TEXT,text TEXT)"
        )

    def duplicate_share(self) -> None:
        self.db.execute(
            "INSERT INTO extra_shares SELECT id,'T100',channel,thread,?,text FROM files",
            (OTHER_MESSAGE,),
        )

    def exchange(self, request: Request) -> Response:
        result = super().exchange(request)
        if request.action not in ("info", "replies") or result.status != 200:
            return result
        value = json.loads(result.body)
        for file, team, channel, thread, message, text in self.db.execute(
            "SELECT * FROM extra_shares"
        ):
            if request.action == "info" and value["file"]["id"] == file:
                value["file"]["shares"]["public"].setdefault(channel, []).append(
                    {"team_id": team, "thread_ts": thread, "ts": message}
                )
            elif request.action == "replies" and channel == request.scope.channel_id:
                value["messages"].append(
                    {
                        "type": "message",
                        "subtype": "file_share",
                        "ts": message,
                        "thread_ts": thread,
                        "text": text,
                        "files": [{"id": file}],
                    }
                )
        if self.split_pages and request.action == "replies":
            next_page = "cursor" in parse_qs(urlsplit(request.url).query)
            value["messages"] = (
                value["messages"][1:] if next_page else value["messages"][:1]
            )
            value["has_more"] = not next_page
            value["response_metadata"] = {
                "next_cursor": "page2" if not next_page else ""
            }
        return response(value)


class ConflictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network")
        )
        self.connect = self.network.start()
        self.addCleanup(self.network.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.http = SharedHTTP(str(self.path / "service.db"))
        self.addCleanup(self.http.close)
        self.journal = UploadJournal(
            str(self.path / "journal.db"), self.http, lambda request: True
        )
        self.addCleanup(self.journal.close)
        self.assertEqual(self.journal.send(SCOPE, INTENT).state, "content_match")
        self.http.duplicate_share()

    def tearDown(self) -> None:
        self.assertEqual(self.connect.call_count, 0)

    def retained(self) -> tuple[object, ...] | None:
        with sqlite3.connect(self.path / "journal.db") as db:
            return cast(
                tuple[object, ...] | None,
                db.execute("SELECT observed,conflict FROM uploads").fetchone(),
            )

    def test_conflict_survives_disappearance_without_any_later_provider_call(
        self,
    ) -> None:
        self.assertEqual(
            self.http.db.execute("SELECT count(*) FROM extra_shares").fetchone(), (1,)
        )
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.retained(), (MESSAGE, 1))
        self.http.db.execute("DELETE FROM extra_shares")
        before = self.http.db.execute("SELECT count(*) FROM calls").fetchone()
        self.assertEqual(self.journal.send(SCOPE, INTENT).state, "unknown")
        self.assertEqual(
            self.http.db.execute("SELECT count(*) FROM calls").fetchone(), before
        )

    def test_wire_conflict_requires_exact_independent_content(self) -> None:
        result = WireClient(self.http, lambda request: True).readback(
            FileBinding(SCOPE, "F100"), INTENT
        )
        self.assertEqual(result.state, "content_conflict")
        self.assertEqual(result.evidence_class, "unqualified_wire_observation")
        self.assertEqual(self.http.calls[-1].action, "download")

    def test_distinct_exact_shares_across_pages_are_retained_as_conflict(self) -> None:
        self.http.split_pages = True
        self.http.calls.clear()
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.retained(), (MESSAGE, 1))
        self.assertEqual(
            [r.action for r in self.http.calls],
            ["info", "replies", "replies", "download"],
        )

    def test_conflict_without_a_previously_retained_success(self) -> None:
        directory = self.path / "unobserved"
        directory.mkdir()
        http = SharedHTTP(str(directory / "service.db"))
        self.addCleanup(http.close)
        journal = UploadJournal(
            str(directory / "journal.db"),
            http,
            lambda request: request.method == "POST",
        )
        self.addCleanup(journal.close)
        self.assertEqual(journal.send(SCOPE, INTENT).state, "unknown")
        http.duplicate_share()
        journal.authorize = lambda request: True
        self.assertEqual(journal.lookup(SCOPE, INTENT).state, "unknown")
        with sqlite3.connect(directory / "journal.db") as db:
            self.assertEqual(
                db.execute("SELECT observed,conflict FROM uploads").fetchone(),
                (None, 1),
            )

    def test_readback_failures_stay_unknown_and_do_not_invent_conflicts(self) -> None:
        for fault in ("rate:info", "rate:replies", "rate:download", "lost:download"):
            with self.subTest(fault=fault):
                self.http.fault = fault
                self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
                self.assertEqual(self.retained(), (MESSAGE, 0))

    def test_recheck_inside_write_lock_can_deny_conflict_retention(self) -> None:
        count = 0

        def authorize(request: Request) -> bool:
            nonlocal count
            if request.action == "info":
                count += 1
            return count < 3

        self.journal.authorize = authorize
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(count, 3)
        self.assertEqual(self.retained(), (MESSAGE, 0))

    def test_conflict_metadata_is_sanitized_before_retention(self) -> None:
        self.journal.sanitizer = Sanitizer((OTHER_MESSAGE,))
        with self.assertRaises(ValueError):
            self.journal.lookup(SCOPE, INTENT)
        self.assertEqual(self.retained(), (MESSAGE, 0))

    def test_conflict_does_not_retain_content_urls_or_second_message(self) -> None:
        self.journal.lookup(SCOPE, INTENT)
        for path in self.path.glob("journal.db*"):
            data = path.read_bytes()
            for forbidden in (
                INTENT.content,
                INTENT.text.encode(),
                INTENT.filename.encode(),
                b"files.slack.com",
                OTHER_MESSAGE.encode(),
            ):
                self.assertNotIn(forbidden, data)

    def test_conflict_survives_fresh_process_with_no_http_requests(self) -> None:
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.http.db.execute("DELETE FROM extra_shares")
        code = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / 'tests'))
from test_slack_upload import INTENT, SCOPE
from tether.slack_upload import UploadJournal
class Forbidden:
    calls = 0
    def exchange(self, request):
        self.calls += 1
        raise AssertionError('forbidden provider request')
provider = Forbidden()
journal = UploadJournal(sys.argv[1], provider, lambda request: True)
try:
    result = journal.send(SCOPE, INTENT)
    if result.state != 'unknown' or provider.calls != 0:
        raise AssertionError('conflict fence missing after restart')
finally:
    journal.close()
"""
        child = subprocess.run(
            [*PYTHON, "-c", code, str(self.path / "journal.db")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_inexact_shares_and_bytes_are_unknown_without_poisoning_history(
        self,
    ) -> None:
        for column, changed in (
            ("text", "different text"),
            ("team", "T200"),
            ("channel", "C200"),
            ("thread", "1700000009.000009"),
            ("message", MESSAGE),
        ):
            with self.subTest(column=column):
                self.http.db.execute("DELETE FROM extra_shares")
                self.http.duplicate_share()
                self.http.db.execute(f"UPDATE extra_shares SET {column}=?", (changed,))
                self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
                self.assertEqual(self.retained(), (MESSAGE, 0))
        self.http.db.execute("DELETE FROM extra_shares")
        self.http.duplicate_share()
        self.http.db.execute("UPDATE files SET content=?", (b"different bytes",))
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.retained(), (MESSAGE, 0))

    def test_revoked_readback_cannot_retain_conflict(self) -> None:
        self.http.calls.clear()
        self.journal.authorize = lambda request: not any(
            call.action == "download" for call in self.http.calls
        )
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.retained(), (MESSAGE, 0))

    def test_readback_cancelled_before_download_does_not_retain_conflict(self) -> None:
        self.http.fault = "cancel:download"
        with self.assertRaises(KeyboardInterrupt):
            self.journal.lookup(SCOPE, INTENT)
        self.assertEqual(self.retained(), (MESSAGE, 0))

    def test_mutations_are_detected_by_independent_database_assertions(self) -> None:
        cases = (
            (
                "slack_upload",
                "or type(facts) is ContentConflict",
                "or False",
                "test_conflict_survives_disappearance_without_any_later_provider_call",
            ),
            (
                "slack_wire",
                "if response.body != intent.content:",
                "if False:",
                "test_inexact_shares_and_bytes_are_unknown_without_poisoning_history",
            ),
        )
        for module, old, new, test in cases:
            with self.subTest(module=module):
                source = (ROOT / "tether" / (module + ".py")).read_text()
                self.assertEqual(source.count(old), 1)
                changed = source.replace(old, new)
                code = (
                    "import sys, unittest\nfrom pathlib import Path\n"
                    "sys.path.insert(0, str(Path.cwd() / 'tests'))\n"
                    f"import tether.{module} as module\n"
                    + "exec(compile("
                    + repr(changed)
                    + ", module.__file__, 'exec'), module.__dict__)\n"
                    + "suite = unittest.defaultTestLoader.loadTestsFromName('test_upload_conflicts.ConflictTests."
                    + test
                    + "')\n"
                    + "result = unittest.TextTestRunner().run(suite)\nsys.exit(0 if result.wasSuccessful() else 1)"
                )
                child = subprocess.run(
                    [*PYTHON, "-c", code],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(child.returncode, 1, child.stderr)
                self.assertIn("AssertionError:", child.stderr)
                self.assertIn("FAILED (failures=1)", child.stderr)
                self.assertNotIn("errors=", child.stderr)


if __name__ == "__main__":
    unittest.main()
