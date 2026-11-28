"""Real SQLite fences and independently stored synthetic HTTP effects; no Slack."""

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from tether.sanitization import Sanitizer
from tether.schema import SchemaRejected
from tether.slack_upload import SCHEMA, UploadJournal
from tether.slack_wire import FileIntent, Request, Response, Scope, WireRejected

ROOT = Path(__file__).resolve().parents[1]
PYTHON = [sys.executable, *(["-O"] if sys.flags.optimize else [])]
INTENT = FileIntent("artifact-1", "result.txt", b"synthetic bytes", "Synthetic result")
SCOPE = Scope(
    "account-1", "T100", "C100", "1700000000.000001", "delivery-1", INTENT.digest()
)
MESSAGE = "1700000001.000002"


def response(value: object) -> Response:
    return Response(
        200, (("Content-Type", "application/json"),), json.dumps(value).encode()
    )


class StoredHTTP:
    """Fixture service in a different database, parsing actual outbound bytes.

    Neither expected Intent nor the production comparison creates observations.
    Every invocation, including forbidden duplicate attempts, has an audit row.
    """

    def __init__(self, path: str, fault: str = "") -> None:
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS calls(action TEXT,phase TEXT,file_id TEXT);
            CREATE TABLE IF NOT EXISTS files(
                id TEXT PRIMARY KEY, name TEXT, size INTEGER, content BLOB,
                channel TEXT, thread TEXT, text TEXT, message TEXT);
        """)
        self.fault = fault
        self.calls: list[Request] = []
        self.journal_path = str(Path(path).with_name("journal.db"))

    def close(self) -> None:
        self.db.close()

    def exchange(self, request: Request) -> Response:
        self.calls.append(request)
        url = urlsplit(request.url)
        actions = {
            "/api/files.getUploadURLExternal": "allocate",
            "/api/files.completeUploadExternal": "complete",
            "/api/files.info": "info",
            "/api/conversations.replies": "replies",
        }
        action = actions.get(url.path)
        if url.path.startswith("/upload/v1/"):
            action = "upload"
        elif url.path.startswith("/files-pri/T100-"):
            action = "download"
        if (
            action != request.action
            or url.scheme != "https"
            or url.hostname not in ("slack.com", "files.slack.com")
        ):
            raise AssertionError("forbidden fixture endpoint")
        with closing(sqlite3.connect(self.journal_path)) as journal:
            retained = journal.execute(
                "SELECT phase,file_id FROM uploads WHERE operation=?",
                (request.scope.operation_id,),
            ).fetchone()
        if retained is None:
            raise AssertionError("provider call before durable reservation")
        self.db.execute(
            "INSERT INTO calls VALUES (?,?,?)", (action, retained[0], retained[1])
        )
        if self.fault == "before:" + str(action):
            os._exit(31)
        if self.fault == "cancel:" + str(action):
            raise KeyboardInterrupt()
        if self.fault == "rate:" + str(action):
            return Response(429, (("Retry-After", "7"),), b"fixture limited")
        if action == "allocate":
            fields = parse_qs(request.body.decode(), strict_parsing=True)
            if request.method != "POST" or set(fields) != {"filename", "length"}:
                raise AssertionError("allocation shape")
            number = self.db.execute("SELECT count(*) FROM files").fetchone()[0] + 100
            file_id = "F" + str(number)
            self.db.execute(
                "INSERT INTO files(id,name,size) VALUES (?,?,?)",
                (file_id, fields["filename"][0], int(fields["length"][0])),
            )
            result = response(
                {
                    "ok": True,
                    "file_id": file_id,
                    "upload_url": "https://files.slack.com/upload/v1/capability-"
                    + file_id,
                }
            )
        elif action == "upload":
            file_id = url.path.rsplit("-", 1)[-1]
            row = self.db.execute(
                "SELECT size FROM files WHERE id=?", (file_id,)
            ).fetchone()
            if request.method != "POST" or row != (len(request.body),):
                raise AssertionError("upload scope/size")
            self.db.execute(
                "UPDATE files SET content=? WHERE id=?", (request.body, file_id)
            )
            result = Response(200, (), b"synthetic upload response")
        elif action == "complete":
            value = json.loads(request.body)
            if (
                request.method != "POST"
                or set(value) != {"files", "channel_id", "thread_ts", "initial_comment"}
                or len(value["files"]) != 1
            ):
                raise AssertionError("completion shape")
            file_id = value["files"][0]["id"]
            row = self.db.execute(
                "SELECT content,name FROM files WHERE id=?", (file_id,)
            ).fetchone()
            if row is None or row[0] is None or row[1] != value["files"][0]["title"]:
                raise AssertionError("unallocated/unuploaded file")
            self.db.execute(
                "UPDATE files SET channel=?,thread=?,text=?,message=? WHERE id=?",
                (
                    value["channel_id"],
                    value["thread_ts"],
                    value["initial_comment"],
                    MESSAGE,
                    file_id,
                ),
            )
            result = response({"ok": True, "files": [{"id": file_id}]})
        elif action == "info":
            file_id = parse_qs(url.query)["file"][0]
            row = self.db.execute(
                "SELECT name,size,channel,thread,message FROM files WHERE id=?",
                (file_id,),
            ).fetchone()
            if row is None:
                return response({"ok": False, "error": "file_not_found"})
            name, size, channel, thread, message = row
            shares = (
                {}
                if channel is None
                else {
                    "public": {
                        channel: [
                            {"team_id": "T100", "thread_ts": thread, "ts": message}
                        ]
                    }
                }
            )
            result = response(
                {
                    "ok": True,
                    "file": {
                        "id": file_id,
                        "name": name,
                        "size": size,
                        "is_external": False,
                        "mode": "hosted",
                        "url_private": f"https://files.slack.com/files-pri/T100-{file_id}/result.txt",
                        "shares": shares,
                    },
                }
            )
        elif action == "replies":
            query = parse_qs(url.query)
            rows = self.db.execute(
                "SELECT id,text,message FROM files WHERE channel=? AND thread=? AND message IS NOT NULL",
                (query["channel"][0], query["ts"][0]),
            ).fetchall()
            result = response(
                {
                    "ok": True,
                    "has_more": False,
                    "response_metadata": {"next_cursor": ""},
                    "messages": [
                        {
                            "type": "message",
                            "subtype": "file_share",
                            "ts": message,
                            "thread_ts": query["ts"][0],
                            "text": text,
                            "files": [{"id": file_id}],
                        }
                        for file_id, text, message in rows
                    ],
                }
            )
        elif action == "download":
            file_id = url.path.split("/")[2].split("-", 1)[1]
            content = self.db.execute(
                "SELECT content FROM files WHERE id=?", (file_id,)
            ).fetchone()[0]
            result = Response(200, (), content)
        else:
            raise AssertionError("forbidden fixture action")
        if self.fault == "after:" + str(action):
            os._exit(32)
        if self.fault == "lost:" + str(action):
            raise TimeoutError("synthetic private error canary")
        if self.fault == "error:" + str(action):
            return response({**json.loads(result.body), "error": "synthetic_error"})
        return result


class UploadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = str(self.root / "journal.db")
        self.service_path = str(self.root / "service.db")
        self.service = StoredHTTP(self.service_path)
        self.addCleanup(self.service.close)
        self.journal = UploadJournal(self.path, self.service, lambda request: True)
        self.addCleanup(self.journal.close)
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("forbidden network")
        )
        self.connections = self.network.start()
        self.addCleanup(self.network.stop)

    def tearDown(self) -> None:
        self.assertEqual(self.connections.call_count, 0)
        self.assertEqual(list(self.root.rglob("forbidden-network-call")), [])

    def counts(self) -> dict[str, int]:
        return dict(
            self.service.db.execute("SELECT action,count(*) FROM calls GROUP BY action")
        )

    def test_exact_wire_effects_once_and_readback_without_send_authority(self) -> None:
        result = self.journal.send(SCOPE, INTENT)
        self.assertEqual(
            (result.state, result.file_id, result.message_ts),
            ("content_match", "F100", MESSAGE),
        )
        self.assertEqual(result.evidence_class, "unqualified_wire_observation")
        self.journal.authorize = lambda request: request.method == "GET"
        self.assertEqual(self.journal.send(SCOPE, INTENT).state, "content_match")
        self.assertEqual(
            {key: self.counts()[key] for key in ("allocate", "upload", "complete")},
            {"allocate": 1, "upload": 1, "complete": 1},
        )
        self.assertEqual(
            self.service.db.execute(
                "SELECT content,channel,thread,text FROM files"
            ).fetchall(),
            [(b"synthetic bytes", "C100", "1700000000.000001", "Synthetic result")],
        )
        self.assertEqual(
            self.service.db.execute(
                "SELECT action,phase,file_id FROM calls WHERE action IN ('allocate','upload','complete')"
            ).fetchall(),
            [
                ("allocate", "allocating", None),
                ("upload", "uploading", "F100"),
                ("complete", "completing", "F100"),
            ],
        )

    def test_reentrant_observation_cannot_dispatch_another_send(self) -> None:
        exchange = self.service.exchange
        nested = []

        def reenter(request: Request) -> Response:
            if request.action == "allocate":
                nested.append(self.journal.send(SCOPE, INTENT).state)
            return exchange(request)

        with patch.object(self.service, "exchange", reenter):
            self.assertEqual(self.journal.send(SCOPE, INTENT).state, "content_match")
        self.assertEqual(nested, ["unknown"])
        self.assertEqual(
            [self.counts().get(key) for key in ("allocate", "upload", "complete")],
            [1, 1, 1],
        )

    def test_revocation_before_each_write_stops_later_effects(self) -> None:
        for index, action in enumerate(("allocate", "upload", "complete")):
            scope = replace(SCOPE, operation_id=f"revoke-{index}")
            seen = 0

            def authorize(request: Request) -> bool:
                nonlocal seen
                if request.action == action:
                    seen += 1
                    return seen == 1
                return True

            self.journal.authorize = authorize
            before = self.counts().get(action, 0)
            self.assertEqual(self.journal.send(scope, INTENT).state, "unknown")
            self.assertEqual(self.counts().get(action, 0), before)
            self.journal.authorize = lambda request: True
            self.assertEqual(self.journal.send(scope, INTENT).state, "unknown")
            self.assertEqual(self.counts().get(action, 0), before)

    def test_no_authority_no_calls_or_rows(self) -> None:
        for callback in (None, lambda request: False, lambda request: 1):
            self.journal.authorize = cast(Callable[[Request], bool] | None, callback)
            with self.assertRaisesRegex(WireRejected, "not authorized"):
                self.journal.send(SCOPE, INTENT)
        self.assertEqual(self.counts(), {})
        self.assertEqual(
            self.journal.db.execute("SELECT count(*) FROM uploads").fetchone(), (0,)
        )

    def test_binding_conflicts_have_no_provider_calls(self) -> None:
        self.journal.send(SCOPE, INTENT)
        before = self.counts()
        for scope in (
            replace(SCOPE, account_id="account-2"),
            replace(SCOPE, channel_id="C200"),
            replace(SCOPE, thread_ts="1700000000.000003"),
        ):
            with self.assertRaisesRegex(WireRejected, "binding conflict"):
                self.journal.send(scope, INTENT)
        changed = replace(INTENT, content=b"different bytes")
        with self.assertRaisesRegex(WireRejected, "binding conflict"):
            self.journal.send(replace(SCOPE, payload_sha256=changed.digest()), changed)
        self.assertEqual(self.counts(), before)

    def test_unknown_operation_is_not_absence_or_retry_permission(self) -> None:
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.counts(), {})

    def test_rate_limit_at_every_mutating_step_does_not_retry(self) -> None:
        for index, action in enumerate(("allocate", "upload", "complete")):
            with self.subTest(action=action):
                scope = replace(SCOPE, operation_id=f"rate-{index}")
                self.service.fault = "rate:" + action
                result = self.journal.send(scope, INTENT)
                self.assertEqual(
                    (result.state, result.retry_action, result.retry_after),
                    ("unknown", action, 7),
                )
                before = {
                    k: v
                    for k, v in self.counts().items()
                    if k in ("allocate", "upload", "complete")
                }
                self.service.fault = ""
                self.assertEqual(self.journal.send(scope, INTENT).state, "unknown")
                self.assertEqual(
                    {k: v for k, v in self.counts().items() if k in before}, before
                )

    def test_readback_rate_limit_survives_reopen_until_exact_deadline(self) -> None:
        directory = self.root / "cooldown"
        directory.mkdir()
        now = 1_000_000_000_000
        first = self.child(directory, "rate:info", clock_ns=now)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["retry_after"], 7)
        expected = {"allocate": 1, "upload": 1, "complete": 1, "info": 1}

        def counts() -> dict[str, int]:
            with closing(sqlite3.connect(directory / "service.db")) as db:
                return dict(
                    db.execute("SELECT action,count(*) FROM calls GROUP BY action")
                )

        self.assertEqual(counts(), expected)
        during = self.child(directory, clock_ns=now + 7_000_000_000 - 1)
        self.assertEqual(during.returncode, 0, during.stderr)
        self.assertEqual(json.loads(during.stdout)["state"], "unknown")
        self.assertEqual(counts(), expected)
        after = self.child(directory, clock_ns=now + 7_000_000_000)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(json.loads(after.stdout)["state"], "content_match")
        self.assertEqual(counts(), dict(expected, info=2, replies=1, download=1))

    def test_v1_hint_starts_one_conservative_interval_after_migration(self) -> None:
        directory = self.root / "legacy"
        directory.mkdir()
        first = self.child(directory, "rate:info", clock_ns=1_000_000_000)
        self.assertEqual(first.returncode, 0, first.stderr)
        database = directory / "journal.db"
        columns = "operation,scope,workspace,phase,file_id,observed,conflict,retry_action,retry_after"
        with closing(sqlite3.connect(database)) as db:
            row = db.execute(f"SELECT {columns} FROM uploads").fetchone()
        legacy = directory / "old.db"
        with closing(sqlite3.connect(legacy)) as db, db:
            db.executescript(SCHEMA)
            db.execute("PRAGMA user_version=1")
            db.execute("PRAGMA application_id=1414135811")
            db.execute("INSERT INTO uploads VALUES(?,?,?,?,?,?,?,?,?)", row)
        os.replace(legacy, database)
        for now in (20_000_000_000, 26_999_999_999):
            result = self.child(directory, clock_ns=now)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["state"], "unknown")
        with closing(sqlite3.connect(database)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                db.execute(f"SELECT {columns},retry_until_ns FROM uploads").fetchone(),
                (*row, 27_000_000_000),
            )
        with closing(sqlite3.connect(directory / "service.db")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM calls").fetchone(), (4,))
        result = self.child(directory, clock_ns=27_000_000_000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "content_match")

    def test_completion_rate_limit_fences_same_call_readback(self) -> None:
        self.service.fault = "rate:complete"
        self.assertEqual(self.journal.send(SCOPE, INTENT).retry_after, 7)
        self.assertEqual(self.counts(), {"allocate": 1, "upload": 1, "complete": 1})

    def test_lost_completion_ack_reconciles_exact_bytes(self) -> None:
        self.service.fault = "lost:complete"
        self.assertEqual(self.journal.send(SCOPE, INTENT).state, "content_match")
        self.assertEqual(self.counts()["complete"], 1)

    def test_corrupt_partial_wrong_thread_and_conflicting_observations(self) -> None:
        self.journal.send(SCOPE, INTENT)
        for sql, args in (
            ("UPDATE files SET content=?", (b"SYNTHETIC BYTES",)),
            ("UPDATE files SET thread=?", ("1700000000.000003",)),
            ("UPDATE files SET message=NULL", ()),
        ):
            self.service.db.execute(sql, args)
            self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
            self.service.db.execute(
                "UPDATE files SET content=?,thread=?,message=?",
                (INTENT.content, SCOPE.thread_ts, MESSAGE),
            )
        self.service.db.execute("UPDATE files SET message='1700000002.000003'")
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.service.db.execute("UPDATE files SET message=?", (MESSAGE,))
        before = self.counts()
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.counts(), before)
        self.assertEqual(
            self.journal.db.execute("SELECT observed,conflict FROM uploads").fetchone(),
            (MESSAGE, 1),
        )

    def test_revocation_after_readback_cannot_retain_match(self) -> None:
        self.service.fault = "lost:upload"
        self.journal.send(SCOPE, INTENT)
        self.service.db.execute(
            "UPDATE files SET channel=?,thread=?,text=?,message=?",
            (SCOPE.channel_id, SCOPE.thread_ts, INTENT.text, MESSAGE),
        )
        self.journal.authorize = lambda request: not any(
            call.action == "download" for call in self.service.calls
        )
        self.assertEqual(self.journal.lookup(SCOPE, INTENT).state, "unknown")
        self.assertEqual(
            self.journal.db.execute("SELECT observed FROM uploads").fetchone(), (None,)
        )

    def test_cancelled_mutating_step_is_not_retried(self) -> None:
        for index, action in enumerate(("allocate", "upload", "complete")):
            scope = replace(SCOPE, operation_id=f"cancel-{index}")
            self.service.fault = "cancel:" + action
            with self.assertRaises(KeyboardInterrupt):
                self.journal.send(scope, INTENT)
            self.service.fault = ""
            before = self.counts()
            self.journal.send(scope, INTENT)
            for key in ("allocate", "upload", "complete"):
                self.assertEqual(self.counts().get(key), before.get(key))

    def test_database_never_retains_payload_or_capability_url(self) -> None:
        self.journal.send(SCOPE, INTENT)
        for path in self.root.glob("journal.db*"):
            data = path.read_bytes()
            for forbidden in (
                INTENT.content,
                INTENT.text.encode(),
                INTENT.filename.encode(),
                b"capability-F100",
                b"files.slack.com",
            ):
                self.assertNotIn(forbidden, data)

    def test_configured_secret_rejected_before_effect_and_callback_error_detached(
        self,
    ) -> None:
        self.journal.sanitizer = Sanitizer(("canary",))
        dirty = replace(INTENT, content=b"canary")
        with self.assertRaises(ValueError):
            self.journal.send(replace(SCOPE, payload_sha256=dirty.digest()), dirty)

        def fail(request: Request) -> bool:
            raise ValueError("private canary")

        self.journal.authorize = fail
        try:
            self.journal.send(SCOPE, INTENT)
        except WireRejected as error:
            self.assertIsNone(error.__context__)
            self.assertNotIn("canary", str(error))
        else:
            self.fail("authorization exception accepted")
        self.assertEqual(self.counts(), {})

    def test_sql_retention_and_schema_family_rejection(self) -> None:
        self.journal.send(SCOPE, INTENT)
        for sql in (
            "DELETE FROM uploads",
            "UPDATE uploads SET file_id='F200'",
            "UPDATE uploads SET phase='allocating'",
            "UPDATE uploads SET scope=x'00'",
        ):
            with self.assertRaises(sqlite3.IntegrityError):
                self.journal.db.execute(sql)
        alien = str(self.root / "alien.db")
        with sqlite3.connect(alien) as db:
            db.execute("CREATE TABLE unrelated(value TEXT)")
        before = Path(alien).read_bytes()
        with self.assertRaises(SchemaRejected):
            UploadJournal(alien, self.service, lambda request: True)
        self.assertEqual(Path(alien).read_bytes(), before)

    def child(
        self,
        directory: Path,
        fault: str = "",
        code: str | None = None,
        *,
        clock_ns: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        program = code or CHILD
        return subprocess.run(
            [*PYTHON, "-c", program, str(directory), fault],
            cwd=ROOT,
            env={
                **os.environ,
                "PYTHONPATH": str(ROOT) + os.pathsep + str(ROOT / "tests"),
                "RUNSPINDLE_UPLOAD_FIXTURE_NS": ""
                if clock_ns is None
                else str(clock_ns),
            },
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_contradictory_readback_stays_unknown_until_clean_fresh_process(
        self,
    ) -> None:
        for action, replies in (("info", 0), ("replies", 1)):
            with self.subTest(action=action):
                directory = self.root / action
                directory.mkdir()
                first = self.child(directory, "error:" + action)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertEqual(json.loads(first.stdout)["state"], "unknown")
                with closing(sqlite3.connect(directory / "journal.db")) as journal:
                    self.assertEqual(
                        journal.execute(
                            "SELECT phase,file_id,observed,conflict FROM uploads"
                        ).fetchone(),
                        ("completing", "F100", None, 0),
                    )
                with closing(sqlite3.connect(directory / "service.db")) as service:
                    mutations = {"allocate": 1, "upload": 1, "complete": 1}
                    calls = "SELECT action,count(*) FROM calls GROUP BY action"
                    expected = {**mutations, "info": 1}
                    if replies:
                        expected["replies"] = replies
                    self.assertEqual(dict(service.execute(calls)), expected)
                    again = self.child(directory)
                    self.assertEqual(again.returncode, 0, again.stderr)
                    observed = json.loads(again.stdout)
                    self.assertEqual(
                        (observed["state"], observed["message_ts"]),
                        ("content_match", MESSAGE),
                    )
                    self.assertEqual(
                        dict(service.execute(calls)),
                        {**mutations, "info": 2, "replies": replies + 1, "download": 1},
                    )
                    self.assertEqual(
                        service.execute(
                            "SELECT content,channel,thread,message FROM files"
                        ).fetchall(),
                        [(INTENT.content, SCOPE.channel_id, SCOPE.thread_ts, MESSAGE)],
                    )
                with closing(sqlite3.connect(directory / "journal.db")) as journal:
                    self.assertEqual(
                        journal.execute(
                            "SELECT observed,conflict FROM uploads"
                        ).fetchone(),
                        (MESSAGE, 0),
                    )

    def test_fresh_process_crash_boundaries_never_repeat_mutations(self) -> None:
        for action in ("allocate", "upload", "complete"):
            for boundary in ("before", "after"):
                with self.subTest(action=action, boundary=boundary):
                    directory = self.root / (boundary + action)
                    directory.mkdir()
                    first = self.child(directory, boundary + ":" + action)
                    self.assertEqual(
                        first.returncode,
                        31 if boundary == "before" else 32,
                        first.stderr,
                    )
                    again = self.child(directory)
                    self.assertEqual(again.returncode, 0, again.stderr)
                    observed = json.loads(again.stdout)
                    self.assertEqual(
                        observed["state"],
                        "content_match"
                        if (boundary, action) == ("after", "complete")
                        else "unknown",
                    )
                    with sqlite3.connect(directory / "service.db") as db:
                        counts = dict(
                            db.execute(
                                "SELECT action,count(*) FROM calls GROUP BY action"
                            )
                        )
                        for key in ("allocate", "upload", "complete"):
                            self.assertLessEqual(counts.get(key, 0), 1)

    def test_competing_processes_have_one_allocation_upload_and_share(self) -> None:
        directory = self.root / "race"
        directory.mkdir()
        env = {**os.environ, "PYTHONPATH": str(ROOT) + os.pathsep + str(ROOT / "tests")}
        children = [
            subprocess.Popen(
                [*PYTHON, "-c", CHILD, str(directory), ""],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(4)
        ]
        try:
            for child in children:
                _, error = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0, error)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate()
        with sqlite3.connect(directory / "service.db") as db:
            counts = dict(
                db.execute("SELECT action,count(*) FROM calls GROUP BY action")
            )
            self.assertEqual(
                [counts.get(key) for key in ("allocate", "upload", "complete")],
                [1, 1, 1],
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM files WHERE message IS NOT NULL"
                ).fetchone(),
                (1,),
            )

    def test_mutation_repeat_completion_is_detected_by_independent_effect_counts(
        self,
    ) -> None:
        source = (ROOT / "tether/slack_upload.py").read_text()
        old = "completed = client.complete(ticket, intent)"
        self.assertEqual(source.count(old), 1)
        changed = source.replace(old, old + "\n        client.complete(ticket, intent)")
        code = (
            "import tether.slack_upload as module\nexec(compile("
            + repr(changed)
            + ", module.__file__, 'exec'), module.__dict__)\n"
            + CHILD
            + "\nif http.db.execute(\"SELECT count(*) FROM calls WHERE action='complete'\").fetchone() != (1,):\n    raise AssertionError('duplicate completion observed')\n"
        )
        directory = self.root / "mutation"
        directory.mkdir()
        result = self.child(
            directory,
            code=code.replace(
                "finally:\n    journal.close()\n    http.close()",
                "finally:\n    journal.close()",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AssertionError: duplicate completion observed", result.stderr)
        self.assertNotIn("SyntaxError", result.stderr)

    def test_mutation_upload_before_durable_substep_is_detected(self) -> None:
        source = (ROOT / "tether/slack_upload.py").read_text()
        old = "uploaded = client.upload(ticket, intent)"
        self.assertEqual(source.count(old), 1)
        changed = source.replace(old, "uploaded = premature_upload").replace(
            '        self.db.execute(\n            "UPDATE uploads SET file_id=',
            '        premature_upload = client.upload(ticket, intent)\n        self.db.execute(\n            "UPDATE uploads SET file_id=',
            1,
        )
        code = (
            "import tether.slack_upload as module\nexec(compile("
            + repr(changed)
            + ", module.__file__, 'exec'), module.__dict__)\n"
            + CHILD
            + "\nif http.db.execute(\"SELECT phase,file_id FROM calls WHERE action='upload'\").fetchone() != ('uploading','F100'):\n    raise AssertionError('upload before durable binding')\n"
        )
        directory = self.root / "order-mutation"
        directory.mkdir()
        result = self.child(
            directory,
            code=code.replace(
                "finally:\n    journal.close()\n    http.close()",
                "finally:\n    journal.close()",
            ),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AssertionError: upload before durable binding", result.stderr)
        self.assertNotIn("SyntaxError", result.stderr)


CHILD = """
import json, os, socket, sys
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from time import time_ns
from test_slack_upload import StoredHTTP, INTENT, SCOPE
from tether.slack_upload import UploadJournal
def forbidden(*args, **kwargs):
    (Path(sys.argv[1]) / 'forbidden-network-call').write_text('attempted')
    raise AssertionError('forbidden socket')
socket.socket.connect = forbidden
directory = Path(sys.argv[1])
http = StoredHTTP(str(directory / 'service.db'), sys.argv[2])
test_clock = os.environ.get("RUNSPINDLE_UPLOAD_FIXTURE_NS")
clock_ns = time_ns if not test_clock else lambda: int(test_clock)
journal = UploadJournal(str(directory / 'journal.db'), http, lambda request: True, clock_ns=clock_ns)
try:
    print(json.dumps(asdict(journal.send(SCOPE, INTENT))))
finally:
    journal.close()
    http.close()
"""
