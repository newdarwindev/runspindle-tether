"""Independent synthetic HTTP observations; never provider or live acceptance."""

import json
import socket
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from tether.slack_wire import (
    API,
    MAX_BYTES,
    ContentFacts,
    FileBinding,
    FileIntent,
    Request,
    Response,
    Scope,
    Ticket,
    WireClient,
    WireRejected,
    allocate_request,
    complete_request,
    replies_request,
    upload_request,
)

ROOT = Path(__file__).resolve().parents[1]
INTENT = FileIntent("artifact-1", "result.txt", b"synthetic bytes", "Synthetic result")
SCOPE = Scope(
    "account-1", "T100", "C100", "1700000000.000001", "delivery-1", INTENT.digest()
)
BINDING = FileBinding(SCOPE, "F100")
MESSAGE_TS = "1700000001.000002"


def json_response(body: object) -> Response:
    return Response(
        200,
        (("Content-Type", "application/json; charset=utf-8"),),
        json.dumps(body).encode(),
    )


class SyntheticHTTP:
    """Parse wire requests independently; hold actual fixture bytes/effects.

    No implementation parser, digest, reply builder, request intent or client
    comparison is used to produce provider observations. Initialized readback
    fixture values are literals, not echoes of readback's expected payload.
    """

    def __init__(self) -> None:
        self.calls: list[Request] = []
        self.effects: list[str] = []
        self.filename = "result.txt"
        self.content = b"synthetic bytes"
        self.text = "Synthetic result"
        self.channel = "C100"
        self.thread = "1700000000.000001"
        self.workspace = "T100"
        self.uploaded: bytes | None = None
        self.allocated_length = 15
        self.response_override: dict[str, Response | Exception] = {}
        self.pages: list[dict[str, object]] = []
        self.page_index = 0
        self.message_thread = self.thread
        self.file_ids = ["F100"]
        self.download = self.content
        self.shares_more = False

    def info(self) -> dict[str, object]:
        return {
            "ok": True,
            "file": {
                "id": "F100",
                "name": self.filename,
                "size": len(self.content),
                "is_external": False,
                "mode": "hosted",
                "has_more_shares": self.shares_more,
                "url_private": "https://files.slack.com/files-pri/T100-F100/result.txt",
                "shares": {
                    "public": {
                        self.channel: [
                            {
                                "team_id": self.workspace,
                                "thread_ts": self.thread,
                                "ts": MESSAGE_TS,
                            }
                        ]
                    }
                },
            },
        }

    def page(self) -> dict[str, object]:
        return {
            "ok": True,
            "has_more": False,
            "messages": [
                {"type": "message", "ts": self.thread, "text": "Original parent"},
                {
                    "type": "message",
                    "subtype": "file_share",
                    "ts": MESSAGE_TS,
                    "thread_ts": self.message_thread,
                    "text": self.text,
                    "files": [{"id": file} for file in self.file_ids],
                },
            ],
            "response_metadata": {"next_cursor": ""},
        }

    def exchange(self, request: Request) -> Response:
        self.calls.append(request)
        override = self.response_override.get(request.action)
        if isinstance(override, Exception):
            raise override
        if override is not None:
            return override
        url = urlsplit(request.url)
        if request.action == "allocate":
            if (
                request.url != "https://slack.com/api/files.getUploadURLExternal"
                or request.method != "POST"
            ):
                raise AssertionError("unexpected allocation wire target")
            fields = parse_qs(request.body.decode(), strict_parsing=True)
            if set(fields) != {"filename", "length"}:
                raise AssertionError("allocation form")
            self.filename = fields["filename"][0]
            self.allocated_length = int(fields["length"][0])
            self.effects.append("allocate")
            return json_response(
                {
                    "ok": True,
                    "file_id": "F100",
                    "upload_url": "https://files.slack.com/upload/v1/synthetic-ticket",
                }
            )
        if request.action == "upload":
            if (
                request.url != "https://files.slack.com/upload/v1/synthetic-ticket"
                or request.method != "POST"
                or request.required_scope is not None
            ):
                raise AssertionError("unexpected upload wire request")
            if len(request.body) != self.allocated_length:
                raise AssertionError("upload length mismatch")
            self.uploaded = request.body
            self.effects.append("upload")
            return Response(200, (), b"OK - 15")
        if request.action == "complete":
            body = json.loads(request.body)
            if (
                request.url != "https://slack.com/api/files.completeUploadExternal"
                or set(body) != {"files", "channel_id", "thread_ts", "initial_comment"}
            ):
                raise AssertionError("unexpected finalize wire request")
            if body["files"] != [{"id": "F100", "title": self.filename}]:
                raise AssertionError("unexpected finalized file")
            if self.uploaded is None:
                return json_response({"ok": False, "error": "file_not_found"})
            self.content = self.uploaded
            self.download = self.uploaded
            self.text = body["initial_comment"]
            self.channel = body["channel_id"]
            self.thread = body["thread_ts"]
            self.message_thread = self.thread
            self.effects.append("share")
            # Deliberately no message timestamp in a valid completion response.
            return json_response(
                {"ok": True, "files": [{"id": "F100", "title": self.filename}]}
            )
        if request.action == "info":
            if (
                url.path != "/api/files.info"
                or parse_qs(url.query) != {"file": ["F100"]}
                or request.method != "GET"
            ):
                raise AssertionError("unexpected file read")
            return json_response(self.info())
        if request.action == "replies":
            fields = parse_qs(url.query)
            if (
                url.path != "/api/conversations.replies"
                or fields.get("channel") != ["C100"]
                or fields.get("ts") != ["1700000000.000001"]
                or fields.get("limit") != ["15"]
                or request.method != "GET"
            ):
                raise AssertionError("unexpected thread read")
            if self.pages:
                result = self.pages[self.page_index]
                self.page_index += 1
                return json_response(result)
            return json_response(self.page())
        if request.action == "download":
            if (
                url.netloc != "files.slack.com"
                or url.path != "/files-pri/T100-F100/result.txt"
                or request.method != "GET"
            ):
                raise AssertionError("unexpected byte read")
            return Response(
                200, (("Content-Length", str(len(self.download))),), self.download
            )
        raise AssertionError("forbidden endpoint")


class WireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.socket_patch = patch.object(
            socket.socket, "connect", side_effect=AssertionError("forbidden socket")
        )
        self.network = self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.http = SyntheticHTTP()
        self.approved: list[Request] = []
        self.client = WireClient(self.http, self.approve)

    def approve(self, request: Request) -> bool:
        self.approved.append(request)
        return request.scope == SCOPE

    def tearDown(self) -> None:
        self.network.assert_not_called()

    def actions(self) -> list[str]:
        return [request.action for request in self.http.calls]

    def test_exact_wire_builders_and_no_implicit_steps(self) -> None:
        allocation = self.client.allocate(SCOPE, INTENT)
        self.assertEqual(allocation.state, "parsed")
        self.assertIsInstance(allocation.facts, Ticket)
        ticket = allocation.facts
        assert isinstance(ticket, Ticket)
        self.assertEqual(self.actions(), ["allocate"])
        self.assertEqual(self.client.upload(ticket, INTENT).state, "upload_response")
        self.assertEqual(self.actions(), ["allocate", "upload"])
        result = self.client.complete(ticket, INTENT)
        self.assertEqual(result.facts, ("F100",))
        self.assertEqual(result.evidence_class, "unqualified_wire_observation")
        self.assertFalse(hasattr(result, "message_id"))
        self.assertEqual(self.http.effects, ["allocate", "upload", "share"])
        self.assertEqual(self.http.uploaded, b"synthetic bytes")
        self.assertEqual(
            (self.http.workspace, self.http.channel, self.http.thread),
            ("T100", "C100", "1700000000.000001"),
        )
        self.assertEqual(self.approved, self.http.calls)
        self.assertNotIn("Authorization", repr(self.http.calls))
        self.assertNotIn("synthetic bytes", repr(self.http.calls))
        self.assertNotIn("upload/v1/", repr(ticket))
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "content_match")
        self.assertEqual(
            self.actions(),
            ["allocate", "upload", "complete", "info", "replies", "download"],
        )
        self.assertEqual(self.http.effects, ["allocate", "upload", "share"])

    def test_independent_readback_is_not_a_delivery_receipt(self) -> None:
        result = self.client.readback(BINDING, INTENT)
        self.assertEqual(result.state, "content_match")
        self.assertEqual(result.evidence_class, "unqualified_wire_observation")
        self.assertEqual(self.actions(), ["info", "replies", "download"])
        self.assertEqual(self.http.effects, [])
        self.assertEqual(self.approved, self.http.calls)
        self.assertIsInstance(result.facts, ContentFacts)
        facts = result.facts
        assert isinstance(facts, ContentFacts)
        self.assertEqual(facts.message.message_ts, MESSAGE_TS)
        self.assertIsInstance(facts.message.message_ts, str)
        self.assertEqual(facts.downloaded_size, 15)
        self.assertEqual(
            facts.downloaded_sha256,
            "a3b16b6e44c6ea47c8f2531f402530e414091de3769594c3db04ddedd3165bc5",
        )

    def test_same_size_wrong_bytes_remain_unknown(self) -> None:
        self.http.download = b"different bytes"
        self.assertEqual(len(self.http.download), len(INTENT.content))
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertEqual(self.actions(), ["info", "replies", "download"])
        self.assertEqual(self.http.effects, [])

    def test_wrong_message_thread_remains_unknown(self) -> None:
        self.http.message_thread = "1700000000.999999"
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertEqual(self.actions(), ["info", "replies"])
        self.assertEqual(self.http.effects, [])

    def test_wrong_share_workspace_channel_and_timestamp(self) -> None:
        for field, value in (
            ("workspace", "T200"),
            ("channel", "C200"),
            ("thread", "1700000000.999999"),
        ):
            with self.subTest(field=field):
                self.http = SyntheticHTTP()
                setattr(self.http, field, value)
                self.client = WireClient(self.http, self.approve)
                self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
                self.assertNotIn("download", self.actions())

    def test_text_file_identity_and_partial_files(self) -> None:
        for text, files in (
            ("other", ["F100"]),
            (INTENT.text, []),
            (INTENT.text, ["F200"]),
            (INTENT.text, ["F100", "F200"]),
            (INTENT.text, ["F100", "F100"]),
        ):
            with self.subTest(text=text, files=files):
                self.http.text, self.http.file_ids = text, files
                self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
                self.assertNotIn("download", self.actions())

    def test_ambiguous_duplicate_and_incomplete_observations(self) -> None:
        page = self.http.page()
        messages = page["messages"]
        assert isinstance(messages, list)
        for extra in (messages[-1], dict(messages[-1], ts="1700000002.000003")):
            with self.subTest(extra=extra):
                self.http.response_override["replies"] = json_response(
                    dict(page, messages=messages + [extra])
                )
                self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.http.response_override.clear()
        self.http.shares_more = True
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertNotIn("download", self.actions())

    def test_each_call_defaults_deny_and_rechecks_scope(self) -> None:
        denied = WireClient(self.http)
        self.assertEqual(denied.allocate(SCOPE, INTENT).state, "unknown")
        self.assertEqual(denied.readback(BINDING, INTENT).state, "unknown")
        self.assertEqual(self.actions(), [])
        decisions = iter((True, True, False))
        revoked = WireClient(self.http, lambda _: next(decisions))
        self.assertEqual(revoked.readback(BINDING, INTENT).state, "unknown")
        self.assertEqual(self.actions(), ["info", "replies"])
        self.assertEqual(self.http.effects, [])

    def test_bound_payload_rejects_before_transport(self) -> None:
        for intent in (
            replace(INTENT, content=b"different bytes"),
            replace(INTENT, filename="different.txt"),
            replace(INTENT, text="different"),
            replace(INTENT, artifact_id="other"),
        ):
            with self.assertRaises(WireRejected):
                self.client.allocate(SCOPE, intent)
            with self.assertRaises(WireRejected):
                self.client.readback(BINDING, intent)
        self.assertEqual(self.actions(), [])

    def test_scoped_builders_preserve_strings_and_validate_identifiers(self) -> None:
        for scope in (
            replace(SCOPE, thread_ts=1700000000.000001),  # type: ignore[arg-type]
            replace(SCOPE, channel_id="C100&channel=C200"),
            replace(SCOPE, workspace_id="T100/other"),
            replace(SCOPE, channel_id="G100"),
            replace(SCOPE, history_scope="files:read"),
        ):
            with self.assertRaises(ValueError):
                replies_request(scope)
        group = replace(SCOPE, channel_id="G100", history_scope="mpim:history")
        self.assertEqual(replies_request(group).required_scope, "mpim:history")
        request = replies_request(SCOPE, "page+=/token")
        self.assertEqual(
            parse_qs(urlsplit(request.url).query)["cursor"], ["page+=/token"]
        )
        self.assertEqual(request.scope.thread_ts, "1700000000.000001")
        self.assertEqual(allocate_request(SCOPE, INTENT).required_scope, "files:write")

    def test_malicious_upload_urls_and_ticket_payload(self) -> None:
        urls = [
            "http://files.slack.com/upload/v1/a",
            "https://files.slack.com.evil.test/upload/v1/a",
            "https://files.slack.com@evil.test/upload/v1/a",
            "https://files.slack.com:443/upload/v1/a",
            "https://files.slack.com/upload/v1/../a",
            "https://files.slack.com/upload/v1/%2e%2e/a",
            "https://files.slack.com/upload/v1/%252e%252e/a",
            "https://files.slack.com/upload/v1/a?token=secret",
            "https://files.slack.com/upload/v1/a#fragment",
            "https://files.slack.com/upload/v1/\\evil",
            "https://files.slack.com/upload/v1/%0aa",
            "https://files.slack.com/upload/v1/",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.http.response_override["allocate"] = json_response(
                    {"ok": True, "file_id": "F100", "upload_url": url}
                )
                self.assertEqual(self.client.allocate(SCOPE, INTENT).state, "unknown")
                with self.assertRaises(WireRejected):
                    upload_request(Ticket(SCOPE, "F100", url), INTENT)
        with self.assertRaises(WireRejected):
            complete_request(
                Ticket(
                    replace(SCOPE, payload_sha256="0" * 64),
                    "F100",
                    "https://files.slack.com/upload/v1/a",
                ),
                INTENT,
            )
        self.assertNotIn("upload", self.actions())

    def test_malicious_download_remote_url_and_redirects(self) -> None:
        for url in (
            "https://evil.test/result.txt",
            "https://files.slack.com/files-pri/T200-F100/result.txt",
            "https://files.slack.com/files-pri/T100-F200/result.txt",
            "https://files.slack.com/files-pri/T100-F100/%2e%2e/result.txt",
        ):
            info = self.http.info()
            info["file"]["url_private"] = url  # type: ignore[index]
            self.http.response_override["info"] = json_response(info)
            self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        info = self.http.info()
        info["file"]["is_external"] = True  # type: ignore[index]
        self.http.response_override["info"] = json_response(info)
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertNotIn("download", self.actions())
        self.http.response_override.clear()
        self.http.response_override["download"] = Response(
            302, (("Location", "https://evil.test/"),), b""
        )
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertEqual(self.actions().count("download"), 1)

    def test_malformed_json_numbers_duplicates_and_depth(self) -> None:
        bad = [
            b'{"ok":true,"ok":true}',
            b'{"ok":true,"extra":NaN}',
            b'{"ok":true,"extra":Infinity}',
            b'{"ok":true,"extra":-Infinity}',
            b'{"ok":true,"extra":1e99999}',
            b'{"ok":true,"extra":{"a":1,"a":2}}',
            b'{"ok":true,"extra":"\\ud800"}',
            b'{"ok":true,"extra":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
            b"[]",
            b"\xff",
            b'{"ok":1}',
            b'{"ok":true,"extra":9223372036854775808}',
        ]
        for raw in bad:
            with self.subTest(raw=raw[:80]):
                self.http.response_override["allocate"] = Response(
                    200, (("content-type", "application/json"),), raw
                )
                self.assertEqual(self.client.allocate(SCOPE, INTENT).state, "unknown")
        self.assertEqual(self.http.effects, [])

    def test_rate_limits_remain_unknown_without_retries(self) -> None:
        for delay, expected in (
            ("30", 30),
            ("0", 0),
            ("-1", None),
            ("1.2", None),
            ("999999", None),
            ("date", None),
        ):
            before = len(self.http.calls)
            self.http.response_override["allocate"] = Response(
                429, (("Retry-After", delay),), b""
            )
            result = self.client.allocate(SCOPE, INTENT)
            self.assertEqual((result.state, result.retry_after), ("unknown", expected))
            self.assertEqual(len(self.http.calls), before + 1)
        self.http.response_override["replies"] = Response(
            429, (("Retry-After", "30"),), b""
        )
        result = self.client.readback(BINDING, INTENT)
        self.assertEqual((result.state, result.retry_after), ("unknown", 30))
        self.assertNotIn("download", self.actions())
        self.assertEqual(self.http.effects, [])

    def test_pagination_continues_but_never_promotes_partial_results(self) -> None:
        page = self.http.page()
        self.http.pages = [
            dict(page, has_more=True, response_metadata={"next_cursor": "next+="}),
            {
                "ok": True,
                "messages": [],
                "has_more": False,
                "response_metadata": {"next_cursor": ""},
            },
        ]
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "content_match")
        self.assertEqual(self.actions(), ["info", "replies", "replies", "download"])
        self.assertEqual(
            parse_qs(urlsplit(self.http.calls[2].url).query)["cursor"], ["next+="]
        )
        self.http.page_index = 0
        self.http.calls.clear()
        self.assertEqual(
            self.client.readback(BINDING, INTENT, max_pages=1).state, "unknown"
        )
        self.assertEqual(self.actions(), ["info", "replies"])

    def test_cursor_loops_missing_cursors_and_repeated_pages(self) -> None:
        for mode in ("missing", "loop", "duplicate", "long"):
            page = self.http.page()
            first = dict(page, has_more=True, response_metadata={"next_cursor": "one"})
            second: dict[str, object] = {
                "ok": True,
                "messages": [],
                "has_more": True,
                "response_metadata": {"next_cursor": "one"},
            }
            if mode == "missing":
                first["response_metadata"] = {}
            elif mode == "duplicate":
                second = page
            elif mode == "long":
                first["response_metadata"] = {"next_cursor": "x" * 513}
            self.http.pages = [first, second]
            self.http.page_index = 0
            self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
            self.assertNotIn("download", self.actions())

    def test_bounds_and_incomplete_or_truncated_response(self) -> None:
        for intent in (
            replace(INTENT, text="a" * 4001),
            replace(INTENT, content=b"x" * MAX_BYTES),
            replace(INTENT, filename="x" * 257),
            replace(INTENT, filename="../x"),
        ):
            with self.assertRaises(WireRejected):
                intent.digest()
        for pages in (0, 9, True, 1.5):
            with self.assertRaises(WireRejected):
                self.client.readback(BINDING, INTENT, max_pages=pages)  # type: ignore[arg-type]
        for response in (
            Response(
                200, (("content-type", "application/json"),), b"x" * (MAX_BYTES + 1)
            ),
            Response(
                200,
                (("content-type", "application/json"), ("Content-Type", "text/html")),
                b"{}",
            ),
            Response(
                200,
                (("content-type", "application/json"), ("content-encoding", "gzip")),
                b"{}",
            ),
            Response(
                200,
                (("content-type", "application/json"), ("content-length", "99")),
                b"{}",
            ),
            json_response({"ok": True, "warning": "message_truncated"}),
            Response(503, (), b""),
        ):
            self.http.response_override["info"] = response
            self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertNotIn("download", self.actions())

    def test_exception_and_api_failure_do_not_become_failed_before_effect(self) -> None:
        for response in (
            RuntimeError("synthetic interruption"),
            json_response({"ok": False, "error": "internal_error"}),
            json_response({"ok": False, "error": "invalid_auth"}),
        ):
            self.http.response_override["complete"] = response
            ticket = Ticket(SCOPE, "F100", "https://files.slack.com/upload/v1/a")
            self.assertEqual(self.client.complete(ticket, INTENT).state, "unknown")
        self.assertEqual(self.actions(), ["complete", "complete", "complete"])
        self.assertEqual(self.http.effects, [])

    def test_provider_error_cannot_be_a_parsed_upload_step(self) -> None:
        ticket = Ticket(SCOPE, "F100", "https://files.slack.com/upload/v1/a")
        for error in ("synthetic_error", None, ""):
            with self.subTest(error=error):
                self.http.response_override["allocate"] = json_response(
                    {
                        "ok": True,
                        "error": error,
                        "file_id": ticket.file_id,
                        "upload_url": ticket.upload_url,
                    }
                )
                self.http.response_override["complete"] = json_response(
                    {"ok": True, "error": error, "files": [{"id": ticket.file_id}]}
                )
                self.assertEqual(self.client.allocate(SCOPE, INTENT).state, "unknown")
                self.assertEqual(self.client.complete(ticket, INTENT).state, "unknown")
        self.assertEqual(self.actions(), ["allocate", "complete"] * 3)

    def test_exact_request_authorization_and_cancellation(self) -> None:
        expected = allocate_request(SCOPE, INTENT)
        scoped = WireClient(self.http, lambda request: request == expected)
        self.assertEqual(scoped.allocate(SCOPE, INTENT).state, "parsed")
        ticket = Ticket(SCOPE, "F100", "https://files.slack.com/upload/v1/a")
        self.assertEqual(scoped.complete(ticket, INTENT).state, "unknown")
        self.assertEqual(self.actions(), ["allocate"])
        with patch.object(
            self.http, "exchange", side_effect=KeyboardInterrupt
        ) as interrupted:
            with self.assertRaises(KeyboardInterrupt):
                self.client.allocate(SCOPE, INTENT)
            self.assertEqual(interrupted.call_count, 1)
        self.assertEqual(self.http.effects, ["allocate"])

    def test_unsupported_message_content_and_incomplete_download(self) -> None:
        for extra in (
            {"blocks": [{"type": "rich_text"}]},
            {"attachments": [{"text": "extra"}]},
            {"subtype": "message_deleted"},
        ):
            page = self.http.page()
            messages = page["messages"]
            assert isinstance(messages, list)
            messages[1].update(extra)
            self.http.response_override["replies"] = json_response(page)
            self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertNotIn("download", self.actions())
        self.http.response_override.clear()
        self.http.download = b"synthetic"
        self.assertEqual(self.client.readback(BINDING, INTENT).state, "unknown")
        self.assertEqual(self.http.effects, [])

    def test_real_provider_types_are_not_journal_receipts(self) -> None:
        import tether.slack_wire as wire

        source = Path(wire.__file__).read_text()
        self.assertNotIn("from tether.journal", source)
        self.assertNotIn("from tether.testing", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("import os", source)
        self.assertEqual(API, "https://slack.com/api/")

    def test_independent_byte_and_thread_mutations_are_detected(self) -> None:
        mutations = [
            (
                "if response.body != intent.content:",
                "if False:",
                "test_same_size_wrong_bytes_remain_unknown",
            ),
            (
                "or message.thread_ts != binding.scope.thread_ts",
                "",
                "test_wrong_message_thread_remains_unknown",
            ),
        ]
        for before, after, case in mutations:
            code = f"""
import pathlib,sys,unittest
sys.path.insert(0,"tests")
import tether.slack_wire as wire
source=pathlib.Path(wire.__file__).read_text()
assert source.count({before!r})==1
exec(compile(source.replace({before!r},{after!r}),wire.__file__,"exec"),wire.__dict__)
import test_slack_wire
suite=unittest.TestSuite([test_slack_wire.WireTests({case!r})])
result=unittest.TextTestRunner().run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
"""
            command = [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                code,
            ]
            child = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=15)
            self.assertEqual(child.returncode, 1, child.stderr)
            self.assertIn(b"AssertionError: 'content_match' != 'unknown'", child.stderr)
            self.assertNotIn(b"ERROR:", child.stderr)


if __name__ == "__main__":
    unittest.main()
