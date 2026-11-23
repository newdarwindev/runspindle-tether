"""Synthetic loopback bytes and isolated subprocesses, never Slack/TLS acceptance."""

import base64
import functools
import io
import multiprocessing
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from tether.slack_http import (
    Connector,
    Credential,
    HTTPRejected,
    HTTPSingleShotTransport,
    _bounded,
    _connect_tls,
    _exchange,
    _read_response,
)
from tether.slack_wire import (
    FileBinding,
    FileFacts,
    FileIntent,
    Request,
    Response,
    Scope,
    Ticket,
    allocate_request,
    complete_request,
    download_request,
    info_request,
    replies_request,
    upload_request,
)

INTENT = FileIntent(
    "artifact-1", "result.txt", b"synthetic content", "Synthetic result"
)
SCOPE = Scope(
    "account-1", "T100", "C100", "1700000000.000001", "operation-1", INTENT.digest()
)
TICKET = Ticket(SCOPE, "F100", "https://files.slack.com/upload/v1/synthetic-capability")
CANARY = "synthetic-token-canary"


def loopback(port: int, host: str, timeout: float) -> socket.socket:
    """Test-only connector, injected into private runner, not a production option."""
    if host not in ("slack.com", "files.slack.com"):
        raise AssertionError("unexpected logical origin")
    return socket.create_connection(("127.0.0.1", port), timeout=timeout)


class Server:
    def __init__(self, reply: bytes, delay: float = 0) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.reply = reply
        self.delay = delay
        self.requests: list[bytes] = []
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self) -> None:
        try:
            with self.listener.accept()[0] as connection:
                connection.settimeout(3)
                with connection.makefile("rb") as stream:
                    lines = []
                    length = 0
                    while True:
                        line = stream.readline(8192)
                        if not line:
                            return
                        lines.append(line)
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":", 1)[1])
                        if line == b"\r\n":
                            break
                    self.requests.append(b"".join(lines) + stream.read(length))
                self.done.wait(self.delay)
                connection.sendall(self.reply)
        except (OSError, ValueError):
            pass
        finally:
            self.listener.close()

    def close(self) -> None:
        self.done.set()
        self.thread.join(4)
        self.listener.close()
        if self.thread.is_alive():
            raise AssertionError("server leaked")


OK = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}'


class HTTPTests(unittest.TestCase):
    def server(self, reply: bytes = OK, delay: float = 0) -> Server:
        server = Server(reply, delay)
        self.addCleanup(server.close)
        return server

    def request(self) -> Request:
        return allocate_request(SCOPE, INTENT)

    def test_six_actions_and_exact_headers(self) -> None:
        binding = FileBinding(SCOPE, "F100")
        facts = FileFacts(
            "F100",
            INTENT.filename,
            len(INTENT.content),
            "https://files.slack.com/files-pri/T100-F100/result.txt",
            (),
        )
        requests = [
            self.request(),
            complete_request(TICKET, INTENT),
            info_request(binding),
            replies_request(SCOPE),
            upload_request(TICKET, INTENT),
            download_request(binding, facts),
        ]
        for request in requests:
            with self.subTest(action=request.action):
                server = self.server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                response = _bounded(
                    request,
                    lambda: None if request.action == "upload" else CANARY,
                    3,
                    functools.partial(loopback, server.port),
                )
                self.assertEqual(response.status, 200)
                server.thread.join(1)
                self.assertEqual(len(server.requests), 1)
                observed = server.requests[0]
                self.assertTrue(observed.endswith(request.body))
                self.assertEqual(
                    b"Authorization: Bearer " + CANARY.encode() in observed,
                    request.action != "upload",
                )
                self.assertIn(b"Connection: close\r\n", observed)

    def test_upload_provider_never_called(self) -> None:
        provider = Mock(side_effect=AssertionError("must not resolve"))
        guard = Mock(return_value=True)
        server = self.server()
        original = _bounded

        def local(
            request: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            return original(
                request, approve, timeout, functools.partial(loopback, server.port)
            )

        with patch("tether.slack_http._bounded", local):
            response = HTTPSingleShotTransport(provider, guard).exchange(
                upload_request(TICKET, INTENT)
            )
        self.assertEqual(response.status, 200)
        provider.assert_not_called()
        self.assertEqual(guard.call_count, 2)
        self.assertNotIn(b"Authorization", server.requests[0])

    def test_revocation_after_connect_and_credential_lookup_emits_nothing(self) -> None:
        server = self.server()
        request = self.request()
        provider = Mock(return_value=Credential(request, CANARY))
        guard = Mock(side_effect=[True, False])
        original = _bounded

        def local(
            request: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            return original(
                request, approve, timeout, functools.partial(loopback, server.port)
            )

        with patch("tether.slack_http._bounded", local):
            with self.assertRaises(HTTPRejected) as caught:
                HTTPSingleShotTransport(provider, guard).exchange(request)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(provider.call_count, 1)
        server.thread.join(1)
        self.assertEqual(server.requests, [])

    def test_wrong_binding_rejected_without_request(self) -> None:
        request = self.request()
        provider = Mock(
            return_value=Credential(replace(request, body=b"changed"), CANARY)
        )

        def after_connect(
            request: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            approve()
            self.fail("wrong credential reached network")

        with patch("tether.slack_http._bounded", after_connect):
            with self.assertRaises(HTTPRejected):
                HTTPSingleShotTransport(provider, lambda _: True).exchange(request)

    def test_invalid_routes_do_not_resolve_or_connect(self) -> None:
        request = self.request()
        invalid = [
            replace(request, url=url)
            for url in (
                "http://slack.com/api/files.getUploadURLExternal",
                "https://slack.com:443/api/files.getUploadURLExternal",
                "https://slack.com.evil.invalid/api/files.getUploadURLExternal",
                "https://files.slack.com/api/files.getUploadURLExternal",
                request.url + "?token=canary",
                request.url + "#fragment",
                request.url + "\r\nInjected: yes",
            )
        ]
        invalid += [
            replace(request, method="GET"),
            replace(request, required_scope=None),
            replace(request, action="chat.postMessage"),
            replace(request, max_response_bytes=True),
        ]
        provider = Mock()
        with patch("tether.slack_http._bounded") as network:
            for bad in invalid:
                with self.assertRaises(HTTPRejected):
                    HTTPSingleShotTransport(provider, lambda _: True).exchange(bad)
        network.assert_not_called()
        provider.assert_not_called()

    def test_framing_bounds_and_truncation(self) -> None:
        bad = [
            b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"Content-Length: 1048577\r\n\r\n",
            b"Content-Length: 3\r\n\r\n{}",
            b"Content-Length: 2\r\nContent-Encoding: gzip\r\n\r\n{}",
            b"Content-Length: 2\r\n folded\r\n\r\n{}",
            b"Transfer-Encoding: chunked\r\n\r\n2;ext=1\r\n{}\r\n0\r\n\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n0\r\nTrailer: nope\r\n\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n100001\r\n",
            b"Transfer-Encoding: gzip\r\n\r\n",
            b"\r\n{}",
            b"X-Huge: " + b"x" * 2200 + b"\r\n\r\n",
            b"X: a\x00\r\nContent-Length: 0\r\n\r\n",
        ]
        for headers in bad:
            with self.subTest(headers=headers[:80]):
                with self.assertRaises(HTTPRejected):
                    _read_response(
                        io.BytesIO(b"HTTP/1.1 200 OK\r\n" + headers), self.request()
                    )
        for status in (
            b"HTTP/1.1 100 Continue",
            b"HTTP/2 200 OK",
            b"HTTP/1.1 200 OK\n",
        ):
            with self.assertRaises(HTTPRejected):
                _read_response(
                    io.BytesIO(status + b"\r\nContent-Length: 0\r\n\r\n"),
                    self.request(),
                )

    def test_chunked_and_non200_observations(self) -> None:
        server = self.server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
        )
        response = _bounded(
            self.request(), lambda: CANARY, 3, functools.partial(loopback, server.port)
        )
        self.assertEqual(response.body, b"{}")
        for status in (302, 429):
            server = self.server(
                f"HTTP/1.1 {status} Test\r\nLocation: https://other.invalid/canary\r\nRetry-After: 3\r\nContent-Length: 0\r\n\r\n".encode()
            )
            response = _bounded(
                self.request(),
                lambda: CANARY,
                3,
                functools.partial(loopback, server.port),
            )
            self.assertEqual(response.status, status)
            self.assertEqual(response.headers, (("retry-after", "3"),))
            self.assertEqual(len(server.requests), 1)

    def test_timeout_unknown_no_retry_and_cleanup(self) -> None:
        before = {p.pid for p in multiprocessing.active_children()}
        server = self.server(delay=5)
        start = time.monotonic()
        with self.assertRaises(HTTPRejected):
            _bounded(
                self.request(),
                lambda: CANARY,
                0.5,
                functools.partial(loopback, server.port),
            )
        self.assertLess(time.monotonic() - start, 5)
        self.assertLessEqual(len(server.requests), 1)
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_cancel_after_connect_no_effect_and_cleanup(self) -> None:
        before = {p.pid for p in multiprocessing.active_children()}
        server = self.server()

        def cancel() -> str | None:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            _bounded(
                self.request(), cancel, 3, functools.partial(loopback, server.port)
            )
        server.thread.join(1)
        self.assertEqual(server.requests, [])
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_deadline_during_response_decode_withholds_observation(self) -> None:
        before = {p.pid for p in multiprocessing.active_children()}
        server = self.server()
        timeout = 3
        clock = Mock(monotonic=Mock(wraps=time.monotonic))
        decode = base64.b64decode

        def decode_at_deadline(encoded: str, *, validate: bool) -> bytes:
            body = decode(encoded, validate=validate)
            clock.monotonic.return_value = clock.monotonic() + timeout
            return body

        with (
            patch("tether.slack_http.time", clock),
            patch(
                "tether.slack_http.base64.b64decode", side_effect=decode_at_deadline
            ) as decoder,
        ):
            with self.assertRaisesRegex(HTTPRejected, "^HTTP outcome unknown$"):
                _bounded(
                    self.request(),
                    lambda: CANARY,
                    timeout,
                    functools.partial(loopback, server.port),
                )
        decoder.assert_called_once()
        self.assertEqual(len(server.requests), 1)
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_private_dns_rejected_before_socket(self) -> None:
        with (
            patch(
                "socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
                ],
            ),
            patch("socket.socket") as connect,
        ):
            with self.assertRaises(HTTPRejected):
                _connect_tls("slack.com", 1)
            connect.assert_not_called()

    def test_upload_token_rejected_before_connection(self) -> None:
        connect = Mock()
        with self.assertRaises(HTTPRejected):
            _exchange(upload_request(TICKET, INTENT), CANARY, 1, connect)
        connect.assert_not_called()

    def test_download_response_size_bound(self) -> None:
        request = replace(
            info_request(FileBinding(SCOPE, "F100")), max_response_bytes=0
        )
        with self.assertRaises(HTTPRejected):
            _read_response(
                io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"), request
            )

    def test_large_body_ipc(self) -> None:
        content = b"x" * 1048576
        server = self.server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n" + content
        )
        result = _bounded(
            self.request(), lambda: CANARY, 4, functools.partial(loopback, server.port)
        )
        self.assertEqual(result.body, content)

    def test_mixed_and_nonunicast_dns_rejected(self) -> None:
        for address in (
            "224.0.0.1",
            "ff02::1",
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "192.168.1.1",
            "::1",
        ):
            answers = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)),
            ]
            with (
                patch("socket.getaddrinfo", return_value=answers),
                patch("socket.socket") as create,
                patch("ssl.create_default_context"),
            ):
                with self.assertRaises(HTTPRejected):
                    _connect_tls("slack.com", 1)
                create.assert_not_called()

    def test_dns_pinned_connect_and_verified_tls_host(self) -> None:
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]
        with (
            patch("socket.getaddrinfo", return_value=answers) as dns,
            patch("socket.socket") as create,
            patch("ssl.create_default_context") as tls,
        ):
            _connect_tls("slack.com", 1)
            self.assertEqual(dns.call_count, 1)
            create.return_value.connect.assert_called_once_with(("1.1.1.1", 443))
            tls.return_value.wrap_socket.assert_called_once_with(
                create.return_value, server_hostname="slack.com"
            )

    def test_reentrant_authorizer_cannot_send_twice(self) -> None:
        calls = []
        transport: HTTPSingleShotTransport

        def authorize(request: Request) -> bool:
            with self.assertRaises(HTTPRejected):
                transport.exchange(request)
            return True

        def network(
            request: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            calls.append(approve())
            return Response(200, (), b"")

        transport = HTTPSingleShotTransport(
            lambda request: Credential(request, CANARY), authorize
        )
        with patch("tether.slack_http._bounded", network):
            transport.exchange(self.request())
        self.assertEqual(calls, [CANARY])

    def test_provider_exception_sanitized_and_lock_reusable(self) -> None:
        provider = Mock(side_effect=ValueError(CANARY))
        transport = HTTPSingleShotTransport(provider, lambda _: True)

        def network(
            request: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            approve()
            self.fail("provider failure reached send")

        with patch("tether.slack_http._bounded", network):
            for _ in range(2):
                with self.assertRaises(HTTPRejected) as caught:
                    transport.exchange(self.request())
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(provider.call_count, 2)

    def test_callback_request_drift_rejected(self) -> None:
        request = self.request()

        def authorize(value: Request) -> bool:
            object.__setattr__(value.scope, "channel_id", "C999")
            return True

        # A fresh nested scope prevents this malicious callback corrupting fixtures.
        request = replace(request, scope=replace(SCOPE))
        with patch("tether.slack_http._bounded") as network:
            with self.assertRaises(HTTPRejected):
                HTTPSingleShotTransport(Mock(), authorize).exchange(request)
            network.assert_not_called()

    def test_chunk_and_total_header_budgets(self) -> None:
        for headers in (
            b"".join(f"X-{i}: v\r\n".encode() for i in range(33)) + b"\r\n",
            b"".join(f"X-{i}: ".encode() + b"a" * 2000 + b"\r\n" for i in range(5))
            + b"\r\n",
            b"Transfer-Encoding: chunked\r\n\r\n" + b"1\r\nx\r\n" * 4096 + b"0\r\n\r\n",
        ):
            with self.assertRaises(HTTPRejected):
                _read_response(
                    io.BytesIO(b"HTTP/1.1 200 OK\r\n" + headers), self.request()
                )

    def test_cancellation_messages_are_sanitized_after_cleanup(self) -> None:
        before = {p.pid for p in multiprocessing.active_children()}
        for exception in (KeyboardInterrupt, SystemExit):
            server = self.server()

            def provider(request: Request) -> Credential:
                raise exception(CANARY)

            original = _bounded

            def network(
                request: Request,
                approve: Callable[[], str | None],
                timeout: float,
                connect: Connector,
            ) -> Response:
                return original(
                    request, approve, timeout, functools.partial(loopback, server.port)
                )

            transport = HTTPSingleShotTransport(provider, lambda _: True)
            with patch("tether.slack_http._bounded", network):
                with self.assertRaises(exception) as caught:
                    transport.exchange(self.request())
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn(CANARY, str(caught.exception))
            server.thread.join(1)
            self.assertEqual(server.requests, [])
            self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_security_mutations_fail_independent_observers(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "tether/slack_http.py").read_text()
        mutations = (
            (
                "or ipaddress.ip_address(a[4][0]).is_multicast",
                "or False",
                "test_mixed_and_nonunicast_dns_rejected",
            ),
            (
                'headers.append("Authorization: Bearer " + token)',
                'headers.append("X-Synthetic-Mutation: omitted-bearer")',
                "test_six_actions_and_exact_headers",
            ),
            (
                "        if time.monotonic() >= deadline:\n"
                '            raise HTTPRejected("HTTP outcome unknown")\n'
                "        return response",
                "        return response",
                "test_deadline_during_response_decode_withholds_observation",
            ),
        )
        for old, new, test in mutations:
            with tempfile.TemporaryDirectory(
                prefix="tether-http-mutation-"
            ) as directory:
                target = Path(directory)
                shutil.copytree(
                    root / "tether",
                    target / "tether",
                    ignore=shutil.ignore_patterns("__pycache__"),
                )
                shutil.copyfile(Path(__file__), target / "test_slack_http.py")
                self.assertIn(old, source)
                (target / "tether/slack_http.py").write_text(
                    source.replace(old, new, 1)
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "unittest",
                        "test_slack_http.HTTPTests." + test,
                    ],
                    cwd=target,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("FAIL:", result.stdout + result.stderr)
                self.assertNotIn("ImportError", result.stdout + result.stderr)

    def test_confirmed_post_send_socket_timeout_has_one_effect(self) -> None:
        server = self.server(delay=2)
        # No process startup race: the real socket timeout begins after connect.
        with self.assertRaises(TimeoutError):
            _exchange(
                self.request(), CANARY, 0.2, functools.partial(loopback, server.port)
            )
        self.assertEqual(len(server.requests), 1)


if __name__ == "__main__":
    unittest.main()
