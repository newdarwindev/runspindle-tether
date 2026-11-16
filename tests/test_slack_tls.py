"""Real synthetic loopback TLS; no system trust changes or live Slack calls."""

import functools
import multiprocessing
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from tether.slack_http import (
    Connector,
    Credential,
    HTTPRejected,
    HTTPSingleShotTransport,
    _bounded,
    _connect_tls,
    _exchange,
)
from tether.slack_wire import FileIntent, Request, Response, Scope, allocate_request

INTENT = FileIntent(
    "tls-artifact", "result.txt", b"synthetic bytes", "Synthetic result"
)
SCOPE = Scope(
    "tls-account", "T100", "C100", "1700000000.000001", "tls-operation", INTENT.digest()
)
CANARY = "synthetic-tls-bearer-canary"


def tls_loopback(port: int, ca: str | None, host: str, timeout: float) -> socket.socket:
    """Only test routing/trust are injected; actual TLS verification stays enabled.

    Spawned cases isolate these scoped mocks in the worker. Direct connector cases
    apply them in the test process while its loopback server thread runs.
    The original production connector still resolves, validates, connects and wraps.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca is not None:
        context.load_verify_locations(cafile=ca)
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise AssertionError("test disabled TLS verification")

    class RoutedSocket(socket.socket):
        def connect(self, address: Any) -> None:
            if address != ("1.1.1.1", 443):
                raise AssertionError("unexpected resolved address")
            super().connect(("127.0.0.1", port))

    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]
    with (
        patch("socket.getaddrinfo", return_value=answers),
        patch("socket.socket", RoutedSocket),
        patch("ssl.create_default_context", return_value=context),
    ):
        return _connect_tls(host, timeout)


class TLSServer:
    def __init__(self, cert: Path, key: Path, stall: bool = False) -> None:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.sni: list[str | None] = []
        self.context.set_servername_callback(
            lambda connection, name, context: self.sni.append(name)
        )
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(6)
        self.port = self.listener.getsockname()[1]
        self.stall = stall
        self.requests: list[bytes] = []
        self.handshake_prefix = b""
        self.verified_channel = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self) -> None:
        try:
            with self.listener.accept()[0] as raw:
                raw.settimeout(5)
                if self.stall:
                    self.handshake_prefix = raw.recv(4096)
                    self.stop.wait(5)
                    return
                with self.context.wrap_socket(raw, server_side=True) as connection:
                    self.verified_channel.set()
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
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                    )
        except (OSError, ValueError):
            pass
        finally:
            self.listener.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(7)
        self.listener.close()
        if self.thread.is_alive():
            raise AssertionError("TLS server leaked")


class TLSTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    root: Path

    @classmethod
    def setUpClass(cls) -> None:
        executable = shutil.which("openssl")
        if executable is None:
            raise RuntimeError(
                "TLS tests require preinstalled OpenSSL; no implicit install"
            )
        cls.temporary = tempfile.TemporaryDirectory(prefix="tether-test-tls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)

        def openssl(*arguments: str) -> None:
            subprocess.run(
                [executable, *arguments],
                cwd=cls.root,
                capture_output=True,
                check=True,
                timeout=15,
            )

        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Synthetic Tether Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        for name, hostname in (("valid", "slack.com"), ("wrong", "wrong.invalid")):
            openssl(
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                name + ".key",
                "-out",
                name + ".csr",
                "-subj",
                "/CN=" + hostname,
            )
            (cls.root / (name + ".ext")).write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:"
                + hostname
                + "\n"
            )
            openssl(
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                "1" if name == "valid" else "2",
                "-out",
                name + ".pem",
                "-days",
                "1",
                "-extfile",
                name + ".ext",
            )

    def server(self, name: str = "valid", stall: bool = False) -> TLSServer:
        server = TLSServer(
            self.root / (name + ".pem"), self.root / (name + ".key"), stall
        )
        self.addCleanup(server.close)
        return server

    def test_verified_handshake_precedes_credential_and_http(self) -> None:
        server = self.server()
        request = allocate_request(SCOPE, INTENT)
        calls = []

        def provider(value: Request) -> Credential:
            self.assertTrue(server.verified_channel.wait(1))
            self.assertEqual(server.requests, [])
            calls.append(value)
            return Credential(value, CANARY)

        original = _bounded

        def network(
            value: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            return original(
                value,
                approve,
                timeout,
                functools.partial(tls_loopback, server.port, str(self.root / "ca.pem")),
            )

        with patch("tether.slack_http._bounded", network):
            result = HTTPSingleShotTransport(provider, lambda _: True, 5).exchange(
                request
            )
        server.thread.join(1)
        self.assertEqual(result.body, b"{}")
        self.assertEqual(server.sni, ["slack.com"])
        self.assertEqual(calls, [request])
        self.assertEqual(len(server.requests), 1)
        self.assertIn(
            b"Authorization: Bearer " + CANARY.encode() + b"\r\n", server.requests[0]
        )

    def test_real_tls_rejects_wrong_hostname_and_untrusted_ca(self) -> None:
        for name, ca in (("wrong", str(self.root / "ca.pem")), ("valid", None)):
            server = self.server(name)
            with self.assertRaises(ssl.SSLCertVerificationError) as caught:
                _exchange(
                    allocate_request(SCOPE, INTENT),
                    CANARY,
                    2,
                    functools.partial(tls_loopback, server.port, ca),
                )
            # Actual OpenSSL verification codes: hostname mismatch / self-signed chain.
            self.assertIn(caught.exception.verify_code, (62, 19, 20, 21))
            server.thread.join(1)
            self.assertEqual(server.requests, [])
            self.assertFalse(server.verified_channel.is_set())

    def test_tls_failure_never_resolves_credential_or_sends_http(self) -> None:
        before = {p.pid for p in multiprocessing.active_children()}
        original = _bounded
        for name, ca in (("wrong", str(self.root / "ca.pem")), ("valid", None)):
            server = self.server(name)
            provider = Mock(
                side_effect=AssertionError("credential resolved before TLS")
            )

            def network(
                value: Request,
                approve: Callable[[], str | None],
                timeout: float,
                connect: Connector,
            ) -> Response:
                return original(
                    value,
                    approve,
                    timeout,
                    functools.partial(tls_loopback, server.port, ca),
                )

            with patch("tether.slack_http._bounded", network):
                with self.assertRaises(HTTPRejected) as caught:
                    HTTPSingleShotTransport(provider, lambda _: True, 5).exchange(
                        allocate_request(SCOPE, INTENT)
                    )
            self.assertIsNone(caught.exception.__context__)
            provider.assert_not_called()
            server.thread.join(1)
            self.assertEqual(server.requests, [])
            self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_real_handshake_timeout_has_no_http_or_token(self) -> None:
        server = self.server(stall=True)
        with self.assertRaises(TimeoutError):
            _exchange(
                allocate_request(SCOPE, INTENT),
                CANARY,
                0.3,
                functools.partial(tls_loopback, server.port, str(self.root / "ca.pem")),
            )
        self.assertTrue(server.handshake_prefix.startswith(b"\x16\x03"))
        self.assertNotIn(CANARY.encode(), server.handshake_prefix)
        self.assertEqual(server.requests, [])

    def test_spawn_handshake_deadline_reaps_worker(self) -> None:
        server = self.server(stall=True)
        before = {p.pid for p in multiprocessing.active_children()}
        provider = Mock(side_effect=AssertionError("credential resolved before TLS"))
        original = _bounded

        def network(
            value: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            return original(
                value,
                approve,
                timeout,
                functools.partial(tls_loopback, server.port, str(self.root / "ca.pem")),
            )

        start = time.monotonic()
        with patch("tether.slack_http._bounded", network):
            with self.assertRaises(HTTPRejected):
                HTTPSingleShotTransport(provider, lambda _: True, 3).exchange(
                    allocate_request(SCOPE, INTENT)
                )
        self.assertLess(time.monotonic() - start, 5)
        provider.assert_not_called()
        self.assertNotIn(CANARY.encode(), server.handshake_prefix)
        self.assertEqual(server.requests, [])
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_cancellation_after_verified_tls_has_no_request(self) -> None:
        server = self.server()
        before = {p.pid for p in multiprocessing.active_children()}
        original = _bounded

        def provider(value: Request) -> Credential:
            self.assertTrue(server.verified_channel.wait(1))
            raise KeyboardInterrupt(CANARY)

        def network(
            value: Request,
            approve: Callable[[], str | None],
            timeout: float,
            connect: Connector,
        ) -> Response:
            return original(
                value,
                approve,
                timeout,
                functools.partial(tls_loopback, server.port, str(self.root / "ca.pem")),
            )

        with patch("tether.slack_http._bounded", network):
            with self.assertRaises(KeyboardInterrupt) as caught:
                HTTPSingleShotTransport(provider, lambda _: True, 5).exchange(
                    allocate_request(SCOPE, INTENT)
                )
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        server.thread.join(1)
        self.assertEqual(server.requests, [])
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)


if __name__ == "__main__":
    unittest.main()
