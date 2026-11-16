"""Single-shot HTTPS transport; trusted authorization is supplied by the host.

No credential discovery, retries, redirects, proxy support or delivery receipts.
Network work is isolated in a bounded ephemeral process, not a service.
"""

import base64
import ipaddress
import json
import multiprocessing
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from multiprocessing.connection import Connection
from typing import BinaryIO
from urllib.parse import parse_qsl, urlsplit

from tether.slack_wire import MAX_BYTES, Request, Response, Scope, _id, _url


class HTTPRejected(ValueError):
    """Fixed diagnostic only. A failure may follow an externally applied effect."""


@dataclass(frozen=True)
class Credential:
    """Host-attested exact request binding, not an authenticated identity itself."""

    request: Request = field(repr=False)
    bearer: str = field(repr=False)


CredentialProvider = Callable[[Request], Credential]
Connector = Callable[[str, float], socket.socket]


def _validate(request: Request) -> tuple[str, str]:
    if type(request) is not Request or type(request.scope) is not Scope:
        raise HTTPRejected("request rejected")
    request.scope.validate()
    if (
        type(request.body) is not bytes
        or len(request.body) > MAX_BYTES
        or type(request.max_response_bytes) is not int
        or not 0 <= request.max_response_bytes <= MAX_BYTES
        or type(request.url) is not str
        or len(request.url) > 2048
        or any(ord(c) < 33 or ord(c) > 126 for c in request.url)
        or "\\" in request.url
    ):
        raise HTTPRejected("request rejected")
    parts = urlsplit(request.url)
    if parts.scheme != "https" or parts.fragment:
        raise HTTPRejected("origin rejected")
    mapping = {
        "allocate": (
            "POST",
            "/api/files.getUploadURLExternal",
            "files:write",
            "application/x-www-form-urlencoded",
        ),
        "complete": (
            "POST",
            "/api/files.completeUploadExternal",
            "files:write",
            "application/json",
        ),
        "info": ("GET", "/api/files.info", "files:read", ""),
        "replies": (
            "GET",
            "/api/conversations.replies",
            request.scope.history_scope,
            "",
        ),
    }
    if request.action in mapping:
        expected = mapping[request.action]
        actual = (
            request.method,
            parts.path,
            request.required_scope,
            request.content_type,
        )
        if parts.netloc != "slack.com" or actual != expected:
            raise HTTPRejected("endpoint rejected")
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        query = dict(pairs)
        if len(query) != len(pairs):
            raise HTTPRejected("query rejected")
        if request.action == "info":
            if set(query) != {"file"}:
                raise HTTPRejected("query rejected")
            _id(query["file"], "F")
        elif request.action == "replies":
            if (
                set(query)
                not in (
                    {"channel", "ts", "limit"},
                    {"channel", "ts", "limit", "cursor"},
                )
                or query.get("channel") != request.scope.channel_id
                or query.get("ts") != request.scope.thread_ts
                or query.get("limit") != "15"
                or len(query.get("cursor", "")) > 512
                or any(ord(c) < 33 or ord(c) > 126 for c in query.get("cursor", ""))
            ):
                raise HTTPRejected("query rejected")
        elif parts.query:
            raise HTTPRejected("query rejected")
    elif request.action == "upload":
        _url(request.url, "/upload/v1/")
        if (request.method, request.required_scope, request.content_type) != (
            "POST",
            None,
            "application/octet-stream",
        ):
            raise HTTPRejected("upload rejected")
    elif request.action == "download":
        prefix = f"/files-pri/{request.scope.workspace_id}-"
        _url(request.url, prefix)
        file_id = parts.path[len(prefix) :].split("/", 1)[0]
        _id(file_id, "F")
        if "/" not in parts.path[len(prefix) :] or (
            request.method,
            request.required_scope,
            request.content_type,
        ) != ("GET", "files:read", ""):
            raise HTTPRejected("download rejected")
    else:
        raise HTTPRejected("action rejected")
    if request.method == "GET" and request.body:
        raise HTTPRejected("body rejected")
    return parts.netloc, parts.path + ("?" + parts.query if parts.query else "")


def _connect_tls(host: str, timeout: float) -> socket.socket:
    # Resolve once, reject all non-public answers, connect only the selected answer.
    # No proxy environment variables are consulted. TLS verifies the original host.
    answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not answers or any(
        not ipaddress.ip_address(a[4][0]).is_global
        or ipaddress.ip_address(a[4][0]).is_multicast
        or ipaddress.ip_address(a[4][0]).is_reserved
        for a in answers
    ):
        raise HTTPRejected("address rejected")
    family, kind, protocol, _, address = answers[0]
    raw = socket.socket(family, kind, protocol)
    try:
        raw.settimeout(timeout)
        raw.connect(address)
        return ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def _line(stream: BinaryIO, limit: int) -> bytes:
    value = stream.readline(limit + 1)
    if not value.endswith(b"\r\n") or len(value) > limit:
        raise HTTPRejected("HTTP line rejected")
    return value[:-2]


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise HTTPRejected("HTTP body truncated")
    return value


def _read_response(stream: BinaryIO, request: Request) -> Response:
    status_line = _line(stream, 256)
    if not re.fullmatch(rb"HTTP/1\.[01] [2-5][0-9]{2} [\x20-\x7e]*", status_line):
        raise HTTPRejected("HTTP status rejected")
    status = int(status_line[9:12])
    headers: dict[str, str] = {}
    budget = 8192
    while True:
        line = _line(stream, min(2180, budget))
        budget -= len(line) + 2
        if not line:
            break
        if len(headers) >= 32 or b":" not in line:
            raise HTTPRejected("HTTP headers rejected")
        name, value = line.split(b":", 1)
        if not re.fullmatch(rb"[A-Za-z0-9-]{1,128}", name) or any(
            c < 32 or c > 126 for c in value
        ):
            raise HTTPRejected("HTTP headers rejected")
        key = name.decode("ascii").lower()
        if key in headers or len(value) > 2048:
            raise HTTPRejected("HTTP headers rejected")
        headers[key] = value.decode("ascii").strip(" ")
    if headers.get("content-encoding", "identity") != "identity":
        raise HTTPRejected("HTTP encoding rejected")
    length = headers.get("content-length")
    transfer = headers.get("transfer-encoding")
    limit = request.max_response_bytes if status == 200 else MAX_BYTES
    if length is not None:
        if (
            transfer is not None
            or not re.fullmatch(r"[0-9]{1,7}", length)
            or int(length) > limit
        ):
            raise HTTPRejected("HTTP framing rejected")
        body = _read_exact(stream, int(length))
    elif transfer == "chunked":
        chunks = []
        total = 0
        for _ in range(4096):
            line = _line(stream, 16)
            if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", line):
                raise HTTPRejected("HTTP chunk rejected")
            size = int(line, 16)
            if size == 0:
                if _line(stream, 2):
                    raise HTTPRejected("HTTP trailers rejected")
                break
            total += size
            if total > limit:
                raise HTTPRejected("HTTP body limit")
            chunks.append(_read_exact(stream, size))
            if _read_exact(stream, 2) != b"\r\n":
                raise HTTPRejected("HTTP chunk rejected")
        else:
            raise HTTPRejected("HTTP chunk limit")
        body = b"".join(chunks)
    else:
        # Deliberate subset: no ambiguous close-delimited or unsupported framing.
        raise HTTPRejected("HTTP framing rejected")
    # Do not propagate server diagnostics, cookies, locations or arbitrary headers.
    retained = tuple(
        (k, v) for k, v in headers.items() if k in ("content-type", "retry-after")
    )
    return Response(status, retained, body)


def _exchange(
    request: Request, token: str | None, timeout: float, connect: Connector
) -> Response:
    host, target = _validate(request)
    headers = [
        f"{request.method} {target} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "Accept-Encoding: identity",
        f"Content-Length: {len(request.body)}",
    ]
    if request.content_type:
        headers.append("Content-Type: " + request.content_type)
    if request.action != "upload":
        if type(token) is not str or not re.fullmatch(
            r"[A-Za-z0-9._~-]{1,4096}", token
        ):
            raise HTTPRejected("credential rejected")
        headers.append("Authorization: Bearer " + token)
    elif token is not None:
        raise HTTPRejected("upload credential rejected")
    with connect(host, timeout) as connection:
        connection.sendall(
            ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + request.body
        )
        with connection.makefile("rb") as stream:
            return _read_response(stream, request)


def _worker(
    pipe: Connection, request: Request, timeout: float, connect: Connector
) -> None:
    try:
        host, _ = _validate(request)
        with connect(host, timeout) as connection:
            pipe.send_bytes(b"ready")
            token_bytes = pipe.recv_bytes(4096)
            token = token_bytes.decode("ascii") if token_bytes else None
            result = _exchange(
                request, token, timeout, lambda _host, _timeout: connection
            )
        payload = json.dumps(
            [
                result.status,
                result.headers,
                base64.b64encode(result.body).decode("ascii"),
            ]
        ).encode("ascii")
        # Atomic small pipe frames keep parent recv bounded after poll.
        for offset in range(0, len(payload), 2048):
            pipe.send_bytes(payload[offset : offset + 2048])
        pipe.send_bytes(b"")
    except BaseException:
        # No exception object, traceback, URL, credential or payload crosses IPC.
        pass
    finally:
        pipe.close()


def _bounded(
    request: Request,
    approve: Callable[[], str | None],
    timeout: float,
    connect: Connector,
) -> Response:
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=True)
    child = context.Process(
        target=_worker, args=(send, request, timeout, connect), daemon=True
    )
    deadline = time.monotonic() + timeout
    started = False
    try:
        child.start()
        started = True
        send.close()
        remaining = deadline - time.monotonic()
        if (
            remaining <= 0
            or not receive.poll(remaining)
            or receive.recv_bytes(2048) != b"ready"
        ):
            raise HTTPRejected("HTTP outcome unknown")
        # Host guard runs after DNS/TLS and immediately before request emission.
        token = approve()
        if time.monotonic() >= deadline:
            raise HTTPRejected("HTTP outcome unknown")
        receive.send_bytes(token.encode("ascii") if token is not None else b"")
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not receive.poll(remaining):
                raise HTTPRejected("HTTP outcome unknown")
            frame = receive.recv_bytes(2048)
            if not frame:
                break
            data.extend(frame)
            if len(data) > 2 * MAX_BYTES:
                raise HTTPRejected("HTTP outcome unknown")
        status, headers, encoded = json.loads(data)
        return Response(
            status,
            tuple(tuple(pair) for pair in headers),
            base64.b64decode(encoded, validate=True),
        )
    finally:
        receive.close()
        send.close()
        if started:
            if child.is_alive():
                child.terminate()
            child.join(1)
            if child.is_alive():
                child.kill()
                child.join(1)
        if not started or not child.is_alive():
            child.close()


class HTTPSingleShotTransport:
    """Host must authorize each exact request and supply a scoped credential.

    The provider must verify account/workspace/lease/current authority itself;
    Scope has no lease credential. No default provider or live integration exists.
    Use WireClient's authorization plus the durable upload fence, never a retry loop.
    Provider execution is trusted host code outside the network deadline.
    """

    def __init__(
        self,
        credential_provider: CredentialProvider,
        authorize: Callable[[Request], bool],
        timeout: float = 10.0,
    ) -> None:
        if (
            not callable(credential_provider)
            or not callable(authorize)
            or type(timeout) not in (int, float)
            or not 0 < timeout <= 30
        ):
            raise HTTPRejected("configuration rejected")
        self._provider = credential_provider
        self._authorize = authorize
        self._timeout = float(timeout)
        self._busy = threading.Lock()

    def exchange(self, request: Request) -> Response:
        if not self._busy.acquire(blocking=False):
            raise HTTPRejected("transport busy")
        try:
            return self._guarded_exchange(request)
        finally:
            self._busy.release()

    def _guarded_exchange(self, request: Request) -> Response:
        cancelled = ""
        try:
            _validate(request)
            snapshot = replace(request, scope=replace(request.scope))
            if self._authorize(request) is not True:
                raise HTTPRejected("request not authorized")

            if request != snapshot:
                raise HTTPRejected("request changed")

            def approve() -> str | None:
                token = None
                if request.action != "upload":
                    credential = self._provider(request)
                    if (
                        type(credential) is not Credential
                        or credential.request != request
                    ):
                        raise HTTPRejected("credential binding rejected")
                    token = credential.bearer
                    if type(token) is not str or not re.fullmatch(
                        r"[A-Za-z0-9._~-]{1,4096}", token
                    ):
                        raise HTTPRejected("credential rejected")
                if self._authorize(request) is not True:
                    raise HTTPRejected("request not authorized")
                if request != snapshot:
                    raise HTTPRejected("request changed")
                return token

            return _bounded(request, approve, self._timeout, _connect_tls)
        except Exception:
            pass
        except KeyboardInterrupt:
            cancelled = "interrupt"
        except SystemExit:
            cancelled = "exit"
        except BaseException:
            cancelled = "other"
        # Outside except: no chained unsanitized provider/socket exception.
        if cancelled == "interrupt":
            raise KeyboardInterrupt("HTTP cancelled; outcome unknown")
        if cancelled == "exit":
            raise SystemExit("HTTP cancelled; outcome unknown")
        if cancelled:
            raise BaseException("HTTP cancelled; outcome unknown")
        raise HTTPRejected("HTTP outcome unknown")
