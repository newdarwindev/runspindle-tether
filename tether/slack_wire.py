"""Bounded Slack wire codecs, with injected transport only.

No network implementation, credentials, retry, durable send orchestration, or
ProviderJournal receipt conversion. All observations are unqualified wire facts.
"""

import asyncio
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, cast
from urllib.parse import unquote, urlencode, urlsplit

from tether.admission import canonical, identifier
from tether.sanitization import Sanitizer

MAX_BYTES = 1048576
MAX_TEXT = 4000
MAX_PAGES = 8
MAX_MESSAGES = 120
MAX_CURSOR = 512
API = "https://slack.com/api/"


class WireRejected(ValueError):
    """Bounded input/response rejected; never include provider content in errors."""


def _string(value: object, limit: int = MAX_BYTES) -> str:
    if type(value) is not str:
        raise WireRejected("string type")
    encoded = None
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        pass
    if encoded is None:
        raise WireRejected("string encoding")
    if len(encoded) > limit:
        raise WireRejected("string limit")
    return value


def _id(value: object, prefix: str) -> str:
    text = _string(value, 64)
    if not re.fullmatch("[" + prefix + "][A-Z0-9]{1,63}", text):
        raise WireRejected("Slack identifier")
    return text


def _ts(value: object) -> str:
    text = _string(value, 32)
    if not re.fullmatch(r"[0-9]{1,20}\.[0-9]{6}", text):
        raise WireRejected("Slack timestamp")
    return text


def _integer(value: object, maximum: int = MAX_BYTES) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise WireRejected("integer bounds")
    return value


def _forbidden_number(value: str) -> Any:
    raise WireRejected("unsupported JSON number")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise WireRejected("duplicate JSON member")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise WireRejected("JSON size/type")
    try:
        result = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_forbidden_number,
            parse_float=_forbidden_number,
        )
        pending = [(result, 0)]
        nodes = 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if depth > 24 or nodes > 10000:
                raise WireRejected("JSON complexity")
            if type(value) is dict:
                for key, item in value.items():
                    _string(key)
                    pending.append((item, depth + 1))
            elif type(value) is list:
                pending.extend((item, depth + 1) for item in value)
            elif type(value) is str:
                _string(value)
            elif type(value) is int:
                if abs(value) > 2**63 - 1:
                    raise WireRejected("JSON integer bounds")
            elif value is not None and type(value) is not bool:
                raise WireRejected("JSON value")
        if type(result) is not dict:
            raise WireRejected("JSON object required")
        return cast(dict[str, Any], result)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        pass
    raise WireRejected("invalid JSON response")


@dataclass(frozen=True)
class FileIntent:
    artifact_id: str
    filename: str
    content: bytes = field(repr=False)
    text: str = field(repr=False)

    def digest(self) -> str:
        identifier(self.artifact_id)
        name = _string(self.filename, 256)
        if not name or any(ord(c) < 32 for c in name) or any(c in name for c in "/\\"):
            raise WireRejected("filename")
        text = _string(self.text)
        if len(text) > MAX_TEXT or type(self.content) is not bytes:
            raise WireRejected("payload type/limit")
        if len(text.encode("utf-8")) + len(self.content) > MAX_BYTES:
            raise WireRejected("payload limit")
        return hashlib.sha256(
            canonical(
                {
                    "text": text,
                    "attachments": [
                        {
                            "id": self.artifact_id,
                            "filename": name,
                            "sha256": hashlib.sha256(self.content).hexdigest(),
                            "bytes": len(self.content),
                        }
                    ],
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class Scope:
    account_id: str
    workspace_id: str
    channel_id: str
    thread_ts: str
    operation_id: str
    payload_sha256: str
    history_scope: str = "channels:history"

    def validate(self) -> None:
        identifier(self.account_id)
        identifier(self.operation_id)
        _id(self.workspace_id, "T")
        _id(self.channel_id, "CGD")
        _ts(self.thread_ts)
        allowed = {
            "C": ("channels:history",),
            "D": ("im:history",),
            "G": ("groups:history", "mpim:history"),
        }
        if self.history_scope not in allowed[self.channel_id[0]]:
            raise WireRejected("conversation history scope")
        if type(self.payload_sha256) is not str or not re.fullmatch(
            "[0-9a-f]{64}", self.payload_sha256
        ):
            raise WireRejected("payload digest")

    def bind(self, intent: FileIntent) -> None:
        self.validate()
        if type(intent) is not FileIntent or intent.digest() != self.payload_sha256:
            raise WireRejected("payload binding")


@dataclass(frozen=True)
class Request:
    scope: Scope
    action: str
    method: str
    url: str = field(repr=False)
    body: bytes = field(repr=False)
    content_type: str
    required_scope: str | None
    max_response_bytes: int = MAX_BYTES

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


def request_binding(request: Request) -> tuple[bytes, bytes]:
    """Detached exact request/scope snapshot, not callback authentication."""
    if type(request) is not Request or type(request.scope) is not Scope:
        raise WireRejected("request binding type")
    scope = {
        name: getattr(request.scope, name)
        for name in (
            "account_id",
            "workspace_id",
            "channel_id",
            "thread_ts",
            "operation_id",
            "payload_sha256",
            "history_scope",
        )
    }
    for value in scope.values():
        _string(value)
    request.scope.validate()
    fields: dict[str, Any] = {"scope": scope}
    for name in ("action", "method", "url", "content_type"):
        fields[name] = _string(getattr(request, name))
    if request.required_scope is not None:
        _string(request.required_scope)
    fields["required_scope"] = request.required_scope
    fields["max_response_bytes"] = _integer(request.max_response_bytes)
    if type(request.body) is not bytes or len(request.body) > MAX_BYTES:
        raise WireRejected("request body type or limit")
    return canonical(fields), request.body


def authorize_request(
    request: Request, authorize: Callable[[Request], bool] | None
) -> bool:
    before = request_binding(request)
    allowed, cancelled = False, ""
    try:
        allowed = authorize is not None and authorize(request) is True
    except Exception:
        pass
    except asyncio.CancelledError:
        cancelled = "async"
    except GeneratorExit:
        cancelled = "generator"
    except KeyboardInterrupt:
        cancelled = "interrupt"
    except SystemExit:
        cancelled = "exit"
    except BaseException:
        cancelled = "other"
    # Outside exception handlers: never expose callback text through a chain.
    if cancelled == "async":
        raise asyncio.CancelledError("authorization cancelled; outcome unknown")
    if cancelled == "generator":
        raise GeneratorExit("authorization cancelled; outcome unknown")
    if cancelled == "interrupt":
        raise KeyboardInterrupt("authorization cancelled; outcome unknown")
    if cancelled == "exit":
        raise SystemExit("authorization cancelled; outcome unknown")
    if cancelled:
        raise BaseException("authorization cancelled; outcome unknown")
    if request_binding(request) != before:
        raise WireRejected("request changed during authorization")
    return allowed


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)


class Transport(Protocol):
    def exchange(self, request: Request) -> Response: ...


@dataclass(frozen=True)
class Ticket:
    scope: Scope
    file_id: str
    upload_url: str = field(repr=False)


@dataclass(frozen=True)
class FileBinding:
    """Caller-supplied binding, NOT evidence of retention or authorization."""

    scope: Scope
    file_id: str


@dataclass(frozen=True)
class Share:
    workspace_id: str
    channel_id: str
    thread_ts: str
    message_ts: str


@dataclass(frozen=True)
class FileFacts:
    file_id: str
    filename: str
    size: int
    download_url: str = field(repr=False)
    shares: tuple[Share, ...]


@dataclass(frozen=True)
class MessageFacts:
    message_ts: str
    thread_ts: str
    text: str = field(repr=False)
    file_ids: tuple[str, ...]


@dataclass(frozen=True)
class Page:
    messages: tuple[MessageFacts, ...]
    next_cursor: str


@dataclass(frozen=True)
class ContentFacts:
    message: MessageFacts
    file: FileFacts
    downloaded_sha256: str
    downloaded_size: int


@dataclass(frozen=True)
class ContentConflict:
    """Multiple exact shares observed, never evidence of successful delivery."""

    messages: tuple[MessageFacts, ...]
    file: FileFacts
    downloaded_sha256: str
    downloaded_size: int


@dataclass(frozen=True)
class Result:
    """State is a parsing/comparison result, never an acceptance receipt."""

    state: str = "unknown"
    facts: Ticket | ContentFacts | ContentConflict | tuple[str, ...] | bytes | None = (
        field(default=None, repr=False)
    )
    retry_after: int | None = None
    evidence_class: str = field(default="unqualified_wire_observation", init=False)


def _url(value: object, prefix: str) -> str:
    url = _string(value, 2048)
    if any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "\\" in url:
        raise WireRejected("file URL characters")
    parts = urlsplit(url)
    path = unquote(parts.path, errors="strict")
    if (
        parts.scheme != "https"
        or parts.netloc != "files.slack.com"
        or parts.query
        or parts.fragment
        or not parts.path.startswith(prefix)
        or not path.startswith(prefix)
        or len(parts.path) <= len(prefix)
        or any(ord(c) <= 32 or ord(c) == 127 for c in path)
        or "\\" in path
        or any(piece in (".", "..") for piece in path.split("/"))
        or "%" in path
    ):
        raise WireRejected("file URL scope")
    return url


def allocate_request(scope: Scope, intent: FileIntent) -> Request:
    scope.bind(intent)
    return Request(
        scope,
        "allocate",
        "POST",
        API + "files.getUploadURLExternal",
        urlencode(
            {"filename": intent.filename, "length": len(intent.content)}
        ).encode(),
        "application/x-www-form-urlencoded",
        "files:write",
    )


def upload_request(ticket: Ticket, intent: FileIntent) -> Request:
    ticket.scope.bind(intent)
    _id(ticket.file_id, "F")
    return Request(
        ticket.scope,
        "upload",
        "POST",
        _url(ticket.upload_url, "/upload/v1/"),
        intent.content,
        "application/octet-stream",
        None,
    )


def complete_request(ticket: Ticket, intent: FileIntent) -> Request:
    ticket.scope.bind(intent)
    _id(ticket.file_id, "F")
    _url(ticket.upload_url, "/upload/v1/")
    return Request(
        ticket.scope,
        "complete",
        "POST",
        API + "files.completeUploadExternal",
        canonical(
            {
                "files": [{"id": ticket.file_id, "title": intent.filename}],
                "channel_id": ticket.scope.channel_id,
                "thread_ts": ticket.scope.thread_ts,
                "initial_comment": intent.text,
            }
        ),
        "application/json",
        "files:write",
    )


def info_request(binding: FileBinding) -> Request:
    binding.scope.validate()
    _id(binding.file_id, "F")
    return Request(
        binding.scope,
        "info",
        "GET",
        API + "files.info?" + urlencode({"file": binding.file_id}),
        b"",
        "",
        "files:read",
    )


def replies_request(scope: Scope, cursor: str = "") -> Request:
    scope.validate()
    _string(cursor, MAX_CURSOR)
    if any(ord(c) < 33 or ord(c) > 126 for c in cursor):
        raise WireRejected("cursor characters")
    params = {"channel": scope.channel_id, "ts": scope.thread_ts, "limit": "15"}
    if cursor:
        params["cursor"] = cursor
    return Request(
        scope,
        "replies",
        "GET",
        API + "conversations.replies?" + urlencode(params),
        b"",
        "",
        scope.history_scope,
    )


def download_request(binding: FileBinding, facts: FileFacts) -> Request:
    binding.scope.validate()
    _id(binding.file_id, "F")
    if facts.file_id != binding.file_id:
        raise WireRejected("file identity")
    _integer(facts.size)
    prefix = f"/files-pri/{binding.scope.workspace_id}-{binding.file_id}/"
    return Request(
        binding.scope,
        "download",
        "GET",
        _url(facts.download_url, prefix),
        b"",
        "",
        "files:read",
        facts.size,
    )


def _response(
    response: Response, request: Request
) -> tuple[dict[str, str], Result | None]:
    if type(response) is not Response or type(response.status) is not int:
        raise WireRejected("response type")
    limit = request.max_response_bytes if response.status == 200 else MAX_BYTES
    if type(response.body) is not bytes or len(response.body) > limit:
        raise WireRejected("response limit")
    if type(response.headers) is not tuple or len(response.headers) > 32:
        raise WireRejected("response headers")
    headers: dict[str, str] = {}
    for pair in response.headers:
        if type(pair) is not tuple or len(pair) != 2:
            raise WireRejected("response header shape")
        name, value = pair
        _string(name, 128)
        _string(value, 2048)
        if not re.fullmatch(r"[A-Za-z0-9-]+", name) or any(
            ord(c) < 32 or ord(c) > 126 for c in value
        ):
            raise WireRejected("response header characters")
        if name.lower() in headers:
            raise WireRejected("duplicate response header")
        headers[name.lower()] = value
    if headers.get("content-encoding", "identity") != "identity":
        raise WireRejected("unsupported response encoding")
    if "content-length" in headers:
        length = headers["content-length"]
        if not re.fullmatch(r"[0-9]{1,7}", length) or int(length) != len(response.body):
            raise WireRejected("response content length")
    # Do not follow redirects or infer success from an HTTP 200 alone.
    if response.status == 429:
        delay = headers.get("retry-after", "")
        if re.fullmatch(r"[0-9]{1,6}", delay) and int(delay) <= 86400:
            return headers, Result(retry_after=int(delay))
        return headers, Result()
    if response.status != 200:
        return headers, Result()
    return headers, None


def _api_object(response: Response, headers: dict[str, str]) -> dict[str, Any]:
    if (
        headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise WireRejected("JSON content type")
    body = _json(response.body)
    metadata = body.get("response_metadata", {})
    if (
        body.get("ok") is not True
        or type(metadata) is not dict
        or body.get("warning")
        or body.get("warnings")
        or metadata.get("warnings")
    ):
        raise WireRejected("API response not complete")
    return body


def _file(body: dict[str, Any], binding: FileBinding) -> FileFacts:
    value = body.get("file")
    if type(value) is not dict or _id(value.get("id"), "F") != binding.file_id:
        raise WireRejected("file identity")
    if (
        value.get("is_external") is not False
        or value.get("mode") not in ("hosted", "snippet")
        or value.get("file_access") not in (None, "visible")
        or value.get("has_more_shares", False) is not False
        or value.get("skipped_shares", False) is not False
    ):
        raise WireRejected("file incomplete/unsupported")
    name = _string(value.get("name"), 256)
    size = _integer(value.get("size"))
    url = _url(
        value.get("url_private"),
        f"/files-pri/{binding.scope.workspace_id}-{binding.file_id}/",
    )
    sharing = value.get("shares")
    if type(sharing) is not dict or set(sharing) - {"public", "private"}:
        raise WireRejected("file share shape")
    shares: list[Share] = []
    for channels in sharing.values():
        if type(channels) is not dict:
            raise WireRejected("file channel shape")
        for channel, rows in channels.items():
            _id(channel, "CGD")
            if type(rows) is not list:
                raise WireRejected("file share rows")
            for row in rows:
                if type(row) is not dict or len(shares) >= MAX_MESSAGES:
                    raise WireRejected("file share limit/shape")
                shares.append(
                    Share(
                        _id(row.get("team_id"), "T"),
                        channel,
                        _ts(row.get("thread_ts")),
                        _ts(row.get("ts")),
                    )
                )
    if len(set(shares)) != len(shares):
        raise WireRejected("duplicate file shares")
    return FileFacts(binding.file_id, name, size, url, tuple(shares))


def _page(body: dict[str, Any]) -> Page:
    rows = body.get("messages")
    more = body.get("has_more")
    metadata = body.get("response_metadata", {})
    cursor = _string(metadata.get("next_cursor", ""), MAX_CURSOR)
    if type(rows) is not list or len(rows) > 15 or type(more) is not bool:
        raise WireRejected("reply page shape/limit")
    if more != bool(cursor) or any(ord(c) < 33 or ord(c) > 126 for c in cursor):
        raise WireRejected("incomplete reply pagination")
    messages = []
    for row in rows:
        if (
            type(row) is not dict
            or row.get("type") != "message"
            or row.get("subtype") not in (None, "file_share")
            or row.get("attachments")
            or row.get("blocks")
        ):
            raise WireRejected("message type")
        ts = _ts(row.get("ts"))
        thread = _ts(row.get("thread_ts", ts))
        text = _string(row.get("text"))
        files = row.get("files", [])
        if type(files) is not list or len(files) > 8:
            raise WireRejected("message files")
        ids = []
        for item in files:
            if type(item) is not dict:
                raise WireRejected("message file shape")
            ids.append(_id(item.get("id"), "F"))
        if len(set(ids)) != len(ids):
            raise WireRejected("duplicate message file")
        messages.append(MessageFacts(ts, thread, text, tuple(ids)))
    return Page(tuple(messages), cursor)


class WireClient:
    """Single explicit requests or read-only bounded observations; no sender loop.

    The callback must approve each exact Request, not just the operation ID.
    This library cannot authenticate that callback or an injected transport.
    """

    def __init__(
        self, transport: Transport, authorize: Callable[[Request], bool] | None = None
    ) -> None:
        self.transport = transport
        self.authorize = authorize

    def _call(self, request: Request) -> tuple[Response, dict[str, str], Result | None]:
        # Every call, including each readback page, requires a fresh exact decision.
        if not authorize_request(request, self.authorize):
            raise WireRejected("request scope not authorized")
        response = self.transport.exchange(request)
        headers, result = _response(response, request)
        return response, headers, result

    def allocate(self, scope: Scope, intent: FileIntent) -> Result:
        request = allocate_request(scope, intent)
        try:
            response, headers, result = self._call(request)
            if result is not None:
                return result
            body = _api_object(response, headers)
            ticket = Ticket(
                scope,
                _id(body.get("file_id"), "F"),
                _url(body.get("upload_url"), "/upload/v1/"),
            )
            return Result("parsed", ticket)
        except Exception:
            return Result()

    def upload(self, ticket: Ticket, intent: FileIntent) -> Result:
        request = upload_request(ticket, intent)
        try:
            response, _, result = self._call(request)
            return (
                result
                if result is not None
                else Result("upload_response", response.body)
            )
        except Exception:
            return Result()

    def complete(self, ticket: Ticket, intent: FileIntent) -> Result:
        request = complete_request(ticket, intent)
        try:
            response, headers, result = self._call(request)
            if result is not None:
                return result
            rows = _api_object(response, headers).get("files")
            if (
                type(rows) is not list
                or len(rows) != 1
                or type(rows[0]) is not dict
                or _id(rows[0].get("id"), "F") != ticket.file_id
            ):
                return Result()
            return Result("parsed", (ticket.file_id,))
        except Exception:
            return Result()

    def readback(
        self,
        binding: FileBinding,
        intent: FileIntent,
        max_pages: int = 4,
        *,
        sanitizer: Sanitizer | None = None,
    ) -> Result:
        binding.scope.bind(intent)
        _integer(max_pages, MAX_PAGES)
        if max_pages == 0:
            raise WireRejected("page budget")
        first = info_request(binding)
        try:
            response, headers, result = self._call(first)
            if result is not None:
                return result
            facts = _file(_api_object(response, headers), binding)
            if facts.filename != intent.filename or facts.size != len(intent.content):
                return Result()
            if sanitizer is not None:
                # The URL parser has already bound the host and prefix. Scan
                # the exact path and decoded form before any follow-up request.
                path = urlsplit(facts.download_url).path
                sanitizer.require_clean([path, unquote(path, errors="strict")])
            cursor = ""
            seen_cursors = set()
            seen_messages = set()
            messages: list[MessageFacts] = []
            for _ in range(max_pages):
                response, headers, result = self._call(
                    replies_request(binding.scope, cursor)
                )
                if result is not None:
                    return result
                page = _page(_api_object(response, headers))
                for message in page.messages:
                    if (
                        message.message_ts in seen_messages
                        or message.thread_ts != binding.scope.thread_ts
                    ):
                        return Result()
                    seen_messages.add(message.message_ts)
                    messages.append(message)
                if len(messages) > MAX_MESSAGES:
                    return Result()
                cursor = page.next_cursor
                if not cursor:
                    break
                if sanitizer is not None:
                    sanitizer.require_clean([cursor, unquote(cursor, errors="strict")])
                if cursor in seen_cursors:
                    return Result()
                seen_cursors.add(cursor)
            else:
                return Result()
            matches = [
                message for message in messages if binding.file_id in message.file_ids
            ]
            if not matches:
                return Result()
            expected_shares = {
                Share(
                    binding.scope.workspace_id,
                    binding.scope.channel_id,
                    binding.scope.thread_ts,
                    message.message_ts,
                )
                for message in matches
            }
            if (
                any(
                    message.file_ids != (binding.file_id,)
                    or message.text != intent.text
                    for message in matches
                )
                or set(facts.shares) != expected_shares
            ):
                return Result()
            request = download_request(binding, facts)
            response, _, result = self._call(request)
            if result is not None:
                return result
            if response.body != intent.content:
                return Result()
            if len(matches) > 1:
                return Result(
                    "content_conflict",
                    ContentConflict(
                        tuple(matches),
                        facts,
                        hashlib.sha256(response.body).hexdigest(),
                        len(response.body),
                    ),
                )
            return Result(
                "content_match",
                ContentFacts(
                    matches[0],
                    facts,
                    hashlib.sha256(response.body).hexdigest(),
                    len(response.body),
                ),
            )
        except Exception:
            return Result()
