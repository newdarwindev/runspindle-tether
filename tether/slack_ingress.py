"""Signed Slack Events API messages into existing durable admission.

No listener, credential discovery, URL-challenge response, dispatch or network.
Only ordinary creates for one explicitly configured app/user/destination bind.
See specs/signed-slack-ingress-v1.md for the deliberately narrow trust boundary.
"""

import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tether.admission import Admission, Grant, Identity, Rejected, canonical
from tether.sanitization import Sanitizer
from tether.slack_wire import MAX_BYTES, _id, _json, _string, _ts

MAX_HEADERS = 64
MAX_HEADER_BYTES = 16384
MAX_SKEW_SECONDS = 300


@dataclass(frozen=True)
class Route:
    """Trusted exact installation, actor and destination; not request input."""

    app_id: str
    workspace_id: str
    actor_id: str
    channel_id: str
    thread_ts: str

    def validate(self) -> None:
        _id(self.app_id, "A")
        _id(self.workspace_id, "T")
        _id(self.actor_id, "UW")
        _id(self.channel_id, "CGD")
        _ts(self.thread_ts)

    @property
    def identity(self) -> Identity:
        return Identity(
            self.actor_id, self.workspace_id, self.channel_id, self.thread_ts
        )


@dataclass(frozen=True)
class _Proof:
    owner: object = field(repr=False)
    normalized_sha256: str
    identity: Identity


def _headers(rows: object, body_size: int) -> dict[str, str]:
    # A mapping may already have collapsed duplicate headers. Require original
    # ordered pairs, not a dict, and reject even duplicate irrelevant headers.
    if type(rows) is not tuple or not 1 <= len(rows) <= MAX_HEADERS:
        raise Rejected("Slack header bounds")
    result: dict[str, str] = {}
    size = 0
    for row in rows:
        if type(row) is not tuple or len(row) != 2:
            raise Rejected("Slack header shape")
        name, value = row
        if type(name) is not str or type(value) is not str:
            raise Rejected("Slack header type")
        size += len(name) + len(value)
        if size > MAX_HEADER_BYTES:
            raise Rejected("Slack header bounds")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(
            ord(c) < 32 or ord(c) > 126 for c in value
        ):
            raise Rejected("Slack header syntax")
        key = name.lower()
        if key in result:
            raise Rejected("duplicate Slack header")
        result[key] = value
    if result.get("content-type", "").lower() not in (
        "application/json",
        "application/json; charset=utf-8",
    ):
        raise Rejected("Slack content type")
    if (
        "transfer-encoding" in result
        or result.get("content-encoding", "identity") != "identity"
    ):
        raise Rejected("Slack content encoding")
    if "content-length" in result and result["content-length"] != str(body_size):
        raise Rejected("Slack content length")
    if not re.fullmatch(r"v0=[0-9a-f]{64}", result.get("x-slack-signature", "")):
        raise Rejected("Slack signature format")
    stamp = result.get("x-slack-request-timestamp", "")
    if not re.fullmatch(r"[1-9][0-9]{0,18}", stamp) or int(stamp) > 2**63 - 1:
        raise Rejected("Slack timestamp format")
    return result


def _routing_fields(value: dict[str, Any], workspace_id: str) -> None:
    # Known alternate Slack routing fields are not harmless unknown metadata.
    # This subset has no Enterprise or cross-workspace identity mapping.
    if value.get("is_ext_shared_channel", False) is not False:
        raise Rejected("unsupported Slack shared-channel routing")
    for key in ("team", "team_id", "user_team", "context_team_id"):
        if key in value and value[key] != workspace_id:
            raise Rejected("Slack workspace routing binding")
    if (
        any(
            value.get(key) is not None
            for key in ("enterprise", "enterprise_id", "context_enterprise_id")
        )
        or value.get("is_enterprise_install", False) is not False
    ):
        raise Rejected("unsupported Slack enterprise routing")


def _callback(
    value: dict[str, Any], route: Route, kinds: tuple[str, ...] = ("message",)
) -> tuple[str, dict[str, Any]]:
    if value.get("type") != "event_callback":
        raise Rejected("unsupported Slack callback")
    if (
        value.get("api_app_id") != route.app_id
        or value.get("team_id") != route.workspace_id
    ):
        raise Rejected("Slack installation binding")
    # Cross-workspace/Enterprise installation routing needs a separate reviewed
    # mapping. Never infer authority from authorizations or a shared channel.
    _routing_fields(value, route.workspace_id)
    if "authorizations" in value:
        authorizations = value["authorizations"]
        if type(authorizations) is not list or len(authorizations) != 1:
            raise Rejected("unsupported Slack authorizations")
        authorization = authorizations[0]
        if (
            type(authorization) is not dict
            or authorization.get("team_id") != route.workspace_id
        ):
            raise Rejected("unsupported Slack authorizations")
        _routing_fields(authorization, route.workspace_id)
    event_id = _string(value.get("event_id"), 64)
    if not re.fullmatch(r"Ev[A-Za-z0-9]{1,62}", event_id):
        raise Rejected("Slack event identifier")
    event = value.get("event")
    if type(event) is not dict or event.get("type") not in kinds:
        raise Rejected("unsupported Slack event")
    return event_id, event


def _normalize(value: dict[str, Any], route: Route) -> bytes:
    event_id, event = _callback(value, route)
    # Do not reinterpret edits, deletions, bot output, structured content or
    # historical/replayed message objects as an ordinary new user request.
    forbidden = {
        "subtype",
        "bot_id",
        "bot_profile",
        "app_id",
        "hidden",
        "edited",
        "deleted_ts",
        "previous_message",
        "message",
        "attachments",
        "files",
        "blocks",
        "metadata",
    }
    if forbidden.intersection(event):
        raise Rejected("unsupported Slack message")
    if event.get("user") != route.actor_id or event.get("channel") != route.channel_id:
        raise Rejected("Slack actor or channel binding")
    _routing_fields(event, route.workspace_id)
    stamp = _ts(event.get("ts"))
    thread = _ts(event.get("thread_ts", stamp))
    if thread != route.thread_ts:
        raise Rejected("Slack thread binding")
    text = _string(event.get("text"), 65536)
    return canonical(
        {
            "version": "runspindle.tether.ingress.v1",
            "event_id": event_id,
            "message_id": stamp,
            "actor_id": route.actor_id,
            "workspace_id": route.workspace_id,
            "channel_id": route.channel_id,
            "thread_id": thread,
            "revision": 1,
            "kind": "create",
            "text": text,
            "mirrored": False,
        }
    )


class SlackMessageVerifier:
    """Raw-body authentication followed by mandatory independent authority.

    Clock returns integer Unix seconds; no wall-clock fallback exists. The
    caller owns secret storage/rotation, HTTP framing and single-threaded use.
    """

    def __init__(
        self,
        signing_secret: bytes,
        route: Route,
        clock: Callable[[], int],
        max_skew_seconds: int = MAX_SKEW_SECONDS,
    ) -> None:
        if type(signing_secret) is not bytes or not 1 <= len(signing_secret) <= 4096:
            raise Rejected("Slack signing configuration")
        if (
            type(route) is not Route
            or not callable(clock)
            or (
                type(max_skew_seconds) is not int
                or not 0 <= max_skew_seconds <= MAX_SKEW_SECONDS
            )
        ):
            raise Rejected("Slack ingress configuration")
        route.validate()
        self._secret = signing_secret
        self._route = route
        self._clock = clock
        self._max_skew = max_skew_seconds

    def verify_callback(
        self,
        raw: bytes,
        headers: tuple[tuple[str, str], ...],
        *,
        reaction: bool = False,
    ) -> dict[str, Any]:
        """Verify raw signature and installation before returning a callback."""
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
            raise Rejected("Slack body bounds")
        fields = _headers(headers, len(raw))
        now = None
        try:
            now = self._clock()
        except Exception:
            pass
        if type(now) is not int or not 0 <= now <= 2**63 - 1:
            raise Rejected("Slack verification clock unavailable")
        timestamp = fields["x-slack-request-timestamp"]
        if abs(now - int(timestamp)) > self._max_skew:
            raise Rejected("Slack request outside time window")
        expected = (
            "v0="
            + hmac.new(
                self._secret,
                b"v0:" + timestamp.encode("ascii") + b":" + raw,
                hashlib.sha256,
            ).hexdigest()
        )
        if not hmac.compare_digest(expected, fields["x-slack-signature"]):
            raise Rejected("Slack signature mismatch")
        value = None
        try:
            value = _json(raw)
            _callback(
                value,
                self._route,
                ("reaction_added", "reaction_removed") if reaction else ("message",),
            )
        except ValueError:
            value = None
        if value is None:
            raise Rejected("unsupported Slack event")
        return value

    def verify(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> bytes:
        """Return a verified ordinary message; mutations remain a separate API."""
        value = self.verify_callback(raw, headers)
        normalized = None
        try:
            normalized = _normalize(value, self._route)
        except ValueError:
            pass
        if normalized is None:
            raise Rejected("unsupported Slack event")
        return normalized


class SignedSlackIngress(SlackMessageVerifier):
    """Verified ordinary Slack requests with separate durable task authority."""

    def __init__(
        self,
        path: str,
        signing_secret: bytes,
        route: Route,
        clock: Callable[[], int],
        authorize: Callable[[Identity, str], Grant | None] | None = None,
        sanitizer: Sanitizer | None = None,
        max_skew_seconds: int = MAX_SKEW_SECONDS,
    ) -> None:
        super().__init__(signing_secret, route, clock, max_skew_seconds)
        self._owner = object()
        self.admission = Admission(path, self._authenticate, authorize, sanitizer)

    def close(self) -> None:
        self.admission.close()

    def _authenticate(self, raw: bytes, proof: object) -> Identity | None:
        if (
            type(proof) is _Proof
            and proof.owner is self._owner
            and (proof.normalized_sha256 == hashlib.sha256(raw).hexdigest())
        ):
            return proof.identity
        return None

    def ingest(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> str:
        normalized = self.verify(raw, headers)
        proof = _Proof(
            self._owner, hashlib.sha256(normalized).hexdigest(), self._route.identity
        )
        return self.admission.ingest(normalized, proof)
