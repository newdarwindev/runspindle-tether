"""Bounded event-projection sanitization, not universal secret discovery."""

import base64
import html
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, quote_plus, unquote, urlsplit, urlunsplit

if TYPE_CHECKING:
    from tether.testing import Payload


class UnsafeProjection(ValueError):
    """Fixed error message only; never include source content."""


@dataclass(frozen=True)
class Limits:
    depth: int = 12
    nodes: int = 2048
    input_bytes: int = 262144
    string_chars: int = 2048


SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "private_key",
        "hidden_reasoning",
        "chain_of_thought",
        "client_secret",
        "secret_key",
        "session_token",
        "set_cookie",
        "proxy_authorization",
        "x_api_key",
        "x_auth_token",
        "x_access_token",
    }
)


def _field_name(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


SENSITIVE_NAMES = frozenset(_field_name(key) for key in SENSITIVE_KEYS)
HEADER_FIELDS = frozenset(
    {"headers", "httpheaders", "requestheaders", "responseheaders", "trailers"}
)
URL_KEYS = frozenset({"url", "uri", "href"})
FIELDS = frozenset(
    {
        "version",
        "kind",
        "message",
        "arguments",
        "result",
        "error",
        "url",
        "attachments",
        "capabilities",
    }
)


def _quoted_expression(value: str) -> str:
    """Match hex case only inside generated URL escapes, never ordinary letters.

    Character classes avoid enumerating exponentially many mixed-case spellings.
    The input is a bounded, escaped configured-secret variant, never caller regex.
    """

    def escape(match: re.Match[str]) -> str:
        return "%" + "".join(
            "[" + char.lower() + char.upper() + "]" if char.isalpha() else char
            for char in match.group(0)[1:]
        )

    return re.sub(r"%[0-9A-F]{2}", escape, re.escape(value))


class Sanitizer:
    def __init__(
        self, secrets: tuple[str, ...] = (), limits: Limits = Limits()
    ) -> None:
        if type(secrets) is not tuple or len(secrets) > 64:
            raise UnsafeProjection("invalid redaction configuration")
        if type(limits) is not Limits or any(
            type(v) is not int or v < 1
            for v in (
                limits.depth,
                limits.nodes,
                limits.input_bytes,
                limits.string_chars,
            )
        ):
            raise UnsafeProjection("invalid sanitization limits")
        if (
            limits.depth > 32
            or limits.nodes > 100000
            or limits.input_bytes > 1048576
            or limits.string_chars > 65536
        ):
            raise UnsafeProjection("sanitization limits exceed implementation bounds")
        variants: set[str] = set()
        quoted: set[str] = set()
        for secret in secrets:
            if type(secret) is not str or not secret or len(secret) > 4096:
                raise UnsafeProjection("invalid redaction configuration")
            encoded = None
            try:
                encoded = secret.encode("utf-8")
            except UnicodeError:
                pass
            if encoded is None or len(encoded) > 4096:
                raise UnsafeProjection("invalid redaction configuration")
            # Accepted artifact bytes are immutable: retain the exact configured
            # spelling as well as its normalized projection representation.
            for value in {secret, unicodedata.normalize("NFC", secret)}:
                quoted.update({quote(value, safe=""), quote_plus(value)})
                variants.update(
                    {
                        value,
                        quote(value, safe=""),
                        quote_plus(value),
                        base64.b64encode(value.encode()).decode(),
                        base64.urlsafe_b64encode(value.encode()).decode(),
                    }
                )
        self._secrets = tuple(sorted(variants, key=len, reverse=True))
        self._pattern = (
            re.compile(
                "|".join(
                    _quoted_expression(value) if value in quoted else re.escape(value)
                    for value in self._secrets
                )
            )
            if self._secrets
            else None
        )
        # UTF-8 literal patterns and ASCII percent-escape classes share exact
        # semantics with text projection. Immutable artifact bytes are rejected,
        # never decoded/replaced or rebound to a different accepted digest.
        self._byte_pattern = (
            re.compile(self._pattern.pattern.encode("utf-8"))
            if self._pattern is not None
            else None
        )
        self.limits = limits

    def _validate(self, value: object) -> None:
        seen: set[int] = set()
        nodes, size = 0, 0

        def walk(item: object, depth: int) -> None:
            nonlocal nodes, size
            nodes += 1
            if depth > self.limits.depth or nodes > self.limits.nodes:
                raise UnsafeProjection("projection complexity limit")
            if type(item) is str:
                if len(item) > self.limits.input_bytes:
                    raise UnsafeProjection("projection byte limit")
                encoded = None
                try:
                    encoded = item.encode("utf-8")
                except UnicodeError:
                    pass
                if encoded is None:
                    raise UnsafeProjection("invalid Unicode")
                size += len(encoded)
            elif item is None or type(item) is bool:
                size += 4
            elif type(item) is int:
                if not -(2**64) < item < 2**64:
                    raise UnsafeProjection("integer limit")
                size += 20
            elif type(item) is float:
                if not math.isfinite(item):
                    raise UnsafeProjection("nonfinite value")
                size += 32
            elif type(item) in (dict, list):
                identity = id(item)
                if identity in seen:
                    raise UnsafeProjection("cyclic projection")
                seen.add(identity)
                if type(item) is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise UnsafeProjection("invalid object key")
                        walk(key, depth + 1)
                        walk(child, depth + 1)
                elif type(item) is list:
                    for child in item:
                        walk(child, depth + 1)
                seen.remove(identity)
            else:
                raise UnsafeProjection("unsupported projection value")
            if size > self.limits.input_bytes:
                raise UnsafeProjection("projection byte limit")

        walk(value, 0)

    def _redact(self, text: str) -> str:
        text = unicodedata.normalize("NFC", text)
        # One substitution pass never reprocesses the inserted marker.
        return (
            self._pattern.sub("[redacted]", text) if self._pattern is not None else text
        )

    def _url(self, text: str) -> str:
        # Repeated URL decoding is bounded. Strip all userinfo/query/fragment;
        # retain only a redacted inert HTTP(S) origin/path, never another scheme.
        try:
            decoded = unquote(unquote(text, errors="strict"), errors="strict")
            value = urlsplit(decoded)
            if value.scheme.lower() not in ("https", "http") or not value.hostname:
                raise UnsafeProjection("unsupported URL")
            # hostname lowercases input and can erase exact known-secret matches.
            # Validate the parsed port, but redact the original authority spelling.
            _ = value.port
            host = value.netloc.rsplit("@", 1)[-1]
            if any(c.isspace() or ord(c) < 32 for c in host):
                raise UnsafeProjection("invalid URL")
            return self._redact(
                urlunsplit((value.scheme.lower(), host, value.path, "", ""))
            )
        except (ValueError, UnicodeError):
            pass
        raise UnsafeProjection("invalid URL")

    def _embedded_url(self, match: re.Match[str]) -> str:
        return self._url(match.group(0))

    def _string(self, text: str, url: bool = False) -> str:
        cleaned = (
            self._url(text)
            if url
            else self._redact(
                re.sub(
                    r"https?://[^\s<>\"']+",
                    self._embedded_url,
                    text,
                    flags=re.IGNORECASE,
                )
            )
        )
        if len(cleaned) > self.limits.string_chars:
            return cleaned[: self.limits.string_chars] + "[truncated]"
        return cleaned

    def _header_entry(self, entry: Any) -> Any:
        """Sanitize conventional header pairs and named header records."""
        if type(entry) is list and len(entry) == 2 and type(entry[0]) is str:
            name, value = entry
            return [
                self._string(name),
                "[redacted]"
                if _field_name(name) in SENSITIVE_NAMES
                else self._walk(value),
            ]
        if type(entry) is dict:
            fields = {_field_name(key): key for key in entry}
            name_key = fields.get("name", "")
            name = entry.get(name_key)
            value_key = fields.get("value") or fields.get("values")
            if (
                len(entry) == len(fields) == 2
                and type(name) is str
                and value_key is not None
                and value_key != name_key
            ):
                value = entry[value_key]
                return self._walk(
                    {
                        name_key: name,
                        value_key: "[redacted]"
                        if _field_name(name) in SENSITIVE_NAMES
                        else value,
                    }
                )
        raise UnsafeProjection("invalid header entry")

    def _walk(self, value: Any, key: str = "") -> Any:
        field = _field_name(key)
        if field in SENSITIVE_NAMES:
            return "[redacted]"
        if field in HEADER_FIELDS:
            if type(value) is list:
                return [self._header_entry(item) for item in value]
            if type(value) is dict and any(
                _field_name(key) == "name"
                and type(name) is str
                and _field_name(name) in SENSITIVE_NAMES
                for key, name in value.items()
            ):
                return self._header_entry(value)
            if value is not None and type(value) is not dict:
                raise UnsafeProjection("invalid header container")
        if type(value) is str:
            return self._string(value, key.lower() in URL_KEYS)
        if type(value) is list:
            return [self._walk(item) for item in value]
        if type(value) is dict:
            result: dict[str, Any] = {}
            for original, item in value.items():
                normalized = unicodedata.normalize("NFC", original)
                if (
                    self._redact(normalized) != normalized
                    or len(normalized) > 128
                    or normalized in result
                ):
                    raise UnsafeProjection("unsafe or colliding key")
                result[normalized] = self._walk(item, normalized)
            return result
        return value

    def _scan(self, value: object) -> None:
        serialized = json.dumps(value, ensure_ascii=False, allow_nan=False)
        if self._pattern is not None and self._pattern.search(serialized):
            raise UnsafeProjection("residual sensitive value")

    def normalize(self, value: object) -> Any:
        self._validate(value)
        result = self._walk(value)
        self._scan(result)
        return result

    def require_clean(self, value: object) -> None:
        """Reject immutable authority/identity data rather than rewriting it."""
        if self.normalize(value) != value:
            raise UnsafeProjection("immutable content requires prior sanitization")

    def require_payload(self, payload: "Payload") -> None:
        # Accepted artifact bytes cannot be rewritten without invalidating core's
        # accepted digest. Match configured secrets in bytes, reject, never mutate.
        payload.validate()
        self.require_clean(
            {
                "text": payload.text,
                "attachments": [
                    {"id": a.attachment_id, "filename": a.filename}
                    for a in payload.attachments
                ],
            }
        )
        for attachment in payload.attachments:
            if self._byte_pattern is not None and self._byte_pattern.search(
                attachment.content
            ):
                raise UnsafeProjection("artifact requires prior sanitization")

    def project(self, value: object) -> dict[str, Any]:
        self._validate(value)
        if (
            type(value) is not dict
            or not {"version", "kind"} <= set(value)
            or not set(value) <= FIELDS
        ):
            raise UnsafeProjection("projection fields")
        if value["version"] != "runspindle.projection.v1":
            raise UnsafeProjection("projection version")
        # Reuse the existing audited synthetic capability declarations, do not
        # infer live status or invent unsupported native event coverage.
        from tether.native_testing import KINDS, Availability, Mode, capabilities

        if type(value["kind"]) is not str or value["kind"] not in KINDS | {
            "snapshot",
            "input",
        }:
            raise UnsafeProjection("unsupported projection kind")
        if "capabilities" in value:
            matrix = value["capabilities"]
            if type(matrix) is not dict or set(matrix) != {
                "mode",
                "availability",
                "supported",
                "evidence_class",
                "control",
                "live_coverage",
            }:
                raise UnsafeProjection("capability fields")
            mode = None
            try:
                mode = Mode(matrix["mode"])
                Availability(matrix["availability"])
            except (ValueError, TypeError):
                mode = None
            if mode is None:
                raise UnsafeProjection("unsupported capability state")
            if (
                matrix
                != {
                    "mode": mode.value,
                    "availability": matrix["availability"],
                    "supported": sorted(capabilities(mode)),
                    "evidence_class": "synthetic",
                    "control": False,
                    "live_coverage": "not_run",
                }
                or type(matrix["control"]) is not bool
            ):
                raise UnsafeProjection("unqualified capability claim")
        if "attachments" in value:
            attachments = value["attachments"]
            if type(attachments) is not list or len(attachments) > 8:
                raise UnsafeProjection("attachment metadata limit")
            for attachment in attachments:
                if type(attachment) is not dict or not set(attachment) <= {
                    "filename",
                    "url",
                    "media_type",
                    "size",
                    "caption",
                }:
                    raise UnsafeProjection("attachment metadata fields")
                if "size" in attachment and (
                    type(attachment["size"]) is not int or attachment["size"] < 0
                ):
                    raise UnsafeProjection("attachment size")
                if any(
                    type(v) is not str for k, v in attachment.items() if k != "size"
                ):
                    raise UnsafeProjection("attachment metadata types")
        if any(k in value and type(value[k]) is not str for k in ("message", "url")):
            raise UnsafeProjection("projection text types")
        projected = dict(self.normalize(value))
        for key in ("version", "kind", "capabilities"):
            if projected.get(key) != value.get(key):
                raise UnsafeProjection("immutable projection metadata")
        return projected

    def render(self, value: object) -> str:
        projected = self.project(value)
        # An inert HTML fragment with no active links/markup. Consumers must not
        # unescape it or treat sanitized values as trusted HTML elsewhere.
        rendered = (
            "<pre>"
            + html.escape(
                json.dumps(projected, sort_keys=True, ensure_ascii=False), quote=True
            )
            + "</pre>"
        )
        if self._pattern is not None and self._pattern.search(rendered):
            raise UnsafeProjection("residual rendered sensitive value")
        return rendered
