"""Explicit same-author Slack edits, ordered by retained provider versions.

Only this opt-in store lane accepts edits. Deletions have no authenticated deleter
in the supported event schema and remain denied. No server or issuer is supplied.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tether.admission import Admission, Grant, Identity, Rejected, canonical
from tether.intent import decode_intent, digest, expected_task_id
from tether.sanitization import Sanitizer
from tether.semantic_journal import JOURNAL_SCHEMA, IntentReferences, SemanticAdmission
from tether.slack_ingress import (
    MAX_SKEW_SECONDS,
    Route,
    SlackMessageVerifier,
    _callback,
    _normalize,
    _routing_fields,
)
from tether.slack_wire import _string, _ts

REVISION_SCHEMA = (
    JOURNAL_SCHEMA
    + """
CREATE TABLE slack_versions (
    scope TEXT PRIMARY KEY, task TEXT NOT NULL UNIQUE, revision TEXT NOT NULL,
    version_ts TEXT NOT NULL, content_sha256 TEXT NOT NULL);
CREATE TABLE slack_events (
    event TEXT PRIMARY KEY, scope TEXT NOT NULL, task TEXT NOT NULL, revision TEXT NOT NULL,
    callback_sha256 TEXT NOT NULL, normalized_sha256 TEXT NOT NULL,
    version_ts TEXT NOT NULL, previous_version_ts TEXT, previous_content_sha256 TEXT);
"""
)


def _version(value: object) -> str:
    text = _ts(value)
    seconds, _ = text.split(".")
    if str(int(seconds)) != seconds:
        raise Rejected("noncanonical Slack version")
    return text


def _order(value: str) -> int:
    seconds, micros = value.split(".")
    return int(seconds) * 1_000_000 + int(micros)


FORBIDDEN_MESSAGE = {
    "subtype",
    "bot_id",
    "bot_profile",
    "app_id",
    "hidden",
    "deleted_ts",
    "previous_message",
    "message",
    "attachments",
    "files",
    "blocks",
    "metadata",
    "app_context",
}


def _message(value: object, route: Route, require_editor: bool) -> tuple[str, str, str]:
    if (
        type(value) is not dict
        or value.get("type") != "message"
        or FORBIDDEN_MESSAGE.intersection(value)
    ):
        raise Rejected("unsupported edited message shape")
    if value.get("user") != route.actor_id:
        raise Rejected("edited message author")
    _routing_fields(value, route.workspace_id)
    if "channel" in value and value["channel"] != route.channel_id:
        raise Rejected("edited message channel")
    stamp = _version(value.get("ts"))
    if _version(value.get("thread_ts", stamp)) != route.thread_ts:
        raise Rejected("edited message thread")
    text = _string(value.get("text"), 65536)
    edited = value.get("edited")
    if "edited" not in value and not require_editor:
        return stamp, text, stamp
    if type(edited) is not dict or set(edited) != {"user", "ts"}:
        raise Rejected("missing explicit editor")
    # message.user is NOT a substitute for the editor's explicit identity.
    if edited["user"] != route.actor_id:
        raise Rejected("explicit editor mismatch")
    version = _version(edited["ts"])
    if _order(version) <= _order(stamp):
        raise Rejected("edited version precedes creation")
    return stamp, text, version


@dataclass(frozen=True)
class _Observation:
    event_id: str
    message_id: str
    text: str
    kind: str
    version: str
    previous_version: str | None
    previous_content: str | None


def _observe(value: dict[str, Any], route: Route) -> _Observation:
    event_id, event = _callback(value, route)
    if "subtype" not in event:
        normalized = json.loads(_normalize(value, route))
        stamp = _version(normalized["message_id"])
        return _Observation(
            event_id, stamp, normalized["text"], "create", stamp, None, None
        )
    if event.get("subtype") != "message_changed" or event.get("hidden") is not True:
        raise Rejected("unsupported Slack mutation")
    if event.get("channel") != route.channel_id:
        raise Rejected("edited event channel")
    if {
        "user",
        "text",
        "thread_ts",
        "edited",
        "deleted_ts",
        "bot_id",
        "app_id",
        "blocks",
        "files",
        "attachments",
        "metadata",
    }.intersection(event):
        raise Rejected("ambiguous edit wrapper")
    _routing_fields(event, route.workspace_id)
    # Wrapper timestamps concern delivery; never use them as provider versions.
    for key in ("ts", "event_ts"):
        if key in event:
            _version(event[key])
    current = _message(event.get("message"), route, True)
    previous = _message(event.get("previous_message"), route, False)
    if current[0] != previous[0] or _order(current[2]) <= _order(previous[2]):
        raise Rejected("edited identity or order")
    return _Observation(
        event_id,
        current[0],
        current[1],
        "edit",
        current[2],
        previous[2],
        digest(previous[1].encode()),
    )


@dataclass(frozen=True)
class _RevisionProof:
    owner: object = field(repr=False)
    normalized_sha256: str
    callback_sha256: str
    scope: str
    task: str
    revision: int
    version: str
    previous_version: str | None
    previous_content: str | None
    content_sha256: str


class _RevisionStore(SemanticAdmission):
    STORE_SCHEMA = REVISION_SCHEMA
    STORE_FAMILY = 1413545988

    def __init__(
        self,
        path: str,
        *,
        route: Route,
        account_id: str,
        owner: object,
        authorize: Callable[[Identity, str], Grant | None] | None,
        references: Callable[[dict[str, Any]], IntentReferences | None] | None,
        sanitizer: Sanitizer | None,
    ) -> None:
        self._route, self._owner = route, owner
        self._pending: _RevisionProof | None = None
        super().__init__(
            path,
            app_id=route.app_id,
            account_id=account_id,
            references=references,
            authenticate=self._authenticate,
            authorize=authorize,
            sanitizer=sanitizer,
        )

    def _authenticate(self, raw: bytes, proof: object) -> Identity | None:
        if (
            type(proof) is _RevisionProof
            and proof.owner is self._owner
            and proof.normalized_sha256 == digest(raw)
        ):
            return self._route.identity
        return None

    def _provider_head(self, scope: str) -> list[tuple[Any, ...]]:
        rows = self.db.execute(
            "SELECT task,revision,version_ts,content_sha256 FROM slack_versions WHERE scope=?",
            (scope,),
        ).fetchall()
        if not rows:
            return rows
        if len(rows) != 1:
            raise Rejected("ambiguous Slack provider head")
        task, revision, version, content = rows[0]
        candidates = self.db.execute(
            "SELECT wire,wire_sha256,raw_sha256 FROM intent_candidates WHERE task=? AND revision=?",
            (task, revision),
        ).fetchall()
        if (
            len(candidates) != 1
            or digest(candidates[0][0].encode()) != candidates[0][1]
        ):
            raise Rejected("Slack provider candidate missing")
        intent = decode_intent(candidates[0][0].encode())
        event_id = intent["event"]["event_id"]
        records = self.db.execute(
            "SELECT scope,task,revision,normalized_sha256,version_ts FROM slack_events WHERE event=?",
            (event_id,),
        ).fetchall()
        if (
            records != [(scope, task, revision, candidates[0][2], version)]
            or intent["event"]["content_sha256"] != content
        ):
            raise Rejected("Slack provider head integrity")
        return rows

    def prepare(
        self, observation: _Observation, callback_sha256: str
    ) -> tuple[bytes, _RevisionProof]:
        if self._pending is not None or self.db.in_transaction:
            raise Rejected("reentrant signed revision")
        source = dict(
            app_id=self.app_id,
            account_id=self.account_id,
            actor_id=self._route.actor_id,
            workspace_id=self._route.workspace_id,
            channel_id=self._route.channel_id,
            thread_id=self._route.thread_ts,
            message_id=observation.message_id,
        )
        task = expected_task_id(source)
        normalized = dict(
            version="runspindle.tether.ingress.v1",
            event_id=observation.event_id,
            message_id=observation.message_id,
            actor_id=source["actor_id"],
            workspace_id=source["workspace_id"],
            channel_id=source["channel_id"],
            thread_id=source["thread_id"],
            revision=1,
            kind=observation.kind,
            text=observation.text,
            mirrored=False,
        )
        scope = Admission.scope(normalized)
        known = self.db.execute(
            "SELECT scope,task,revision,callback_sha256 FROM slack_events WHERE event=?",
            (observation.event_id,),
        ).fetchall()
        if known:
            if (
                len(known) != 1
                or known[0][0] != scope
                or known[0][1] != task
                or known[0][3] != callback_sha256
            ):
                raise Rejected("Slack callback identity conflict")
            revision = int(known[0][2])
        elif observation.kind == "create":
            revision = 1
        else:
            head = self._provider_head(scope)
            if (
                len(head) != 1
                or head[0][0] != task
                or head[0][2:]
                != (observation.previous_version, observation.previous_content)
            ):
                raise Rejected("missing or stale Slack predecessor")
            revision = int(head[0][1]) + 1
        normalized["revision"] = revision
        raw: bytes = canonical(normalized)
        proof = _RevisionProof(
            self._owner,
            digest(raw),
            callback_sha256,
            scope,
            task,
            revision,
            observation.version,
            observation.previous_version,
            observation.previous_content,
            digest(observation.text.encode()),
        )
        return raw, proof

    def ingest(self, raw: bytes, proof: object) -> str:
        if self._pending is not None or self._authenticate(raw, proof) is None:
            raise Rejected("signed revision proof required")
        if not isinstance(proof, _RevisionProof):
            raise Rejected("signed revision proof required")
        self._pending = proof
        try:
            return super().ingest(raw, proof)
        finally:
            self._pending = None

    def _retained_extension(
        self, raw: bytes, envelope: dict[str, Any], duplicate: bool
    ) -> None:
        proof = self._pending
        if (
            proof is None
            or proof.normalized_sha256 != digest(raw)
            or envelope["binding"]["task_id"] != proof.task
            or envelope["binding"]["revision"] != proof.revision
        ):
            raise Rejected("signed revision transaction proof")
        row = (
            proof.scope,
            proof.task,
            str(proof.revision),
            proof.callback_sha256,
            proof.normalized_sha256,
            proof.version,
            proof.previous_version,
            proof.previous_content,
        )
        known = self.db.execute(
            "SELECT scope,task,revision,callback_sha256,normalized_sha256,version_ts,previous_version_ts,previous_content_sha256 FROM slack_events WHERE event=?",
            (envelope["message_id"],),
        ).fetchall()
        if duplicate:
            if known != [row]:
                raise Rejected("Slack replay proof mismatch")
            super()._retained_extension(raw, envelope, True)
            return
        if known:
            raise Rejected("Slack event already retained")
        head = self._provider_head(proof.scope)
        expected = (
            []
            if proof.revision == 1
            else [
                (
                    proof.task,
                    str(proof.revision - 1),
                    proof.previous_version,
                    proof.previous_content,
                )
            ]
        )
        if head != expected:
            raise Rejected("Slack predecessor changed under lock")
        super()._retained_extension(raw, envelope, False)
        self.db.execute(
            "INSERT INTO slack_events VALUES (?,?,?,?,?,?,?,?,?)",
            (envelope["message_id"], *row),
        )
        self.db.execute(
            "INSERT OR REPLACE INTO slack_versions VALUES (?,?,?,?,?)",
            (
                proof.scope,
                proof.task,
                str(proof.revision),
                proof.version,
                proof.content_sha256,
            ),
        )


class SignedRevisionIngress(SlackMessageVerifier):
    """New opt-in signed own-message edits; old create-only APIs stay unchanged."""

    def __init__(
        self,
        path: str,
        signing_secret: bytes,
        route: Route,
        clock: Callable[[], int],
        *,
        account_id: str,
        references: Callable[[dict[str, Any]], IntentReferences | None] | None = None,
        authorize: Callable[[Identity, str], Grant | None] | None = None,
        sanitizer: Sanitizer | None = None,
        max_skew_seconds: int = MAX_SKEW_SECONDS,
    ) -> None:
        super().__init__(signing_secret, route, clock, max_skew_seconds)
        _version(route.thread_ts)
        self._owner = object()
        self.admission = _RevisionStore(
            path,
            route=route,
            account_id=account_id,
            owner=self._owner,
            references=references,
            authorize=authorize,
            sanitizer=sanitizer,
        )

    def close(self) -> None:
        self.admission.close()

    def ingest(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> str:
        value = self.verify_callback(raw, headers)
        observation = None
        try:
            observation = _observe(value, self._route)
        except ValueError:
            pass
        if observation is None:
            raise Rejected("unsupported signed revision")
        normalized, proof = self.admission.prepare(observation, digest(raw))
        return self.admission.ingest(normalized, proof)
