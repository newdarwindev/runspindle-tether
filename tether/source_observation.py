"""Durable deny-only task-source observations; no admission or dispatch authority."""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from tether.admission import Admission, Rejected, canonical, identifier
from tether.sanitization import Sanitizer
from tether.schema import open_store
from tether.slack_ingress import Route, SlackMessageVerifier, _routing_fields
from tether.slack_wire import _id, _ts

MAX_RECORDS = 1000
SCHEMA = """
CREATE TABLE source_fences (
    source BLOB PRIMARY KEY, original BLOB NOT NULL,
    event_id TEXT NOT NULL, body_sha256 TEXT NOT NULL, cause TEXT NOT NULL);
CREATE TABLE source_events (
    namespace BLOB NOT NULL, event_id TEXT NOT NULL, body_sha256 TEXT NOT NULL,
    source BLOB NOT NULL, PRIMARY KEY(namespace,event_id));
CREATE TRIGGER source_fence_no_update BEFORE UPDATE ON source_fences
    BEGIN SELECT RAISE(ABORT,'immutable source fence'); END;
CREATE TRIGGER source_fence_no_delete BEFORE DELETE ON source_fences
    BEGIN SELECT RAISE(ABORT,'retain source fence'); END;
CREATE TRIGGER source_event_no_update BEFORE UPDATE ON source_events
    BEGIN SELECT RAISE(ABORT,'immutable source event'); END;
CREATE TRIGGER source_event_no_delete BEFORE DELETE ON source_events
    BEGIN SELECT RAISE(ABORT,'retain source event'); END;
"""


@dataclass(frozen=True)
class SourceKey:
    app_id: str
    workspace_id: str
    channel_id: str
    message_ts: str

    def validate(self) -> None:
        _id(self.app_id, "A")
        _id(self.workspace_id, "T")
        _id(self.channel_id, "CGD")
        _ts(self.message_ts)

    def encoded(self) -> bytes:
        self.validate()
        return canonical(asdict(self))


@dataclass(frozen=True)
class RetainedSource:
    """Historical original attribution, NEVER the editor/deleter's identity."""

    source: SourceKey
    task_id: str
    original_actor_id: str
    original_thread_ts: str
    original_intent_sha256: str

    def encoded(self) -> bytes:
        if type(self.source) is not SourceKey:
            raise Rejected("source binding type")
        self.source.validate()
        identifier(self.task_id)
        _id(self.original_actor_id, "UW")
        _ts(self.original_thread_ts)
        if type(self.original_intent_sha256) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", self.original_intent_sha256
        ):
            raise Rejected("original intent digest")
        return canonical(asdict(self))


@dataclass(frozen=True)
class SourceObservation:
    source: SourceKey
    event_id: str
    body_sha256: str
    cause: str

    def validate(self) -> None:
        if type(self.source) is not SourceKey:
            raise Rejected("source observation type")
        self.source.validate()
        if (
            type(self.event_id) is not str
            or not re.fullmatch(r"Ev[A-Za-z0-9]{1,62}", self.event_id)
            or type(self.body_sha256) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", self.body_sha256)
            or type(self.cause) is not str
            or self.cause not in ("message_changed", "message_deleted")
        ):
            raise Rejected("source observation shape")


def decision(observation: SourceObservation, original: RetainedSource) -> bytes:
    if (
        type(observation) is not SourceObservation
        or type(original) is not RetainedSource
    ):
        raise Rejected("source decision type")
    observation.validate()
    original.encoded()
    if observation.source != original.source:
        raise Rejected("source decision binding")
    return canonical(
        {
            "version": "runspindle.tether.source-observation.v1",
            "effect_scope": "retain_deny_only_source_fence",
            "observation": asdict(observation),
            "original": asdict(original),
        }
    )


class SourceObservationStore:
    """New separate SQLite family. Unknown is never positive eligibility.

    Trusted bounded callbacks are separate from provider proof. No existing
    Admission database schema, revision, grant or Core dispatch state is changed.
    """

    def __init__(
        self,
        path: str,
        resolve_original: Callable[[SourceKey], RetainedSource | None],
        authenticate: Callable[[bytes, object], bool] | None = None,
        authorize: Callable[[dict[str, Any]], bool] | None = None,
        sanitizer: Sanitizer | None = None,
    ) -> None:
        if (
            type(path) is not str
            or not path
            or path == ":memory:"
            or path.lower().startswith("file:")
        ):
            raise Rejected("source store requires a file path")
        self.resolve_original = resolve_original
        self.authenticate = authenticate
        self.authorize = authorize
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.db = open_store(path, SCHEMA, 1414743631)

    def close(self) -> None:
        self.db.close()

    def _allowed(self, raw: bytes) -> bool:
        try:
            request = json.loads(raw)
            allowed = self.authorize is not None and self.authorize(request) is True
            return allowed and canonical(request) == raw
        except Exception:
            return False

    def _original_matches(self, source: SourceKey, encoded: bytes) -> bool:
        try:
            original = self.resolve_original(source)
            return type(original) is RetainedSource and original.encoded() == encoded
        except Exception:
            return False

    def record(
        self, observation: SourceObservation, original: RetainedSource, proof: object
    ) -> str:
        raw = decision(observation, original)
        self.sanitizer.require_clean(json.loads(raw))
        authenticated = False
        try:
            authenticated = (
                self.authenticate is not None and self.authenticate(raw, proof) is True
            )
        except Exception:
            pass
        if not authenticated or not self._allowed(raw):
            raise Rejected("source observation not authorized")
        # Capture exact immutable bytes before callbacks/lock acquisition.
        source = observation.source.encoded()
        retained = original.encoded()
        if raw != decision(observation, original) or not self._original_matches(
            observation.source, retained
        ):
            raise Rejected("source original unavailable")
        namespace = canonical(
            [
                observation.source.app_id,
                observation.source.workspace_id,
                observation.source.channel_id,
            ]
        )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if (
                not self._allowed(raw)
                or not self._original_matches(observation.source, retained)
                or raw != decision(observation, original)
            ):
                raise Rejected("source authority or original changed")
            fence = self.db.execute(
                "SELECT original FROM source_fences WHERE source=?", (source,)
            ).fetchone()
            if fence is not None and fence[0] != retained:
                raise Rejected("source historical binding conflict")
            prior = self.db.execute(
                "SELECT body_sha256,source FROM source_events WHERE namespace=? AND event_id=?",
                (namespace, observation.event_id),
            ).fetchone()
            if prior is not None:
                if fence is None or prior != (observation.body_sha256, source):
                    raise Rejected("source event conflict")
                self.db.rollback()
                return "duplicate"
            if self.db.execute("SELECT count(*) FROM source_events").fetchone()[
                0
            ] >= MAX_RECORDS or (
                fence is None
                and self.db.execute("SELECT count(*) FROM source_fences").fetchone()[0]
                >= MAX_RECORDS
            ):
                raise Rejected("source observation capacity")
            if fence is None:
                self.db.execute(
                    "INSERT INTO source_fences VALUES (?,?,?,?,?)",
                    (
                        source,
                        retained,
                        observation.event_id,
                        observation.body_sha256,
                        observation.cause,
                    ),
                )
            self.db.execute(
                "INSERT INTO source_events VALUES (?,?,?,?)",
                (namespace, observation.event_id, observation.body_sha256, source),
            )
            self.db.commit()
            return "fenced"
        except BaseException:
            self.db.rollback()
            raise

    def state(self, source: SourceKey) -> str:
        if type(source) is not SourceKey:
            raise Rejected("source key type")
        encoded = source.encoded()
        self.sanitizer.require_clean(asdict(source))
        found = self.db.execute(
            "SELECT 1 FROM source_fences WHERE source=?", (encoded,)
        ).fetchone()
        return "fenced" if found else "unknown"


@dataclass(frozen=True)
class _Proof:
    owner: object = field(repr=False)
    decision_sha256: str


class SignedSlackSourceObserver:
    """Signed negative facts for an already retained original task source only."""

    def __init__(
        self,
        path: str,
        verifier: SlackMessageVerifier,
        route: Route,
        admission: Admission,
        authorize: Callable[[dict[str, Any]], bool] | None = None,
        sanitizer: Sanitizer | None = None,
    ) -> None:
        if (
            type(verifier) is not SlackMessageVerifier
            or type(route) is not Route
            or type(admission) is not Admission
        ):
            raise Rejected("source observer configuration")
        route.validate()
        # Verifier is a trusted dependency but must bind the configured installation.
        if verifier._route != route:
            raise Rejected("source verifier route")
        self._verifier = verifier
        self._route = route
        self._admission = admission
        self._owner = object()
        self.store = SourceObservationStore(
            path, self._resolve, self._authenticate, authorize, sanitizer
        )

    def close(self) -> None:
        self.store.close()

    def _authenticate(self, raw: bytes, proof: object) -> bool:
        return (
            type(proof) is _Proof
            and proof.owner is self._owner
            and proof.decision_sha256 == hashlib.sha256(raw).hexdigest()
        )

    def _resolve(self, source: SourceKey) -> RetainedSource | None:
        route = self._route
        if (source.app_id, source.workspace_id, source.channel_id) != (
            route.app_id,
            route.workspace_id,
            route.channel_id,
        ):
            return None
        key = canonical(
            [route.workspace_id, route.channel_id, route.thread_ts, source.message_ts]
        ).decode()
        row = self._admission.db.execute(
            "SELECT s.task,r.scope,r.digest FROM sources s JOIN revisions r ON r.task=s.task AND r.revision='1' AND r.kind='create' WHERE s.scope=?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        expected = [
            route.workspace_id,
            route.channel_id,
            route.thread_ts,
            source.message_ts,
            route.actor_id,
        ]
        if row[1] != canonical(expected).decode():
            raise Rejected("source original identity mismatch")
        return RetainedSource(source, row[0], route.actor_id, route.thread_ts, row[2])

    def observe(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> str:
        value = self._verifier.verify_callback(raw, headers)
        event = value["event"]
        route = self._route
        if event.get("channel") != route.channel_id or event.get("hidden") is not True:
            raise Rejected("source event route or kind")
        _routing_fields(event, route.workspace_id)
        cause = event.get("subtype")
        hints = []
        if cause == "message_changed":
            message = event.get("message")
            if type(message) is not dict or message.get("type") != "message":
                raise Rejected("source changed message")
            stamp = _ts(message.get("ts"))
            if any(
                k in message for k in ("bot_id", "bot_profile", "app_id", "subtype")
            ):
                raise Rejected("source changed message type")
            hints.append(message)
            # Editor metadata never supplies authority or replaces original author.
            if "edited" in message:
                edited = message["edited"]
                if type(edited) is not dict or set(edited) != {"user", "ts"}:
                    raise Rejected("source editor hint")
                _id(edited["user"], "UW")
                _ts(edited["ts"])
        elif cause == "message_deleted":
            stamp = _ts(event.get("deleted_ts"))
        else:
            raise Rejected("unsupported source observation")
        if "user" in event:
            raise Rejected("unsupported source event actor")
        if "thread_ts" in event and event["thread_ts"] != route.thread_ts:
            raise Rejected("source thread hint")
        if "previous_message" in event:
            previous = event["previous_message"]
            if type(previous) is not dict or previous.get("ts") != stamp:
                raise Rejected("source previous identity")
            hints.append(previous)
        for hint in hints:
            _routing_fields(hint, route.workspace_id)
            if (
                hint.get("channel", route.channel_id) != route.channel_id
                or hint.get("user", route.actor_id) != route.actor_id
                or hint.get("thread_ts", route.thread_ts) != route.thread_ts
            ):
                raise Rejected("source identity hint")
        source = SourceKey(route.app_id, route.workspace_id, route.channel_id, stamp)
        original = self._resolve(source)
        if original is None:
            raise Rejected("source original not retained")
        observation = SourceObservation(
            source, value["event_id"], hashlib.sha256(raw).hexdigest(), cause
        )
        encoded = decision(observation, original)
        proof = _Proof(self._owner, hashlib.sha256(encoded).hexdigest())
        return self.store.record(observation, original, proof)
