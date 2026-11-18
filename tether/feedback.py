"""Retained feedback evidence, never collection/training or execution authority."""

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from tether.admission import Identity, Rejected, canonical, counter, identifier, pairs
from tether.feedback_schema import SCHEMA as SCHEMA
from tether.feedback_schema import open_feedback_store, state
from tether.journal import ProviderJournal
from tether.sanitization import Sanitizer
from tether.testing import Payload

MAX_EVENTS = 1000
MAX_INVALIDATIONS = 1000
MAX_BYTES = 262144
TARGET_FIELDS = {
    "task_id",
    "task_revision",
    "artifact_id",
    "artifact_revision",
    "artifact_sha256",
    "delivery_operation_id",
    "message_id",
    "payload_sha256",
    "workspace_id",
    "channel_id",
    "thread_id",
}
FIELDS = {
    "version",
    "namespace",
    "event_id",
    "feedback_id",
    "revision",
    "predecessor",
    "actor_id",
    "workspace_id",
    "channel_id",
    "thread_id",
    "kind",
    "judgment",
    "correction",
    "target",
}


@dataclass(frozen=True)
class FeedbackGrant:
    """Trusted callback result permitting retention only, not wire credentials."""

    identity: Identity
    event_sha256: str
    target_sha256: str
    policy_revision: str
    grant_ref: str


def validate_target(target: Any) -> None:
    if type(target) is not dict or set(target) != TARGET_FIELDS:
        raise Rejected("target fields")
    for key, item in target.items():
        if key in {"task_revision", "artifact_revision"}:
            counter(item)
        elif key.endswith("sha256"):
            if type(item) is not str or re.fullmatch("[0-9a-f]{64}", item) is None:
                raise Rejected("target digest")
        else:
            identifier(item)


def decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise Rejected("feedback size or encoding")
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        if (
            type(value) is not dict
            or set(value) != FIELDS
            or value["version"] != "runspindle.tether.feedback.v1"
        ):
            raise Rejected("feedback fields")
        for key in (
            "namespace",
            "event_id",
            "feedback_id",
            "actor_id",
            "workspace_id",
            "channel_id",
            "thread_id",
        ):
            identifier(value[key])
        counter(value["revision"])
        previous = value["predecessor"]
        if value["revision"] == 1:
            if previous is not None or value["kind"] != "create":
                raise Rejected("feedback initial revision")
        elif (
            type(previous) is not int
            or previous != value["revision"] - 1
            or value["kind"] not in ("edit", "delete")
        ):
            raise Rejected("feedback predecessor")
        if value["kind"] == "delete":
            if value["judgment"] is not None or value["correction"] is not None:
                raise Rejected("delete content")
        elif value["judgment"] not in (
            "positive",
            "negative",
            "correction",
            "thumbs_up",
        ):
            raise Rejected("feedback judgment")
        elif value["judgment"] == "correction":
            if type(value["correction"]) is not str or not value["correction"]:
                raise Rejected("correction content")
        elif value["correction"] is not None:
            raise Rejected("unexpected correction")
        target = value["target"]
        validate_target(target)
        if any(
            value[k] != target[k] for k in ("workspace_id", "channel_id", "thread_id")
        ):
            raise Rejected("feedback target destination")
        if canonical(value) != raw:
            raise Rejected("noncanonical feedback")
        return cast(dict[str, Any], value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    raise Rejected("invalid feedback")


def decode_invalidation(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        raise Rejected("invalidation bounds")
    try:
        v = json.loads(raw, object_pairs_hook=pairs)
        fields = {
            "version",
            "namespace",
            "app_id",
            "workspace_id",
            "channel_id",
            "feedback_id",
            "event_id",
            "body_sha256",
            "cause",
            "author_hint",
            "thread_hint",
            "target",
        }
        if (
            type(v) is not dict
            or set(v) != fields
            or v["version"] != "runspindle.tether.provider-invalidation.v1"
        ):
            raise ValueError()
        for name in (
            "namespace",
            "app_id",
            "workspace_id",
            "channel_id",
            "feedback_id",
            "event_id",
        ):
            identifier(v[name])
        for name in ("author_hint", "thread_hint"):
            if v[name] is not None:
                identifier(v[name])
        if (
            v["cause"] not in ("message_changed", "message_deleted", "reaction_removed")
            or type(v["body_sha256"]) is not str
            or re.fullmatch("[0-9a-f]{64}", v["body_sha256"]) is None
        ):
            raise ValueError()
        expected_namespace = (
            "slack:"
            + hashlib.sha256(
                canonical([v["app_id"], v["workspace_id"], v["channel_id"]])
            ).hexdigest()
        )
        validate_target(v["target"])
        if v["namespace"] != expected_namespace or any(
            v[k] != v["target"][k] for k in ("workspace_id", "channel_id")
        ):
            raise ValueError()
        if (
            v["thread_hint"] is not None
            and v["thread_hint"] != v["target"]["thread_id"]
        ):
            raise ValueError()
        if canonical(v) != raw:
            raise ValueError()
        return cast(dict[str, Any], v)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    raise Rejected("invalid provider invalidation")


class FeedbackStore:
    def __init__(
        self,
        path: str,
        journal: ProviderJournal,
        authenticate: Callable[[bytes, object], Identity | None] | None = None,
        authorize_retention: Callable[[Identity, str, str], FeedbackGrant | None]
        | None = None,
        verify_target: Callable[[bytes, Payload, dict[str, Any]], bool] | None = None,
        sanitizer: Sanitizer | None = None,
        *,
        authenticate_invalidation: Callable[[bytes, object], bool] | None = None,
        authorize_invalidation: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        if (
            type(path) is not str
            or not path
            or path == ":memory:"
            or path.startswith("file:")
        ):
            raise Rejected("durable feedback requires a filesystem path")
        self.journal = journal
        self.authenticate = authenticate
        self.authenticate_invalidation = authenticate_invalidation
        self.authorize_invalidation = authorize_invalidation
        self.authorize_retention = authorize_retention
        self.verify_target = verify_target
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.db: sqlite3.Connection = open_feedback_store(path)

    def close(self) -> None:
        self.db.close()

    def ingest(
        self, raw: bytes, proof: object, delivery_raw: bytes, payload: Payload
    ) -> str:
        if (
            self.authenticate is None
            or self.authorize_retention is None
            or self.verify_target is None
        ):
            raise Rejected("trusted feedback adapters unavailable")
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise Rejected("feedback size or encoding")
        identity = None
        unavailable = False
        try:
            identity = self.authenticate(raw, proof)
        except Exception:
            unavailable = True
        if unavailable:
            raise Rejected("feedback authentication unavailable")
        event = decode(raw)
        claimed = Identity(
            *(event[k] for k in ("actor_id", "workspace_id", "channel_id", "thread_id"))
        )
        if type(identity) is not Identity or identity != claimed:
            raise Rejected("feedback authentication failed")
        self.sanitizer.require_clean(event)
        if self.invalidated(event["namespace"], event["feedback_id"]):
            raise Rejected("feedback permanently invalidated")
        event_sha = hashlib.sha256(raw).hexdigest()
        target_sha = hashlib.sha256(canonical(event["target"])).hexdigest()
        authorize = self.authorize_retention
        verify_target = self.verify_target

        def verify() -> FeedbackGrant:
            if event["judgment"] == "thumbs_up" and self.invalidated(
                event["namespace"], event["target"]["message_id"]
            ):
                raise Rejected("reaction target permanently invalidated")
            grant = None
            target_ok = False
            unavailable = False
            try:
                grant = authorize(identity, event_sha, target_sha)
                target_ok = verify_target(
                    delivery_raw, payload, json.loads(canonical(event["target"]))
                )
            except Exception:
                unavailable = True
            if unavailable:
                raise Rejected("feedback authority unavailable")
            if (
                type(grant) is not FeedbackGrant
                or type(grant.identity) is not Identity
                or grant.identity != identity
                or grant.event_sha256 != event_sha
                or grant.target_sha256 != target_sha
                or target_ok is not True
            ):
                raise Rejected("feedback retention or target denied")
            identifier(grant.grant_ref)
            identifier(grant.policy_revision)
            self.sanitizer.require_clean([grant.grant_ref, grant.policy_revision])
            target = self.journal.retained_target(
                delivery_raw, payload, event["target"]["message_id"]
            )
            if canonical(target) != canonical(event["target"]):
                raise Rejected("retained target mismatch")
            return grant

        grant = verify()
        # Immutable feedback identity includes delivery namespace, not only caller ID.
        key = hashlib.sha256(
            canonical([event["namespace"], event["feedback_id"]])
        ).hexdigest()
        binding = canonical(
            [
                identity.actor_id,
                identity.workspace_id,
                identity.channel_id,
                identity.thread_id,
                event["target"],
            ]
        )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            grant = verify()  # Recheck revocable authority after waiting for the lock.
            if self.invalidated(event["namespace"], event["feedback_id"]):
                raise Rejected("feedback permanently invalidated")
            if self.db.execute(
                "SELECT 1 FROM feedback_invalidation_events WHERE namespace=? AND event=?",
                (event["namespace"], event["event_id"]),
            ).fetchone():
                raise Rejected("feedback provider event identity conflicted")
            old = self.db.execute(
                "SELECT identity,digest FROM feedback_deliveries WHERE namespace=? AND event=?",
                (event["namespace"], event["event_id"]),
            ).fetchone()
            head = self.db.execute(
                "SELECT revision,binding,deleted,conflict FROM feedback_heads_v2 WHERE identity=?",
                (key,),
            ).fetchone()
            revision = self.db.execute(
                "SELECT digest FROM feedback_revisions WHERE identity=? AND revision=?",
                (key, str(event["revision"])),
            ).fetchone()
            conflict = (
                (old is not None and old != (key, event_sha))
                or (revision is not None and revision[0] != event_sha)
                or (head is not None and head[1] != binding)
            )
            if conflict:
                # Fence already-retained identities BEFORE checking evidence capacity.
                # One bounded digest slot: conflict storms cannot allocate rows or undo fence.
                keys = {key} | ({old[0]} if old else set())
                for victim in keys:
                    self.db.execute(
                        "UPDATE feedback_heads_v2 SET conflict=1,conflict_digest=COALESCE(conflict_digest,?) WHERE identity=?",
                        (event_sha, victim),
                    )
                self.db.execute("COMMIT")
                return "conflict"
            if head is not None and head[3]:
                raise Rejected("feedback conflict retained")
            if old is not None:
                self.db.execute("ROLLBACK")
                return "duplicate"
            if head is None:
                if event["revision"] != 1:
                    raise Rejected("missing feedback predecessor")
            elif head[2] or int(head[0]) + 1 != event["revision"]:
                raise Rejected("stale or deleted feedback")
            if (
                self.db.execute("SELECT count(*) FROM feedback_revisions").fetchone()[0]
                >= MAX_EVENTS
            ):
                raise Rejected("feedback capacity")
            self.db.execute(
                "INSERT INTO feedback_revisions VALUES(?,?,?,?,?,?)",
                (
                    key,
                    str(event["revision"]),
                    event_sha,
                    raw,
                    grant.grant_ref,
                    grant.policy_revision,
                ),
            )
            self.db.execute(
                "INSERT INTO feedback_deliveries VALUES(?,?,?,?)",
                (event["namespace"], event["event_id"], key, event_sha),
            )
            if head is None:
                self.db.execute(
                    "INSERT INTO feedback_heads_v2 VALUES(?,?,?, ?,0,NULL)",
                    (key, str(event["revision"]), binding, event["kind"] == "delete"),
                )
            else:
                self.db.execute(
                    "UPDATE feedback_heads_v2 SET revision=?,deleted=? WHERE identity=?",
                    (str(event["revision"]), event["kind"] == "delete", key),
                )
            self.db.execute("COMMIT")
            return "retained"
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def invalidation(self, namespace: str, message: str) -> dict[str, Any] | None:
        blocked, digest = state(self.db)
        if blocked:
            return {"cause": "store_saturated", "body_sha256": digest}
        row = self.db.execute(
            "SELECT event,digest,cause FROM feedback_invalidations WHERE namespace=? AND message=?",
            (namespace, message),
        ).fetchone()
        return (
            None
            if row is None
            else {"event_id": row[0], "body_sha256": row[1], "cause": row[2]}
        )

    def invalidated(self, namespace: str, message: str) -> bool:
        return self.invalidation(namespace, message) is not None

    def invalidate(
        self, raw: bytes, proof: object, delivery_raw: bytes, payload: Payload
    ) -> str:
        """Provider observation only. Never fabricate an authored feedback revision."""
        authenticate, authorize = (
            self.authenticate_invalidation,
            self.authorize_invalidation,
        )
        if authenticate is None or authorize is None:
            raise Rejected("trusted invalidation adapters unavailable")
        authenticated = False
        try:
            authenticated = authenticate(raw, proof) is True
        except Exception:
            pass
        if not authenticated:
            raise Rejected("feedback invalidation authentication failed")
        observation = decode_invalidation(raw)
        # Only minimal identifiers/digest/cause and configured retained target are
        # normalized; changed text, previous-message text and editor are not kept.
        self.sanitizer.require_clean(observation)
        namespace, message, event, digest = (
            observation[k]
            for k in ("namespace", "feedback_id", "event_id", "body_sha256")
        )
        key = hashlib.sha256(canonical([namespace, message])).hexdigest()

        def verify() -> None:
            permitted = False
            try:
                decision = json.loads(raw)
                decision["effect_scope"] = "message_fence_or_storewide_saturation"
                permitted = authorize(decision) is True
            except Exception:
                pass
            if not permitted:
                raise Rejected("feedback invalidation authority denied")
            target = observation["target"]
            retained = self.journal.retained_target(
                delivery_raw, payload, target["message_id"]
            )
            if retained != target:
                raise Rejected("feedback invalidation target mismatch")
            original = self.db.execute(
                "SELECT body FROM feedback_revisions WHERE identity=? ORDER BY rowid LIMIT 1",
                (key,),
            ).fetchone()
            if original is not None:
                prior = decode(original[0])
                if prior["target"] != target or any(
                    observation[hint] is not None and observation[hint] != prior[field]
                    for hint, field in (
                        ("author_hint", "actor_id"),
                        ("thread_hint", "thread_id"),
                    )
                ):
                    raise Rejected("feedback invalidation binding mismatch")

        verify()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            verify()
            if state(self.db)[0]:
                self.db.execute("ROLLBACK")
                return "saturated"
            prior_event = self.db.execute(
                "SELECT message,digest FROM feedback_invalidation_events WHERE namespace=? AND event=?",
                (namespace, event),
            ).fetchone()
            prior_message = self.db.execute(
                "SELECT 1 FROM feedback_invalidations WHERE namespace=? AND message=?",
                (namespace, message),
            ).fetchone()
            # Capacity cannot silently drop a negative event then allow a late
            # create. Permanently deny the store instead; no automatic reset.
            if (
                prior_message is None
                and self.db.execute(
                    "SELECT count(*) FROM feedback_invalidations"
                ).fetchone()[0]
                >= MAX_INVALIDATIONS
            ) or (
                prior_event is None
                and self.db.execute(
                    "SELECT count(*) FROM feedback_invalidation_events"
                ).fetchone()[0]
                >= MAX_INVALIDATIONS
            ):
                self.db.execute(
                    "UPDATE feedback_invalidation_state SET blocked=1,digest=? WHERE singleton=1",
                    (digest,),
                )
                self.db.execute("COMMIT")
                return "saturated"
            create_event = self.db.execute(
                "SELECT identity,digest FROM feedback_deliveries WHERE namespace=? AND event=?",
                (namespace, event),
            ).fetchone()
            collision = (
                prior_event is not None and prior_event != (message, digest)
            ) or create_event is not None
            if create_event is not None:
                # Negative quarantine never retargets or rewrites another record.
                for victim in (key, create_event[0]):
                    self.db.execute(
                        "UPDATE feedback_heads_v2 SET conflict_digest=COALESCE(conflict_digest,?),conflict=1 WHERE identity=?",
                        (digest, victim),
                    )
            if prior_message is None:
                self.db.execute(
                    "INSERT INTO feedback_invalidations VALUES(?,?,?,?,?)",
                    (
                        namespace,
                        message,
                        event,
                        digest,
                        "identity_conflict" if collision else observation["cause"],
                    ),
                )
            if prior_event is None:
                self.db.execute(
                    "INSERT INTO feedback_invalidation_events VALUES(?,?,?,?)",
                    (namespace, event, message, digest),
                )
            self.db.execute("COMMIT")
            return (
                "conflict"
                if collision
                else "duplicate"
                if prior_event is not None
                else "invalidated"
            )
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def evidence(self, namespace: str, feedback_id: str) -> dict[str, Any]:
        """Read retained facts only; consumers must separately select and authorize use."""
        identifier(namespace)
        identifier(feedback_id)
        key = hashlib.sha256(canonical([namespace, feedback_id])).hexdigest()
        self.db.execute("BEGIN")
        try:
            head = self.db.execute(
                "SELECT revision,deleted,conflict FROM feedback_heads_v2 WHERE identity=?",
                (key,),
            ).fetchone()
            if head is None:
                raise Rejected("feedback unavailable")
            rows = self.db.execute(
                "SELECT digest,body,grant_ref,policy_revision FROM feedback_revisions WHERE identity=? ORDER BY rowid",
                (key,),
            ).fetchall()
            invalidation = self.invalidation(namespace, feedback_id)
            # Resolve target fences in the same read snapshot as reaction history.
            for sha, raw, _, _ in rows:
                if hashlib.sha256(raw).hexdigest() != sha:
                    raise Rejected("feedback integrity")
                retained = decode(raw)
                if retained["judgment"] == "thumbs_up":
                    invalidation = invalidation or self.invalidation(
                        namespace, retained["target"]["message_id"]
                    )
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        revisions = []
        for sha, raw, grant_ref, policy_revision in rows:
            if hashlib.sha256(raw).hexdigest() != sha:
                raise Rejected("feedback integrity")
            revisions.append(
                {
                    "event_sha256": sha,
                    "event": decode(raw),
                    "retention_grant_ref": grant_ref,
                    "retention_policy_revision": policy_revision,
                }
            )
        return {
            "version": "runspindle.tether.feedback-evidence.v1",
            "revisions": revisions,
            "head_revision": int(head[0]),
            "state": "invalidated"
            if invalidation
            else "conflicted"
            if head[2]
            else "deleted"
            if head[1]
            else "active",
            "provider_invalidation": invalidation,
            "transport_evidence": "historical_destination_confirmation",
            "core_acceptance": "not_established",
            "collection_allowed": False,
            "training_allowed": False,
        }
