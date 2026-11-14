"""Retained feedback evidence, never collection/training or execution authority."""

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from tether.admission import Identity, Rejected, canonical, counter, identifier, pairs
from tether.journal import ProviderJournal
from tether.schema import open_store
from tether.sanitization import Sanitizer
from tether.testing import Payload

MAX_EVENTS = 1000
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


SCHEMA = """
            CREATE TABLE IF NOT EXISTS feedback_revisions (
                identity TEXT, revision TEXT, digest TEXT NOT NULL, body BLOB NOT NULL,
                grant_ref TEXT NOT NULL, policy_revision TEXT NOT NULL,
                PRIMARY KEY(identity,revision));
            CREATE TABLE IF NOT EXISTS feedback_deliveries (
                namespace TEXT,event TEXT,identity TEXT NOT NULL,digest TEXT NOT NULL,
                PRIMARY KEY(namespace,event));
            CREATE TABLE IF NOT EXISTS feedback_heads (
                identity TEXT PRIMARY KEY,revision TEXT NOT NULL,binding BLOB NOT NULL,
                deleted INTEGER NOT NULL,conflict INTEGER NOT NULL DEFAULT 0,
                conflict_digest TEXT);
            CREATE TRIGGER IF NOT EXISTS feedback_immutable_update BEFORE UPDATE ON feedback_revisions
                BEGIN SELECT RAISE(ABORT,'immutable feedback revision'); END;
            CREATE TRIGGER IF NOT EXISTS feedback_immutable_delete BEFORE DELETE ON feedback_revisions
                BEGIN SELECT RAISE(ABORT,'retain feedback revision'); END;
        """


@dataclass(frozen=True)
class FeedbackGrant:
    """Trusted callback result permitting retention only, not wire credentials."""

    identity: Identity
    event_sha256: str
    target_sha256: str
    policy_revision: str
    grant_ref: str


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
        elif value["judgment"] not in ("positive", "negative", "correction"):
            raise Rejected("feedback judgment")
        elif value["judgment"] == "correction":
            if type(value["correction"]) is not str or not value["correction"]:
                raise Rejected("correction content")
        elif value["correction"] is not None:
            raise Rejected("unexpected correction")
        target = value["target"]
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
        if any(
            value[k] != target[k] for k in ("workspace_id", "channel_id", "thread_id")
        ):
            raise Rejected("feedback target destination")
        if canonical(value) != raw:
            raise Rejected("noncanonical feedback")
        return cast(dict[str, Any], value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Rejected("invalid feedback") from None


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
        self.authorize_retention = authorize_retention
        self.verify_target = verify_target
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.db: sqlite3.Connection = open_store(path, SCHEMA, 1413873665)

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
        try:
            identity = self.authenticate(raw, proof)
        except Exception:
            raise Rejected("feedback authentication unavailable") from None
        event = decode(raw)
        claimed = Identity(
            *(event[k] for k in ("actor_id", "workspace_id", "channel_id", "thread_id"))
        )
        if type(identity) is not Identity or identity != claimed:
            raise Rejected("feedback authentication failed")
        self.sanitizer.require_clean(event)
        event_sha = hashlib.sha256(raw).hexdigest()
        target_sha = hashlib.sha256(canonical(event["target"])).hexdigest()
        authorize = self.authorize_retention
        verify_target = self.verify_target

        def verify() -> FeedbackGrant:
            try:
                grant = authorize(identity, event_sha, target_sha)
                target_ok = verify_target(
                    delivery_raw, payload, json.loads(canonical(event["target"]))
                )
            except Exception:
                raise Rejected("feedback authority unavailable") from None
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
            old = self.db.execute(
                "SELECT identity,digest FROM feedback_deliveries WHERE namespace=? AND event=?",
                (event["namespace"], event["event_id"]),
            ).fetchone()
            head = self.db.execute(
                "SELECT revision,binding,deleted,conflict FROM feedback_heads WHERE identity=?",
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
                        "UPDATE feedback_heads SET conflict=1,conflict_digest=COALESCE(conflict_digest,?) WHERE identity=?",
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
                    "INSERT INTO feedback_heads VALUES(?,?,?, ?,0,NULL)",
                    (key, str(event["revision"]), binding, event["kind"] == "delete"),
                )
            else:
                self.db.execute(
                    "UPDATE feedback_heads SET revision=?,deleted=? WHERE identity=?",
                    (str(event["revision"]), event["kind"] == "delete", key),
                )
            self.db.execute("COMMIT")
            return "retained"
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
                "SELECT revision,deleted,conflict FROM feedback_heads WHERE identity=?",
                (key,),
            ).fetchone()
            if head is None:
                raise Rejected("feedback unavailable")
            rows = self.db.execute(
                "SELECT digest,body,grant_ref,policy_revision FROM feedback_revisions WHERE identity=? ORDER BY rowid",
                (key,),
            ).fetchall()
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
            "state": "conflicted" if head[2] else "deleted" if head[1] else "active",
            "transport_evidence": "historical_destination_confirmation",
            "core_acceptance": "not_established",
            "collection_allowed": False,
            "training_allowed": False,
        }
