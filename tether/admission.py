"""Authenticated ingress seam with durable revision history and local outbox.

Adapters are trusted application dependencies, never values from request JSON.
No default adapter exists. This module does not launch or deliver anything.
"""

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast


class Rejected(ValueError):
    """Input did not satisfy the ingress contract."""


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def identifier(value: object) -> None:
    if type(value) is not str or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value
    ):
        raise Rejected("identifier")


def counter(value: object) -> None:
    if type(value) is not int or not 1 <= value <= 2**64 - 1:
        raise Rejected("counter")


def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in rows:
        if key in result:
            raise Rejected("duplicate key")
        result[key] = value
    return result


@dataclass(frozen=True)
class Identity:
    actor_id: str
    workspace_id: str
    channel_id: str
    thread_id: str


@dataclass(frozen=True)
class Grant:
    """Trusted authority result for this exact event, not a wire credential.

    Resolver must check revocation, expiry and operation scope on every call.
    Its authenticated result binds both the event digest and exact envelope.
    """

    identity: Identity
    event_digest: str
    task_id: str
    revision: int
    operation_id: str
    policy_revision: str
    host_id: str
    lease_epoch: int
    grant_ref: str
    delivery_namespace: str


FIELDS = {
    "version",
    "event_id",
    "message_id",
    "actor_id",
    "workspace_id",
    "channel_id",
    "thread_id",
    "revision",
    "kind",
    "text",
    "mirrored",
}


def decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > 1048576:
        raise Rejected("size or encoding")
    try:
        event = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        if type(event) is not dict or set(event) != FIELDS:
            raise Rejected("fields")
        if event["version"] != "runspindle.tether.ingress.v1":
            raise Rejected("version")
        for key in (
            "event_id",
            "message_id",
            "actor_id",
            "workspace_id",
            "channel_id",
            "thread_id",
        ):
            identifier(event[key])
        counter(event["revision"])
        if event["kind"] not in ("create", "edit", "delete"):
            raise Rejected("kind")
        if (event["revision"] == 1) != (event["kind"] == "create"):
            raise Rejected("revision kind")
        if type(event["text"]) is not str or type(event["mirrored"]) is not bool:
            raise Rejected("content")
        if event["kind"] == "delete" and event["text"]:
            raise Rejected("delete content")
        if canonical(event) != raw:
            raise Rejected("noncanonical")
        return cast(dict[str, Any], event)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise Rejected("invalid event") from exc


class Admission:
    def __init__(
        self,
        path: str,
        authenticate: Callable[[bytes, object], Identity | None] | None = None,
        authorize: Callable[[Identity, str], Grant | None] | None = None,
    ) -> None:
        self.authenticate = authenticate
        self.authorize = authorize
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS revisions (
                task TEXT NOT NULL, revision TEXT NOT NULL, scope TEXT NOT NULL,
                kind TEXT NOT NULL, digest TEXT NOT NULL, envelope TEXT NOT NULL,
                PRIMARY KEY(task, revision));
            CREATE TABLE IF NOT EXISTS deliveries (
                namespace TEXT NOT NULL, event TEXT NOT NULL, digest TEXT NOT NULL,
                PRIMARY KEY(namespace, event));
            CREATE TABLE IF NOT EXISTS heads (
                task TEXT PRIMARY KEY, revision TEXT NOT NULL, scope TEXT NOT NULL,
                deleted INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sources (
                scope TEXT PRIMARY KEY, task TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS mirrors (scope TEXT PRIMARY KEY);
        """)

    def close(self) -> None:
        self.db.close()

    @staticmethod
    def scope(event: dict[str, Any], actor: bool = True) -> str:
        fields = ["workspace_id", "channel_id", "thread_id", "message_id"]
        if actor:
            fields.append("actor_id")
        return canonical([event[key] for key in fields]).decode()

    def record_mirror(
        self, workspace_id: str, channel_id: str, thread_id: str, message_id: str
    ) -> None:
        """Trusted outbound readback seam; never expose as an inbound command."""
        values = [workspace_id, channel_id, thread_id, message_id]
        for value in values:
            identifier(value)
        self.db.execute(
            "INSERT OR IGNORE INTO mirrors VALUES (?)", (canonical(values).decode(),)
        )

    def ingest(self, raw: bytes, proof: object) -> str:
        # Authentication precedes parsing, authority precedes all persistent effects.
        if self.authenticate is None or self.authorize is None:
            raise Rejected("trusted adapters unavailable")
        if type(raw) is not bytes or len(raw) > 1048576:
            raise Rejected("size or encoding")
        try:
            identity = self.authenticate(raw, proof)
        except Exception as exc:
            raise Rejected("transport authentication unavailable") from exc
        if type(identity) is not Identity:
            raise Rejected("transport authentication failed")
        event = decode(raw)
        claimed = Identity(
            *(
                event[key]
                for key in ("actor_id", "workspace_id", "channel_id", "thread_id")
            )
        )
        if claimed != identity:
            raise Rejected("identity or destination mismatch")
        digest = hashlib.sha256(raw).hexdigest()
        try:
            grant = self.authorize(identity, digest)
        except Exception as exc:
            raise Rejected("authority unavailable") from exc
        if (
            type(grant) is not Grant
            or grant.identity != identity
            or grant.event_digest != digest
        ):
            raise Rejected("authority mismatch")
        if grant.revision != event["revision"]:
            raise Rejected("authority revision")
        for key in (
            "task_id",
            "operation_id",
            "policy_revision",
            "host_id",
            "grant_ref",
            "delivery_namespace",
        ):
            identifier(getattr(grant, key))
        counter(grant.revision)
        counter(grant.lease_epoch)
        envelope = {
            "version": "runspindle.envelope.v1",
            "message_type": "admission_request",
            "message_id": event["event_id"],
            "binding": {
                "task_id": grant.task_id,
                "revision": grant.revision,
                "operation_id": grant.operation_id,
                "policy_revision": grant.policy_revision,
                "host_id": grant.host_id,
                "workspace_id": identity.workspace_id,
                "lease_epoch": grant.lease_epoch,
            },
            "payload": {
                "delivery_namespace": grant.delivery_namespace,
                "delivery_id": event["event_id"],
                "predecessor_revision": None
                if grant.revision == 1
                else grant.revision - 1,
                "normalized_digest": digest,
                "grant_ref": grant.grant_ref,
            },
        }
        scope = self.scope(event)
        encoded = canonical(envelope).decode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if (
                event["mirrored"]
                or self.db.execute(
                    "SELECT 1 FROM mirrors WHERE scope=?", (self.scope(event, False),)
                ).fetchone()
            ):
                raise Rejected("mirrored output")
            previous = self.db.execute(
                "SELECT digest FROM deliveries WHERE namespace=? AND event=?",
                (grant.delivery_namespace, event["event_id"]),
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise Rejected("delivery conflict")
                self.db.execute("ROLLBACK")
                return "duplicate"
            head = self.db.execute(
                "SELECT revision, scope, deleted FROM heads WHERE task=?",
                (grant.task_id,),
            ).fetchone()
            if head:
                if head[1] != scope or head[2] or int(head[0]) + 1 != grant.revision:
                    raise Rejected("stale, conflicting or deleted intent")
            elif grant.revision != 1:
                raise Rejected("missing predecessor")
            owner = self.db.execute(
                "SELECT task FROM sources WHERE scope=?", (self.scope(event, False),)
            ).fetchone()
            if owner and owner[0] != grant.task_id:
                raise Rejected("message already bound")
            self.db.execute(
                "INSERT OR IGNORE INTO sources VALUES (?,?)",
                (self.scope(event, False), grant.task_id),
            )
            self.db.execute(
                "INSERT INTO deliveries VALUES (?,?,?)",
                (grant.delivery_namespace, event["event_id"], digest),
            )
            self.db.execute(
                "INSERT INTO revisions VALUES (?,?,?,?,?,?)",
                (
                    grant.task_id,
                    str(grant.revision),
                    scope,
                    event["kind"],
                    digest,
                    encoded,
                ),
            )
            self.db.execute(
                "INSERT OR REPLACE INTO heads VALUES (?,?,?,?)",
                (grant.task_id, str(grant.revision), scope, event["kind"] == "delete"),
            )
            self.db.execute("COMMIT")
            return "admitted"
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def envelopes(self) -> list[dict[str, Any]]:
        """Read local immutable admission records. Not dispatch or delivery receipts."""
        return [
            json.loads(row[0])
            for row in self.db.execute("SELECT envelope FROM revisions ORDER BY rowid")
        ]
