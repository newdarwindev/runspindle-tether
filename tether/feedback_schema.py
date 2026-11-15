"""Explicit feedback v2 schema and atomic, opt-in v1 migration.

No automatic migration, repair, backups or concurrent-client rollout. Quiesce all
clients before migration. Renaming the heads table fences supported old APIs.
"""

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Any

from tether.schema import SchemaRejected, inspect, inventory, statements

FAMILY = 0x54460001

SCHEMA_V1 = """
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

INVALIDATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback_invalidations (
    namespace TEXT NOT NULL, message TEXT NOT NULL, event TEXT NOT NULL,
    digest TEXT NOT NULL, cause TEXT NOT NULL,
    PRIMARY KEY(namespace,message));
CREATE TABLE IF NOT EXISTS feedback_invalidation_events (
    namespace TEXT NOT NULL, event TEXT NOT NULL, message TEXT NOT NULL,
    digest TEXT NOT NULL, PRIMARY KEY(namespace,event));
CREATE TABLE IF NOT EXISTS feedback_invalidation_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    blocked INTEGER NOT NULL CHECK(blocked IN (0,1)), digest TEXT);
CREATE TRIGGER IF NOT EXISTS invalidations_immutable_update BEFORE UPDATE ON feedback_invalidations
    BEGIN SELECT RAISE(ABORT,'immutable invalidation'); END;
CREATE TRIGGER IF NOT EXISTS invalidations_immutable_delete BEFORE DELETE ON feedback_invalidations
    BEGIN SELECT RAISE(ABORT,'retain invalidation'); END;
CREATE TRIGGER IF NOT EXISTS invalidation_events_immutable_update BEFORE UPDATE ON feedback_invalidation_events
    BEGIN SELECT RAISE(ABORT,'immutable invalidation event'); END;
CREATE TRIGGER IF NOT EXISTS invalidation_events_immutable_delete BEFORE DELETE ON feedback_invalidation_events
    BEGIN SELECT RAISE(ABORT,'retain invalidation event'); END;
CREATE TRIGGER IF NOT EXISTS invalidation_state_permanent BEFORE UPDATE ON feedback_invalidation_state
    WHEN OLD.blocked=1 BEGIN SELECT RAISE(ABORT,'permanent invalidation fence'); END;
CREATE TRIGGER IF NOT EXISTS invalidation_state_retained BEFORE DELETE ON feedback_invalidation_state
    BEGIN SELECT RAISE(ABORT,'retain invalidation state'); END;
"""
SCHEMA = (
    SCHEMA_V1.replace("feedback_heads", '"feedback_heads_v2"') + INVALIDATION_SCHEMA
)


def expected(script: str) -> list[tuple[str, str, str, str | None]]:
    model = sqlite3.connect(":memory:")
    try:
        model.executescript(script)
        return inventory(model)
    finally:
        model.close()


def state(db: sqlite3.Connection) -> tuple[int, str | None]:
    rows = db.execute(
        "SELECT singleton,blocked,digest FROM feedback_invalidation_state"
    ).fetchall()
    if len(rows) != 1 or rows[0][0] != 1 or rows[0][1] not in (0, 1):
        raise SchemaRejected("feedback invalidation state rejected")
    _, blocked, digest = rows[0]
    if (blocked == 0 and digest is not None) or (
        blocked == 1
        and (type(digest) is not str or re.fullmatch("[0-9a-f]{64}", digest) is None)
    ):
        raise SchemaRejected("feedback invalidation state rejected")
    return blocked, digest


def validate(db: sqlite3.Connection) -> None:
    if (
        db.execute("PRAGMA user_version").fetchone() != (2,)
        or db.execute("PRAGMA application_id").fetchone() != (FAMILY,)
        or inventory(db) != expected(SCHEMA)
        or db.execute("PRAGMA quick_check").fetchall() != [("ok",)]
    ):
        raise SchemaRejected("feedback v2 schema required; explicit migration only")
    state(db)


def path(value: str, *, exists: bool = False) -> Path:
    if (
        type(value) is not str
        or not value
        or value == ":memory:"
        or value.startswith("file:")
    ):
        raise SchemaRejected("feedback requires a filesystem path")
    result = Path(value)
    if (
        result.is_symlink()
        or (result.exists() and not result.is_file())
        or (exists and not result.is_file())
    ):
        raise SchemaRejected("feedback path rejected")
    return result


def open_feedback_store(value: str) -> sqlite3.Connection:
    file = path(value)
    if file.exists():
        probe = sqlite3.connect(file.absolute().as_uri() + "?mode=ro", uri=True)
        try:
            validate(probe)
        finally:
            probe.close()
    db = sqlite3.connect(value, isolation_level=None)
    try:
        db.execute("BEGIN IMMEDIATE")
        if (
            not inventory(db)
            and db.execute("PRAGMA user_version").fetchone() == (0,)
            and db.execute("PRAGMA application_id").fetchone() == (0,)
        ):
            for statement in statements(SCHEMA):
                db.execute(statement)
            db.execute("INSERT INTO feedback_invalidation_state VALUES(1,0,NULL)")
            db.execute(f"PRAGMA application_id={FAMILY}")
            db.execute("PRAGMA user_version=2")
        validate(db)
        db.commit()
        return db
    except BaseException:
        db.rollback()
        db.close()
        raise


def validate_v1_evidence(db: sqlite3.Connection) -> None:
    """Check retained bytes/linkage, without claiming to reauthenticate old proofs."""
    from tether.admission import canonical, identifier
    from tether.feedback import MAX_EVENTS, decode

    revisions: dict[tuple[str, str], dict[str, Any]] = {}
    deliveries = {}
    for identity, revision, digest, raw, grant, policy in db.execute(
        "SELECT identity,revision,digest,body,grant_ref,policy_revision FROM feedback_revisions"
    ):
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
            raise SchemaRejected("feedback v1 evidence integrity rejected")
        event = decode(raw)
        key = hashlib.sha256(
            canonical([event["namespace"], event["feedback_id"]])
        ).hexdigest()
        if identity != key or revision != str(event["revision"]):
            raise SchemaRejected("feedback v1 evidence identity rejected")
        identifier(grant)
        identifier(policy)
        if (
            len(revisions) >= MAX_EVENTS
            or (event["namespace"], event["event_id"]) in deliveries
        ):
            raise SchemaRejected("feedback v1 evidence capacity or event collision")
        revisions[(identity, revision)] = event
        deliveries[(event["namespace"], event["event_id"])] = (identity, digest)
    actual_deliveries = {
        (namespace, event): (identity, digest)
        for namespace, event, identity, digest in db.execute(
            "SELECT namespace,event,identity,digest FROM feedback_deliveries"
        )
    }
    if actual_deliveries != deliveries:
        raise SchemaRejected("feedback v1 event lineage rejected")
    heads = set()
    for identity, revision, binding, deleted, conflict, conflict_digest in db.execute(
        "SELECT identity,revision,binding,deleted,conflict,conflict_digest FROM feedback_heads"
    ):
        head_event = revisions.get((identity, revision))
        if head_event is None or deleted not in (0, 1) or conflict not in (0, 1):
            raise SchemaRejected("feedback v1 head rejected")
        history = sorted(
            (int(r), e) for (key, r), e in revisions.items() if key == identity
        )
        if [r for r, e in history] != list(range(1, len(history) + 1)) or int(
            revision
        ) != len(history):
            raise SchemaRejected("feedback v1 revision lineage rejected")
        for number, prior in history:
            expected_binding = canonical(
                [
                    prior["actor_id"],
                    prior["workspace_id"],
                    prior["channel_id"],
                    prior["thread_id"],
                    prior["target"],
                ]
            )
            if binding != expected_binding or (
                prior["kind"] == "delete" and number != len(history)
            ):
                raise SchemaRejected("feedback v1 binding or deletion lineage rejected")
        if bool(deleted) != (head_event["kind"] == "delete"):
            raise SchemaRejected("feedback v1 deletion state rejected")
        if (conflict == 0 and conflict_digest is not None) or (
            conflict == 1
            and (
                type(conflict_digest) is not str
                or re.fullmatch("[0-9a-f]{64}", conflict_digest) is None
            )
        ):
            raise SchemaRejected("feedback v1 conflict digest rejected")
        heads.add(identity)
    if heads != {identity for identity, revision in revisions}:
        raise SchemaRejected("feedback v1 head linkage rejected")


def migrate_feedback_v1_to_v2(value: str) -> None:
    """Explicit local migration, requiring quiesced clients. Never called on open."""
    file = path(value, exists=True)
    legacy = expected(SCHEMA_V1)

    def require_v1(db: sqlite3.Connection) -> None:
        # inspect accepts legacy adoption too; require actual known-v1 metadata.
        if inspect(db, legacy, FAMILY) or db.execute(
            "PRAGMA user_version"
        ).fetchone() != (1,):
            raise SchemaRejected("known feedback v1 store required")
        validate_v1_evidence(db)

    probe = sqlite3.connect(file.absolute().as_uri() + "?mode=ro", uri=True)
    try:
        require_v1(probe)
    finally:
        probe.close()
    db = sqlite3.connect(value, isolation_level=None)
    try:
        db.execute("BEGIN IMMEDIATE")
        require_v1(db)
        db.execute('ALTER TABLE feedback_heads RENAME TO "feedback_heads_v2"')
        for statement in statements(INVALIDATION_SCHEMA):
            db.execute(statement)
        db.execute("INSERT INTO feedback_invalidation_state VALUES(1,0,NULL)")
        db.execute("PRAGMA user_version=2")
        validate(db)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()
