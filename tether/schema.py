"""Exact SQLite family admission; no repair of unknown or damaged stores."""

import sqlite3
from pathlib import Path


class SchemaRejected(ValueError):
    """Store cannot be admitted without changing unknown durable state."""


def inventory(db: sqlite3.Connection) -> list[tuple[str, str, str, str | None]]:
    return db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()


def statements(script: str) -> list[str]:
    result = []
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            result.append(pending)
            pending = ""
    if pending.strip():
        raise SchemaRejected("invalid schema definition")
    return result


def inspect(
    db: sqlite3.Connection,
    expected: list[tuple[str, str, str, str | None]],
    family: int,
    *,
    schema_version: int = 1,
) -> bool:
    """Return whether initialization/adoption is needed; do not write."""
    version = db.execute("PRAGMA user_version").fetchone()[0]
    application = db.execute("PRAGMA application_id").fetchone()[0]
    found = inventory(db)
    if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise SchemaRejected("store integrity rejected")
    if version == schema_version and application == family and found == expected:
        return False
    if version == 0 and application == 0 and (not found or found == expected):
        return True
    raise SchemaRejected("store schema rejected")


def open_store(
    path: str,
    script: str,
    family: int,
    *,
    upgrade: str | None = None,
    require_initialized: bool = False,
) -> sqlite3.Connection:
    with sqlite3.connect(":memory:") as model:
        model.executescript(script)
        expected = inventory(model)
        if upgrade is not None:
            model.execute(upgrade)
            upgraded = inventory(model)
        else:
            upgraded = expected
    model.close()

    def check(db: sqlite3.Connection) -> tuple[bool, bool]:
        if upgrade is not None and db.execute("PRAGMA user_version").fetchone() == (2,):
            return inspect(db, upgraded, family, schema_version=2), False
        adopt = inspect(db, expected, family)
        if adopt and require_initialized:
            raise SchemaRejected("initialized store required")
        return adopt, upgrade is not None

    # Read-only preflight rejects existing unknown state before obtaining a
    # writable connection. URI mode is constructed, never accepted from callers.
    file = Path(path)
    uri = file.absolute().as_uri() + "?mode=rw"
    if path and path != ":memory:" and file.exists():
        probe = sqlite3.connect(file.absolute().as_uri() + "?mode=ro", uri=True)
        try:
            # Read version, family and objects from one snapshot. Another
            # opener may commit adoption between individual metadata queries.
            probe.execute("BEGIN")
            check(probe)
        finally:
            probe.close()
    db = sqlite3.connect(
        uri if require_initialized else path,
        isolation_level=None,
        uri=require_initialized,
    )
    try:
        db.execute("BEGIN IMMEDIATE")
        adopt, migrate = check(db)
        if adopt:
            if not inventory(db):
                for statement in statements(script):
                    db.execute(statement)
            db.execute(f"PRAGMA application_id={family}")
            db.execute("PRAGMA user_version=1")
        if migrate and upgrade is not None:
            db.execute(upgrade)
            db.execute("PRAGMA user_version=2")
            inspect(db, upgraded, family, schema_version=2)
        db.commit()
        return db
    except BaseException:
        db.rollback()
        db.close()
        raise
