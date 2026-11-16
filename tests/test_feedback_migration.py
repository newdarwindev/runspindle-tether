"""Explicit v2 migration, including actual pinned v1 code and open objects."""

import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tether.feedback_schema import (
    FAMILY,
    SCHEMA_V1,
    migrate_feedback_v1_to_v2,
    open_feedback_store,
)
from tether.schema import SchemaRejected

ROOT = Path(__file__).resolve().parents[1]
V1 = "040b71f2213a34f34e6b6a40124ed1164b93ce30"


def pinned_v1() -> Path:
    value = os.environ.get("RUNSPINDLE_TETHER_V1_SOURCE")
    if not value:
        raise RuntimeError(
            "RUNSPINDLE_TETHER_V1_SOURCE must name exact prepared v1 source; no fetch/fallback"
        )
    root = Path(value).absolute()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != V1:
        raise RuntimeError("v1 source revision mismatch")
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--exit-code",
            "HEAD",
            "--",
            "tether",
            "tests",
        ],
        check=True,
        capture_output=True,
    )
    return root


class FeedbackMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "feedback.sqlite"

    def legacy(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.executescript(SCHEMA_V1)
            db.execute(f"PRAGMA application_id={FAMILY}")
            db.execute("PRAGMA user_version=1")

    def test_no_implicit_migration_and_atomic_explicit_upgrade(self) -> None:
        self.legacy()
        before = self.path.read_bytes()
        with self.assertRaises(SchemaRejected):
            open_feedback_store(str(self.path))
        self.assertEqual(self.path.read_bytes(), before)
        migrate_feedback_v1_to_v2(str(self.path))
        db = open_feedback_store(str(self.path))
        try:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (2,))
            self.assertEqual(
                db.execute(
                    "SELECT blocked FROM feedback_invalidation_state"
                ).fetchone(),
                (0,),
            )
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("SELECT * FROM feedback_heads")
        finally:
            db.close()
        before = self.path.read_bytes()
        with self.assertRaises(SchemaRejected):
            migrate_feedback_v1_to_v2(str(self.path))
        self.assertEqual(self.path.read_bytes(), before)

    def test_wrong_missing_corrupt_and_future_schema_unchanged(self) -> None:
        for mutation in (
            "DROP TABLE feedback_heads",
            "DROP TRIGGER feedback_immutable_update",
            "PRAGMA user_version=999",
            "PRAGMA application_id=42",
        ):
            with self.subTest(mutation=mutation):
                self.path.unlink(missing_ok=True)
                self.legacy()
                with sqlite3.connect(self.path) as db:
                    db.execute(mutation)
                before = self.path.read_bytes()
                with self.assertRaises(SchemaRejected):
                    migrate_feedback_v1_to_v2(str(self.path))
                self.assertEqual(self.path.read_bytes(), before)
        self.path.write_bytes(b"not a database")
        with self.assertRaises(sqlite3.DatabaseError):
            migrate_feedback_v1_to_v2(str(self.path))
        self.assertEqual(self.path.read_bytes(), b"not a database")

    def test_corrupt_retained_payload_rejects_without_repair(self) -> None:
        self.legacy()
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO feedback_revisions VALUES(?,?,?,?,?,?)",
                ("identity", "1", "0" * 64, b"corrupt", "grant", "policy"),
            )
        before = self.path.read_bytes()
        with self.assertRaises(SchemaRejected):
            migrate_feedback_v1_to_v2(str(self.path))
        self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_revision_heads_bindings_and_conflict_state_reject(self) -> None:
        import hashlib
        import json

        from tests.test_feedback import FeedbackTests
        from tether.admission import canonical

        fixture = FeedbackTests()
        fixture.setUp()
        try:
            fixture.ingest(fixture.raw())
            fixture.ingest(fixture.raw(2, kind="delete", judgment=None))
            source_rows = {
                name: fixture.app.db.execute("SELECT * FROM " + name).fetchall()
                for name in (
                    "feedback_revisions",
                    "feedback_deliveries",
                    "feedback_heads_v2",
                )
            }
        finally:
            fixture.doCleanups()
        for mode in (
            "valid",
            "old_head",
            "gap",
            "binding",
            "clear_conflict",
            "missing_conflict_digest",
        ):
            with self.subTest(mode=mode):
                self.path.unlink(missing_ok=True)
                self.legacy()
                rows = {
                    name: [list(row) for row in values]
                    for name, values in source_rows.items()
                }
                if mode == "old_head":
                    rows["feedback_heads_v2"][0][1] = "1"
                    rows["feedback_heads_v2"][0][3] = 0
                if mode == "gap":
                    rows["feedback_revisions"] = rows["feedback_revisions"][1:]
                    rows["feedback_deliveries"] = rows["feedback_deliveries"][1:]
                if mode == "binding":
                    row = rows["feedback_revisions"][1]
                    changed = json.loads(row[3])
                    changed["actor_id"] = "other-author"
                    row[3] = canonical(changed)
                    row[2] = hashlib.sha256(row[3]).hexdigest()
                    rows["feedback_deliveries"][1][3] = row[2]
                    binding = json.loads(rows["feedback_heads_v2"][0][2])
                    binding[0] = "other-author"
                    rows["feedback_heads_v2"][0][2] = canonical(binding)
                if mode == "clear_conflict":
                    rows["feedback_heads_v2"][0][5] = "0" * 64
                if mode == "missing_conflict_digest":
                    rows["feedback_heads_v2"][0][4] = 1
                with sqlite3.connect(self.path) as db:
                    for table, values in rows.items():
                        name = (
                            "feedback_heads" if table == "feedback_heads_v2" else table
                        )
                        for row in values:
                            db.execute(
                                "INSERT INTO "
                                + name
                                + " VALUES("
                                + ",".join("?" for _ in row)
                                + ")",
                                row,
                            )
                before = self.path.read_bytes()
                if mode == "valid":
                    migrate_feedback_v1_to_v2(str(self.path))
                else:
                    with self.assertRaises(SchemaRejected):
                        migrate_feedback_v1_to_v2(str(self.path))
                    self.assertEqual(self.path.read_bytes(), before)

    def test_writer_lock_revalidation_rejects_changed_v1(self) -> None:
        self.legacy()
        import tether.feedback_schema as schema

        inspect: Any = getattr(schema, "inspect")
        calls = 0

        def raced(*args: Any) -> bool:
            nonlocal calls
            result = inspect(*args)
            calls += 1
            if calls == 1:
                with sqlite3.connect(self.path) as db:
                    db.execute("PRAGMA user_version=999")
            return bool(result)

        with patch.object(schema, "inspect", raced), self.assertRaises(SchemaRejected):
            migrate_feedback_v1_to_v2(str(self.path))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (999,))
            self.assertEqual(
                db.execute("SELECT count(*) FROM feedback_heads").fetchone(), (0,)
            )
            self.assertFalse(
                db.execute(
                    "SELECT name FROM sqlite_master WHERE name='feedback_heads_v2'"
                ).fetchall()
            )

    def test_process_interruption_rolls_back_rename_and_new_tables(self) -> None:
        self.legacy()
        code = """
import os,sys
import tether.feedback_schema as schema
original=schema.statements
def interrupted(script):
 for statement in original(script):
  yield statement
  os._exit(71)
schema.statements=interrupted
schema.migrate_feedback_v1_to_v2(sys.argv[1])
"""
        child = subprocess.run(
            [sys.executable, "-O", "-c", code, str(self.path)],
            cwd=ROOT,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(child.returncode, 71, child.stderr)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(
                db.execute("SELECT count(*) FROM feedback_heads").fetchone(), (0,)
            )
            self.assertFalse(
                db.execute(
                    "SELECT name FROM sqlite_master WHERE name LIKE 'feedback_invalidation%'"
                ).fetchall()
            )
        migrate_feedback_v1_to_v2(str(self.path))
        open_feedback_store(str(self.path)).close()

    def test_actual_pinned_old_open_and_new_readers_fail_after_migration(self) -> None:
        old = pinned_v1()
        code = """
import json,sqlite3,subprocess,sys
from pathlib import Path
from tests.test_slack_feedback import Harness, feedback, headers, MESSAGE
from tether.feedback import FeedbackStore
from tether.schema import SchemaRejected
h=Harness(Path(sys.argv[1]))
try:
 raw=feedback()
 h.app.ingest(raw,headers(raw))
 before=h.app.store.evidence(h.app.namespace,MESSAGE)
 rows=h.app.store.db.execute('SELECT * FROM feedback_revisions').fetchall()
 migration=subprocess.run([sys.executable,sys.argv[2],h.path,'--clients-quiesced'],capture_output=True,text=True)
 if migration.returncode: raise RuntimeError(migration.stdout+ migration.stderr)
 for call in (lambda:h.app.store.evidence(h.app.namespace,MESSAGE),lambda:h.app.ingest(raw,headers(raw))):
  try: call()
  except sqlite3.OperationalError: pass
  else: raise RuntimeError('already-open v1 API ignored v2')
 if h.app.store.db.in_transaction: raise RuntimeError('old failed write left transaction')
 if h.app.store.db.execute('SELECT * FROM feedback_revisions').fetchall()!=rows:
  raise RuntimeError('old API partially committed')
 original=Path(h.path).read_bytes()
 try: FeedbackStore(h.path,h.journal)
 except SchemaRejected: pass
 else: raise RuntimeError('fresh old reader admitted v2')
 if Path(h.path).read_bytes()!=original: raise RuntimeError('old reader modified v2')
 print(json.dumps(before))
finally:h.close()
"""
        child = subprocess.run(
            [
                sys.executable,
                "-O",
                "-c",
                code,
                str(self.root),
                str(ROOT / "tools/migrate_feedback_v2.py"),
            ],
            cwd=old,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        import json

        old_evidence = json.loads(child.stdout)
        from tether.feedback import FeedbackStore

        journal: Any = None
        new = FeedbackStore(str(self.path), journal)
        try:
            original = old_evidence["revisions"][0]["event"]
            evidence = new.evidence(original["namespace"], original["feedback_id"])
            self.assertEqual(evidence["revisions"], old_evidence["revisions"])
            self.assertEqual(evidence["state"], "active")
        finally:
            new.close()
