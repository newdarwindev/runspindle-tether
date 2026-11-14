"""Actual SQLite schema admission, using only synthetic disposable stores."""

from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tether.admission import Admission, SCHEMA as ADMISSION
from tether.feedback import FeedbackStore, SCHEMA as FEEDBACK
from tether.journal import ProviderJournal, SCHEMA as JOURNAL
from tether.schema import SchemaRejected, open_store

PYTHON = [sys.executable, *(["-O"] if sys.flags.optimize else [])]
ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ((ADMISSION, 0x54410001), (JOURNAL, 0x544A0001), (FEEDBACK, 0x54460001))


class SchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "store.sqlite"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def snapshot(self) -> dict[str, bytes]:
        return {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}

    def test_future_version_does_not_initialize(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version=999")
        before = self.snapshot()
        with self.assertRaises(SchemaRejected):
            Admission(str(self.path))
        self.assertEqual(before, self.snapshot())

    def test_legacy_adoption_retains_data_and_families_are_distinct(self) -> None:
        for script, family in FAMILIES:
            with self.subTest(family=family):
                self.path.unlink(missing_ok=True)
                db = sqlite3.connect(self.path)
                db.executescript(script)
                original = db.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
                ).fetchall()
                db.close()
                db = open_store(str(self.path), script, family)
                self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (1,))
                self.assertEqual(
                    db.execute("PRAGMA application_id").fetchone(), (family,)
                )
                self.assertEqual(
                    db.execute(
                        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
                    ).fetchall(),
                    original,
                )
                db.close()
                before = self.snapshot()
                other = next(x for x in FAMILIES if x[1] != family)
                with self.assertRaises(SchemaRejected):
                    open_store(str(self.path), *other)
                self.assertEqual(before, self.snapshot())
        # A retained admission record survives adoption and fresh-process reopen.
        self.path.unlink()
        with sqlite3.connect(self.path) as db:
            db.executescript(ADMISSION)
            db.execute("INSERT INTO mirrors VALUES ('retained-exact-scope')")
        code = "from tether.admission import Admission; import sys; a=Admission(sys.argv[1]); rows=a.db.execute('SELECT scope FROM mirrors').fetchall(); a.close(); sys.exit(0 if rows==[('retained-exact-scope',)] else 1)"
        result = subprocess.run(
            [*PYTHON, "-c", code, str(self.path)], cwd=ROOT, capture_output=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_table_index_trigger_and_missing_table_reject(self) -> None:
        changes = (
            "DROP TABLE provider_attempts",
            "DROP TRIGGER provider_binding_immutable",
            "CREATE INDEX unexpected ON provider_attempts(state)",
            "ALTER TABLE provider_attempts ADD COLUMN unexpected TEXT",
        )
        for change in changes:
            with self.subTest(change=change):
                self.path.unlink(missing_ok=True)
                db = open_store(str(self.path), JOURNAL, FAMILIES[1][1])
                db.close()
                with sqlite3.connect(self.path) as db:
                    db.execute(change)
                before = self.snapshot()
                with self.assertRaises(SchemaRejected):
                    ProviderJournal(str(self.path))
                self.assertEqual(before, self.snapshot())
        self.path.unlink()
        with sqlite3.connect(self.path) as db:
            db.executescript(ADMISSION.replace("task TEXT NOT NULL", "task TEXT"))
        before = self.snapshot()
        with self.assertRaises(SchemaRejected):
            Admission(str(self.path))
        self.assertEqual(before, self.snapshot())

    def test_wrong_legacy_family_and_non_database_rejected(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.executescript(FEEDBACK)
        before = self.snapshot()
        with self.assertRaises(SchemaRejected):
            Admission(str(self.path))
        self.assertEqual(before, self.snapshot())
        self.path.write_bytes(b"not a SQLite database")
        before = self.snapshot()
        with self.assertRaises(sqlite3.DatabaseError):
            Admission(str(self.path))
        self.assertEqual(before, self.snapshot())

    def test_wal_future_schema_rejection_preserves_main_and_wal(self) -> None:
        owner = sqlite3.connect(self.path)
        try:
            owner.execute("PRAGMA journal_mode=WAL")
            owner.execute("PRAGMA user_version=999")
            owner.commit()
            paths = [self.path, Path(str(self.path) + "-wal")]
            before = [p.read_bytes() for p in paths]
            with self.assertRaises(SchemaRejected):
                Admission(str(self.path))
            self.assertEqual(before, [p.read_bytes() for p in paths])
        finally:
            owner.close()

    def test_concurrent_process_adoption(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.executescript(ADMISSION)
        code = "from tether.admission import Admission; import sys; a=Admission(sys.argv[1]); a.close()"
        children = [
            subprocess.Popen(
                [*PYTHON, "-c", code, str(self.path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(4)
        ]
        for child in children:
            _, err = child.communicate(timeout=15)
            self.assertEqual(child.returncode, 0, err)
        a = Admission(str(self.path))
        a.close()

    def test_lock_time_recheck_rejects_changed_version(self) -> None:
        import tether.schema as schema

        real = schema.inspect
        count = 0
        with sqlite3.connect(self.path) as db:
            db.executescript(ADMISSION)

        def raced(
            db: sqlite3.Connection,
            expected: list[tuple[str, str, str, str | None]],
            family: int,
        ) -> bool:
            nonlocal count
            result = real(db, expected, family)
            count += 1
            if count == 1:
                with sqlite3.connect(self.path) as writer:
                    writer.execute("PRAGMA user_version=999")
            return result

        with patch.object(schema, "inspect", raced), self.assertRaises(SchemaRejected):
            Admission(str(self.path))
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (999,))
            self.assertEqual(db.execute("PRAGMA application_id").fetchone(), (0,))

    def test_process_interruption_rolls_back_schema_transaction(self) -> None:
        # Interrupt after the first actual DDL statement while the write lock is held.
        code = """
import os,sys
import tether.schema as s
from tether.admission import Admission
original=s.statements
def interrupted(script):
    for statement in original(script):
        yield statement
        os._exit(71)
s.statements=interrupted
Admission(sys.argv[1])
"""
        child = subprocess.run(
            [*PYTHON, "-c", code, str(self.path)],
            cwd=ROOT,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(child.returncode, 71)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(
                db.execute("SELECT name FROM sqlite_master").fetchall(), []
            )
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (0,))
        a = Admission(str(self.path))
        a.close()

    def test_interrupted_legacy_metadata_adoption_rolls_back(self) -> None:
        with sqlite3.connect(self.path) as db:
            db.executescript(ADMISSION)
            db.execute("INSERT INTO mirrors VALUES ('retained')")
        code = """
import os,sqlite3,sys
import tether.schema as schema
from tether.admission import Admission
original=sqlite3.connect
class Interrupted(sqlite3.Connection):
    def execute(self, sql, *args, **kwargs):
        result=super().execute(sql, *args, **kwargs)
        if sql == 'PRAGMA user_version=1':
            os._exit(72)
        return result
def connect(*args, **kwargs):
    return original(*args, **kwargs, factory=Interrupted)
schema.sqlite3.connect=connect
Admission(sys.argv[1])
"""
        child = subprocess.run(
            [*PYTHON, "-c", code, str(self.path)],
            cwd=ROOT,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(child.returncode, 72)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (0,))
            self.assertEqual(db.execute("PRAGMA application_id").fetchone(), (0,))
            self.assertEqual(
                db.execute("SELECT scope FROM mirrors").fetchall(), [("retained",)]
            )
        reopened = Admission(str(self.path))
        reopened.close()

    def test_schema_rejection_mutation_is_detected(self) -> None:
        code = """
import sys,unittest
sys.path.insert(0,'tests')
import test_schema
import tether.schema as schema
schema.inspect=lambda *args: True
suite=unittest.TestSuite([test_schema.SchemaTests('test_future_version_does_not_initialize')])
result=unittest.TextTestRunner().run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
"""
        child = subprocess.run(
            [*PYTHON, "-c", code], cwd=ROOT, capture_output=True, timeout=15
        )
        self.assertEqual(child.returncode, 1)
        self.assertIn(b"SchemaRejected not raised", child.stderr)
        self.assertNotIn(b"ERROR:", child.stderr)

    def test_all_public_stores_use_schema_admission(self) -> None:
        journal = ProviderJournal(":memory:")
        self.addCleanup(journal.close)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA user_version=999")
        for factory in (
            lambda: Admission(str(self.path)),
            lambda: ProviderJournal(str(self.path)),
            lambda: FeedbackStore(str(self.path), journal),
        ):
            with self.assertRaises(SchemaRejected):
                factory()


if __name__ == "__main__":
    unittest.main()
