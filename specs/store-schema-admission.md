# Exact SQLite store schema admission

Bounded work for issues #8/#9 and retained feedback. This changes opening actual
Admission, ProviderJournal and FeedbackStore databases, not their authority or
provider adapters. No new dependency, service, background repair or backup exists.

## Accepted states

Each family has version 1 and a distinct SQLite application ID: admission
1413545985, provider journal 1414135809, feedback 1413873665. The exact schema is
constructed from that family's original current-main DDL in an in-memory SQLite
connection, then compared to the complete ordered sqlite_master inventory, including
SQL, constraints, indexes and triggers. Formatting-equivalent but differently
recorded SQL is intentionally not accepted as an undocumented migration.

- An empty version-0/application-0 store initializes inside one IMMEDIATE transaction.
- A version-0/application-0 store with the exact current legacy family schema adopts
  metadata in that transaction without rewriting rows, tables, indexes or triggers.
- A version-1 store must match its family and exact schema. No migration runs.
- Future/unknown versions, another family, partial/different schemas, extra indexes,
  missing/changed triggers and failed SQLite quick_check reject. No repair or data
  salvage is attempted. Historical layouts other than the exact current legacy
  layout require a separate explicit migration design.

Existing filesystem stores receive a read-only preflight. A writable connection
then obtains BEGIN IMMEDIATE and repeats every check, preventing adoption based on
an earlier stale read. Schema creation uses individual transactional statements,
not executescript's implicit commit. Initialization and metadata adoption commit
atomically; an exception rolls back and closes the connection. Concurrent openers
serialize through SQLite's existing bounded lock wait. Authority callbacks and
provider calls are never invoked by schema admission.

## Guarantees and limits

Tests observe byte-identical rejected ordinary database files and a rejected
future-version WAL database's main/WAL files while its original connection remains
open. Unknown schemas are rejected before writable open or schema DDL. This is
not a universal byte-preservation promise for hostile filesystems, corrupt/hot
journals, SQLite recovery/checkpoint behavior, shared-memory files, concurrent
external writers or power loss. No journal-mode changes are introduced. The
write-lock recheck cannot make guarantees about actors replacing database files
outside SQLite locking. SQLite errors remain explicit; database content is never
included in newly introduced schema-error messages.

The helper validates structure and SQLite integrity, not all application-level
record associations, provenance or authorization. No SQL dump is trusted or run.
Admission/journal's pre-existing ephemeral SQLite modes remain available without
any new durability claim; FeedbackStore's existing persistent-path restriction
remains unchanged. Current APIs and default-deny adapters remain unchanged.

## Verification

Run `python3 tools/validate.py` and `python3 -O -m unittest discover -s tests -v`.
`tests/test_schema.py` creates only synthetic disposable files. Tests cover future
versions, exact legacy adoption, wrong families, constraints/indexes/triggers,
missing tables, malformed files, main/WAL rejection observations, concurrent
processes, a version change between preflight and lock, and abrupt process exit
after the first transactional DDL and after legacy metadata writes. Reopen proves
rollback with retained rows intact, then successful fresh
initialization. A deliberate mutation bypasses inspection; the independent
future-version rejection regression must fail by assertion, not import failure.
SIGKILL/process exit is not power-loss qualification. Production filesystem and
live-provider acceptance remain unqualified. Parent issues remain open.
