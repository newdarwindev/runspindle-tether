# Provider-authenticated permanent feedback invalidation

Partial Refinery #15/Tether feedback work, layered on reviewed Tether #28. No live
migration, rollout, deployment, automatic training or full freshness qualification.
The signed create API remains separate from this deny-only observation path.

## Provider semantics and attribution

Official Slack documents [message_changed](https://docs.slack.dev/reference/events/message/message_changed/)
by channel and nested message.ts. Nested message.user is the original author;
edited.user, when present, is an editor, not replacement authorship. Metadata or
language detection changes can also trigger this event. Every supported signed
change conservatively invalidates, even if text seems unchanged.

[message_deleted](https://docs.slack.dev/reference/events/message/message_deleted)
uses channel and deleted_ts; Slack's documented example has no deleting actor or
thread. This implementation does not infer an actor from authorizations.user_id,
previous_message.user, the configured route, or the original author. Editor/deleter
attribution remains unknown; no authored feedback revision/tombstone is fabricated.
Only supplied original-author/thread hints are checked. Original attribution and
exact output target remain in immutable retained revisions.

## Entry points and authority

`SignedSlackFeedback.invalidate(raw, headers)` reuses `SlackMessageVerifier` raw
HMAC/timestamp and app/workspace/channel routing verification before any store
operation. It accepts only hidden message_changed/message_deleted callbacks. It
locates the affected message timestamp without importing changed/previous text.
Known source/target mismatches and contradictory author/thread hints reject.
Missing author/thread is allowed for an actorless provider negative observation.

A distinct `authorize_invalidation` callback defaults to deny. Its request includes
`effect_scope=message_fence_or_storewide_saturation` plus the exact provider scope,
message, raw-body digest, event identity, cause and configured retained target.
Returning True authorizes both the individual permanent fence and the explicitly
bounded store-wide availability fallback described below. Signing alone grants
none of this authority. Retention, collection, training, task execution and use
permissions remain distinct. Authority and target are checked again under the
SQLite writer lock; callback exceptions deny with fixed errors.

## Durable negative state and limits

Feedback schema v2 adds immutable invalidation records and an event ledger. The
namespace hashes authenticated app/workspace/channel; affected message timestamps
are unique within that namespace. First event ID/body SHA-256/cause are retained;
no raw changed content, editor identity, secret or fabricated author is stored.
Duplicate and reordered notifications cannot clear fences. Event-ID/digest reuse
fences the new affected message without overwriting the first ledger mapping;
collisions with retained create identities quarantine affected existing heads
without retargeting their output or authorship.

A fence can precede a create. It creates no feedback revision or head/author
binding. Later positive retention checks this durable fence before and under its
writer lock, and rejects rather than resurrecting old evidence. Evidence reads
consult v2 fences and report `state=invalidated`; immutable earlier revisions stay
intact. Consumers such as Refinery must use compatible pinned v2 source and reread
it at import/use time. Stored snapshots are historical data, not continuing use
permission. This source change alone does not update published Refinery pins.

Both fence and event ledgers are bounded by MAX_INVALIDATIONS=1000. A verified,
authorized notification that would exceed either bound atomically sets a permanent
store-wide deny flag instead of dropping evidence. All positive retains and
compatible evidence reads consult that flag, including after restart. This
intentionally trades availability for non-resurrection. There is no automatic
reset, eviction or recovery endpoint. Existing recorded first digests are not
rewritten, and unauthorized events cannot consume capacity or set the flag.

Slack event delivery is best-effort and can be delayed; absence of a received
invalidation is not proof of provider freshness. An observation arriving after
completed use cannot retroactively revoke that use. Cross-process/source authority
changes and in-flight computations are not a distributed atomic transaction.

## Explicit schema compatibility and migration

`FeedbackStore` creates new v2 stores or opens exact compatible v2 stores only.
Opening v1 never migrates or repairs it. `migrate_feedback_v1_to_v2(path)` is an
explicit code API; `python3 tools/migrate_feedback_v2.py PATH --clients-quiesced`
is the opt-in command. The operator must stop/quiesce **all** clients before using
it. The flag is an explicit assertion, not an automatic process-discovery system.
No migration of any user's live store was run for this work.

Migration read-only preflight and writer-lock revalidation require exact known-v1
schema, application/version metadata, SQLite integrity, retained content hashes,
canonical identities, complete contiguous revision history, maximal heads,
immutable binding across revisions, deletion chronology, event ledger consistency,
and conflict flag/digest consistency. Unknown, malformed, corrupted, legacy
unversioned or newer stores reject without repair. A v2 store is not a migration
input; open it normally instead.

The transaction renames feedback_heads to feedback_heads_v2, adds the new durable
structures, initializes their deny state, and sets user_version=2. Original
revision/delivery bytes are preserved. Any error/interruption rolls back the
entire rename/DDL/version update. The explicit rename makes supported queries in
actual already-open v1 objects fail instead of silently ignoring invalidations;
fresh v1 readers reject v2 metadata/schema. The underlying generic v1 schema loader
and other Tether stores are unchanged.

This is not a promise to revoke cached/in-memory snapshots or reads already in a
transaction before migration. WAL readers, computations and other clients must be
quiesced; the migration command does not establish distributed exclusion. An old
client retaining a historical Python object cannot be made to forget it. Positive
consumers must reopen compatible source and check eligibility at use time.

## Bounded qualification

Run with Python 3.12.14 and an exact external checkout of Tether
040b71f2213a34f34e6b6a40124ed1164b93ce30:

`RUNSPINDLE_TETHER_V1_SOURCE=/path/to/exact/v1 python3 -m unittest tests.test_feedback_invalidation tests.test_feedback_migration -v`

The existing isolated component workflow prepares this exact old-reader source
without persisted credentials. No hosted fallback, runner change or package install
is added. Actual old code is run in a separate process, kept open across a synthetic
migration, then its supported reads/writes are tested for rejection and no partial
writes. All databases, keys, identities and authority are synthetic/disposable.

Tests exercise actual raw HMAC, SQLite transaction/restart behavior, capacity,
collisions, pre-create fences, scope/authority rejection and unchanged task/provider
ledgers; sockets and execution are denied during invalidation. A deliberate read
fence removal exposes active evidence despite retained invalidation, separately
observed from the normal invalidated result. Migration corruption/rollback and
old-client compatibility are independent of live Slack or rollout qualification.
