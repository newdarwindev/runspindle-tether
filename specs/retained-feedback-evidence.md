# Retained feedback evidence

Original prerequisite for Refinery #15, not completion of that issue or live
collection. The implementation extends Tether main `4883cd3acd6ff5812d6890279d7494a1c1cb6dde`.
No external dependency/serializer copy or new outbox is introduced. Existing
Admission Identity, canonical JSON/parser/identifier checks, sanitizer and provider
journal remain canonical. The later Refinery bridge is not implemented here.

## Exact bindings and independent permissions

`ProviderJournal.retained_target(delivery_bytes, payload, message_id)` is read-only.
It requires exact existing immutable journal binding and independently observed
message ID with no retained conflict. The supplied attachment bytes must match the
artifact digest, and the full payload digest/destination must match. It never calls
send/readback, changes admission, or upgrades transport confirmation into Core
acceptance. Its observation is historical, not current message existence. Old
output revisions remain old revisions even if task admission subsequently changes.

`FeedbackStore.ingest(raw, proof, delivery_bytes, payload)` accepts only canonical
`runspindle.tether.feedback.v1` bytes. Fields are namespace/event ID, feedback
ID/revision/predecessor, actor/workspace/channel/thread, create/edit/delete kind,
positive/negative/correction judgment, correction text or null, and exact target.
Target fields bind task/revision, artifact ID/revision/SHA256, delivery operation,
message ID, payload SHA256 and workspace/channel/thread. Integer revisions reject
booleans. Delete has no judgment/correction; correction is explicit sanitized text.
The complete target and all metadata are sanitized without rewriting identities.

Three independently injected trusted seams are required, otherwise deny:
- transport authentication returns existing Identity for these exact raw bytes;
- retention authority returns FeedbackGrant binding Identity, event and target
  hashes, policy revision and grant reference (retention only);
- artifact/Core verifier validates supplied delivery/payload/target provenance,
  including authorization to use a historical artifact identity as a target.

Authority and target checks repeat after acquiring the SQLite write lock. Proofs
and callback exceptions are never persisted; callback failures return fixed errors.
Callbacks are trusted local code, not request-defined functions. Production
implementations, real provider proofs and actual Core verification remain absent.
Synthetic test callbacks are not production authentication.

## Persistence, exclusion and consent boundaries

The constructor requires a nonempty filesystem-path string and rejects `:memory:`
and all `file:` URI names before opening a connection. Ephemeral SQLite names
cannot return successful retained evidence.

Separate local SQLite tables retain immutable canonical revisions and delivery
identities, with a stable identity derived from namespace and feedback ID.
Identical event replay returns duplicate without new rows. Edits require consecutive
revisions and unchanged actor/scope/target. Delete tombstones the head; later edits
cannot revive it. Conflicting event/revision reuse or identity binding fences
already retained affected heads, without overwriting original history. Conflicting
requests must first pass authentication, retention and exact target verification;
unauthenticated or malformed/oversized input cannot poison history.

The store caps revisions at 1000 and each raw envelope at 262144 bytes (sanitizer
limits may reject earlier). A required conflict fence updates existing rows before
checking evidence capacity, with at most one fixed digest slot; conflict storms do
not allocate audit rows or roll back that fence due to logical evidence limits.
Disk/filesystem failure is not a successful commit or a qualified recovery path.
No auto-retry, cleanup or reconciliation of unknown filesystem effects is claimed.

`evidence(namespace, feedback_id)` reads one SQLite snapshot with ordered immutable
revisions, hashes and retention references; state is active, deleted or conflicted.
It always reports collection_allowed=false and training_allowed=false. Reading
retained evidence is not dataset eligibility. A later consumer must explicitly
select exact feedback versions, obtain exact-batch collection approval and separate
training consent, and quarantine deleted/conflicted/superseded evidence rather than
silently using an old positive judgment. No event, reaction, retention grant or
transport confirmation authorizes training, provider transmission or execution.

The component-owned stores use real SQLite transactions; this is not hostile-store,
multi-host production, revocation-after-return or distributed atomicity qualification.
Separate connections are required for parallel callers. Journal confirmation and
feedback commit span separate stores; facts are rechecked but no global transaction
is claimed. A newly discovered later transport conflict requires downstream
revalidation, never a claim of timeless truth.

## Verification

Run `python3 -m unittest tests.test_feedback -v`, repeat with `python3 -O`, and run
`python3 tools/validate.py`. Synthetic fixtures execute actual Admission,
ProviderJournal and FeedbackStore with real SQLite and a disposable SQLite-backed
fake provider. Tests observe unchanged provider-call ledger and denied network/
subprocess effects during ingestion; no optimizer/provider capability is exposed.
A fresh process replays exact retained history without provider access. Tests cover
edits/deletes, proof/authority denial, target byte/destination mismatch, bool
revisions, callback revocation, bounded conflicts, and an intentional missing-fence
mutation observed through actual stored state. No live messages are collected.
