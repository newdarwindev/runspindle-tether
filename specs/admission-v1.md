# Bounded authenticated ingress and durable revisions

Scope: original Python library seam, not an HTTP endpoint, Slack SDK, source lift,
core execution integration, or deployed service. Related: issue #8 and parent #3.
These remain open pending their upstream and live integration acceptance.

## Entrypoints and trust boundary

`Admission(path, authenticate, authorize).ingest(raw_bytes, proof)` accepts the
canonical `runspindle.tether.ingress.v1` event shape exercised in
`tests/test_admission.py`. Exact fields: version, event_id, message_id, actor_id,
workspace_id, channel_id, thread_id, revision, kind, text and mirrored. Identifiers
use the runtime ASCII grammar. Revisions are positive u64 integer tokens. Create
requires revision 1; edit/delete require later revisions; delete has empty text.
Unknown fields, duplicate keys, noncanonical JSON and inputs over 1 MiB are denied.

The trusted transport adapter must authenticate the exact bytes and return an
`Identity` binding actor plus exact workspace/channel/thread. The caller's JSON
never supplies trusted identity. The trusted authority resolver receives identity
and SHA-256 of those bytes; it must return a `Grant` bound to the same digest,
identity and revision, plus task/operation/policy/host/epoch/grant/namespace. Both
adapters are injected trusted application code. Absent, failed or unavailable
adapters deny. This library has no built-in production trust source. Synthetic
HMAC transport and static synthetic grants exist only in tests. No credentials,
network listener, runner settings or persistent jobs are created.

Expiry and revocation decisions belong to the resolver on **every** ingress,
including replays. This layer checks the returned bindings, not cryptographic
core attestations or dispatch-time expiry/revocation. Never connect these records
to execution without core #16's trusted admission/dispatch gate.

## Durable effects and ordering

One SQLite `BEGIN IMMEDIATE` transaction atomically stores delivery deduplication,
source/task identity, immutable revision/envelope history and a current head.
Stable namespace/event identity deduplicates exact byte replays and rejects
conflicting content. Revisions must be contiguous; out-of-order future revisions
are rejected without effects and can be retried once the predecessor is admitted.
A task cannot switch source identity, nor a message be rebound to another task.
Deletion is a terminal tombstone; it cannot be undone by a late edit or create.
Exceptions and cancellation roll back all writes. Counters are stored as decimal
text to preserve the complete u64 domain without SQLite signed-integer overflow.
The caller owns DB placement, lifecycle and any future retention policy.

`record_mirror(workspace, channel, thread, message)` is a trusted outbound
readback seam, never an inbound action. Recorded output identities survive restart
and are rejected regardless of event actor. Authenticated mirrored flags are also
rejected. Real outbound integration must record/read back output identities before
allowing their ingress; this library cannot recognize unmarked, unrecorded output.
No claim of universal live echo suppression is made.

`envelopes()` returns immutable local admission records, not deliveries or dispatch
receipts. Mapping targets `runspindle.envelope.v1` admission_request as specified
by root PR #47 at `9201310df7982e7d52f4b9facd8d4caec8ab35dc` (wire contract pin;
no codec copied/imported). event_id maps to message_id and delivery_id; grant
supplies the binding and grant_ref; canonical event SHA-256 maps to
normalized_digest. The ingress digest includes kind and content. Core must obtain
and independently verify the matching normalized intent through an authorized
integration before execution; the envelope does not carry raw text or delete
semantics. There is deliberately no automatic execution/dispatch path here.

## Acceptance boundary

Local synthetic tests cover exact mapping, authentication/scope/authority failure,
replay, conflicts, stale/out-of-order edits/deletes, fresh-process SQLite replay,
concurrent processes, mirror persistence and failure/cancellation rollback.
An independently read database dump/count observes forbidden effects; network
connect calls are trapped in the in-process tests. A disposable source mutation
removes actor/scope comparison and produces one forbidden durable revision,
showing the zero-effect invariant detects that defect.

Still blocked/not run: production transport signature verification and identity
mapping; root/core authenticated cross-language integration; dispatch-time
revocation; actual Tether/RepoFleet event source; live Slack echo/readback; native
execution, outbound deliveries, deployment and production acceptance. This is a
bounded implementation tranche, not completion of the entire adapter or issue.
