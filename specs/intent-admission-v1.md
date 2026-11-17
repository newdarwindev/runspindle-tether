# Semantic intent admission producer v1

This is a pure producer for the separately versioned Core v3 authority lane,
contributing to issue #8. It is not a Slack adapter, issuer, transport, admission
store, or production qualification. Neither issue #8 nor its parent closes.

`build_intent` accepts canonical normalized `runspindle.tether.ingress.v1` bytes
and explicit trusted application configuration: app/account, task binding,
delivery namespace/operation and a grant reference. It emits canonical UTF-8 JSON
`runspindle.intent-admission.v1`. `decode_intent` validates the bounded canonical
shape, not signatures, expiry, durable source ownership, or permission.

The event carries exact app/account/actor/workspace/channel/thread/message/event
identity, revision, create/edit/delete semantics, SHA256 of UTF-8 text and an
optional predecessor. No raw text is emitted. A predecessor includes its exact
Core request envelope and SHA256 of its **full intent wire**, not merely its
request. The producer requires consecutive revisions, unchanged source/task,
distinct task operation IDs, and no resurrection after a delete. Delete text is
empty. Mirrored input always rejects. Core must independently enforce these
checks against its durable accepted state; supplied previous bytes are not proof.

The exact destination is `tether:` followed by lowercase SHA256 of canonical JSON
array `[app_id, account_id, workspace_id, channel_id, thread_id]`. Its account
matches source account. The scoped envelope's normalized digest hashes the whole
semantic event, including prior request and prior full-wire digest. Delivery and
task operation IDs differ. The legacy ingress/envelope serializers are unchanged. The still-unqualified
semantic lane now requires source-owned deterministic task identity as below.

A grant reference does not authorize these bytes. A trusted issuer must issue a
**fresh runspindle.authority.v3 assertion over the resulting full wire**. Never
reuse an existing ingress `Grant`, reinterpret its raw-ingress digest, or infer
permission from transport authentication. The constructor intentionally accepts
no Grant or signing credentials and calls no callback. The Core consumer must
check current authority at admission and before effects. Caller values and the
Python process itself remain trusted application seams, not remote RPC inputs.

## Actual Slack semantics remain deny-only

The existing `SignedSlackIngress` still rejects raw Slack edit/delete subtypes.
This codec does not establish who performed an edit/delete and never treats the
original message author as that actor. Ordered synthetic normalized edit/delete
vectors prove only the wire seam. A future authenticated source adapter and
explicit actor attribution are prerequisites to real edited/deleted Slack tasks.
No server, live subscription, credential, deployment or persistent job is added.

## Verification and remaining gates

Base: Tether `dcaa5c9d61564e7247ff05793afa0e7cc1ae08b3`.
Consumer source contract: Core `src/intent.rs`, proposed semantic v1 lane on base
`4093613`; not a merged or production-qualified dependency. Exact cross-component
pins must be recorded by composition qualification after both heads are final.

Bounded local reproduction:

```sh
export RUNSPINDLE_TETHER_V1_SOURCE=/path/to/clean/prepared/tether-v1
# Required exact legacy fixture: 040b71f2213a34f34e6b6a40124ed1164b93ce30
python3 tools/check_scaffold.py
python3 -m unittest tests.test_intent -v
python3 -O -m unittest tests.test_intent -v
python3 -m unittest discover -s tests
python3 -O -m unittest discover -s tests
```

Tests independently build the expected wire and destination hash, cover source
and task rebinding, revision gaps, tombstones, forged digest/destination fields,
unknown nested fields, duplicate JSON keys, bounds, noncanonical wire, and mirrored
input. A maintained mirror-guard-removal mutant must fail the actual regression by
assertion. Network socket creation and SQLite opening are independently forbidden
in the positive vector. Existing signed Slack transport regressions are retained.

The codec has no state, so no producer durability claim applies. Actual Core
registry restart/replay, trusted issuer provisioning, signed Slack revision actor
attribution, native effects, exact-head composed qualification and live service
acceptance remain separate, not-run/blocked gates. Successful encoding is never
successful admission, execution, or delivery.

The independent cross-language vectors are `conformance/intent-v1/vectors.json`.
Each embeds its exact wire object, full canonical wire SHA256 and semantic event
SHA256. They contain create/edit/delete chaining and a non-ASCII text digest.
The vectors were constructed independently of the producer; tests compare exact
bytes, not just a producer/decoder round trip.

See [bounded evidence](../docs/intent-producer-evidence.json) for test counts,
artifact digests and explicit aggregate static-check blockers. No existing debt
baseline was relaxed. Full cross-component qualification must pin both final heads.

## Source-owned task identity correction

A semantic request MUST supply `binding.task_id` equal to `expected_task_id(source)`:
`tether-task:` + lowercase SHA256 of canonical JSON array
`[app_id, account_id, workspace_id, channel_id, thread_id, message_id]`.
The codec rejects a mismatch; it never silently rewrites a caller's task ID.
Actor is deliberately excluded: different actors referring to the same source
message must address the same durable Core workflow, not parallel task registries.
Core must independently enforce this deterministic address AND immutable source
actor binding, freshness, authority and revision ordering. The hash gives no
permission and is not global durable admission on its own.

This corrects a gap in the previously unqualified semantic candidate: its arbitrary
initial task IDs could address multiple workflows for one source. Earlier fixture
hashes and semantic bytes are superseded, not qualified for production. Legacy
arbitrary-task workflows are not automatically migrated, adopted or coalesced.
Migration requires separate explicit qualification. Delete remains non-executable,
empty-content, and terminal; only the Core lane can reserve authenticated deletion
against actual durable history. Signed Slack edits/deletes remain deny-only here.

## Retained export seam

`export_retained_intent(admission, raw, **build_arguments)` accepts an actual
`Admission` owned by trusted application code, not a request-controlled database.
It builds the candidate then uses one SQLite read transaction to verify the exact
retained revision kind/scope/raw digest, canonical legacy envelope, source owner,
global delivery namespace/event digest, current head and absence of a mirror.
Any missing, different, stale or corrupted record rejects. Nested transactions
reject without committing or rolling back the caller's transaction. Every owned
read transaction rolls back on success, failure or cancellation; no record changes.

The legacy retained envelope's grant reference is validated only as retained data;
it is never reused to authorize the new wire. The explicit new grant reference is
still merely a reference requiring fresh v3 issuance. The returned bytes contain
no raw message text. The existing sanitizer checks exported metadata unchanged.

This export is deliberately latest-retained-only. After a newer revision is
retained, earlier candidates cannot be newly exported by this seam. Export/store
processing must preserve order; this helper is not a replay coordinator or a way
to reconstruct missed exports after later admissions. A prior candidate's exact
wire must already be available when exporting its successor. Durable end-to-end
coordination/recovery remains a separate Core/composition qualification gate.
The read snapshot cannot prevent a later deletion or revocation before effect;
Core's independent current authority and state fencing remain mandatory.

Pure `build_intent` remains available for conformance and trusted construction,
not as a production ingress bypass. A production bridge must use retained export
and must not submit arbitrary codec output around the existing authenticated,
durable delivery/source deduplication path. Retained export tests use actual SQLite
with explicitly fake authentication and grants, independently inspect unchanged
database dumps, reject conflicting provider event IDs across sources, and reopen
in fresh normal/optimized processes. There is no issuer/provider/network effect.
