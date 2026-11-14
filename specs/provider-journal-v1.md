# Provider attempt journal v1 (bounded synthetic qualification)

Related: issue #9 and parent #1. This partial component does not close either
issue or establish a live Tether adapter. Core remains the owner of task/artifact
acceptance, durable delivery reservations, retry authority and Delivered state.
The core `outbox::Transport` contract at core main
`83296c3962de7546efdd1bb4e3d7e5b25452509f` was inspected; no native core serializer,
store, authority implementation or source was copied.

## Integration boundary

`tether.journal.ProviderJournal` is a provider-attempt fence beneath the core
outbox. Its public send/readback methods are not a task dispatcher or background
worker. An application must supply retained `Admission`, an authoritative callback
for the exact canonical envelope **and** outbound payload digest, a trusted
account/destination-to-workspace/channel/thread resolver, and a provider adapter.
Without any of these trust seams it denies before creating attempts or invoking a
provider. The callback must validate the real core reservation, accepted artifact,
current authority, expiry/revocation and sanitized outbound content. No production
callback or Python/Rust bridge is included; core #16 integration remains blocked.

Input is the strict canonical `runspindle.envelope.v1` delivery_request subset,
using the root contract introduced in #43/#47 (root main observed at
`3c1968bab54b774ccf0239c4450e599049a14455`). Unknown/duplicate fields, bad counters,
noncanonical bytes, wrong type/version and identical artifact/delivery operation
IDs are rejected. The entire binding must equal a retained admitted binding and
its task revision must still be current and not deleted. Exact trusted route
workspace must match the binding. The current slice requires exactly one accepted
artifact attachment: ID and SHA-256 must match the envelope; normalized payload
hash additionally binds text, filename and all bytes. It does not generalize core
artifact acceptance into arbitrary multi-attachment authority.

Authority/route/admission are checked before reservation and immediately before
send; lookup checks before and after provider readback and again after acquiring
the potentially blocking SQLite write lock. These are synchronous
observations, not a distributed atomic transaction with core revocation. No
production freshness/dispatch guarantee is claimed from injected callbacks.
The provider protocol currently accepts only synthetic classified replies; it is
not a verified Slack protocol and cannot be presented as live delivery evidence.

## Durable state and races

SQLite `BEGIN IMMEDIATE` atomically binds delivery operation to exact envelope,
payload digest and resolved route. That attempt is committed **before** any send.
The single newly reserved path can call the provider once. Every existing attempt,
including failed, rate-limited, interrupted or uncertain attempts, goes exclusively
to readback. The journal does not retry sends, expire/delete reservations or grant
a new delivery operation. Core must define any future safe retry protocol.

The journal stores synthetic provider status (attempted, accepted, unknown,
rate_limited, failed), acknowledgement identity, last exact observed identity,
retry metadata and a retained conflict flag. It never stores or emits core's
Delivered state. Payload text and attachment bytes are not retained in the journal;
callers re-supply digest-matching content on recovery. Binding columns cannot be
updated and rows cannot be deleted through normal SQL. This is a bounded API, not
a protection against a privileged actor editing the SQLite file/schema.

Acceptance is distinct from exact readback. A successful lookup requires exactly
one full destination/operation/content/attachment match. Missing, malformed,
partial or wrong-thread observations stay unknown. Conflicting exact receipt IDs
against an acknowledgement or previous observation permanently fence that
operation; subsequent apparently good readback cannot clear the conflict. A
concurrent readback may observe an empty provider store while send is in flight;
it remains unknown and can later read back again without sending.

Provider exceptions/malformed acknowledgements become unknown. Cancellation or
process death after reservation retains the fence, including the conservative
case where no provider call actually happened. 429 records `retry_at` but does not
schedule or retry. A valid failed-before-effect response is recorded without
assuming any retry permission. Core remains the owner of deciding what follows.

## Reproducible evidence

Run `python3 tools/validate.py && python3 -O -m unittest discover -s tests -v`.
Only Python/SQLite standard library is needed. New tests use the existing FakeSlack
through a test-only separate SQLite destination adapter. Destination message bytes,
exact route and actual send-call rows are independently queried. Both journals are
real disposable SQLite files; the provider store is synthetic, not a real service.

Fresh processes exercise a hard exit after committed destination effects, restart
readback, retained conflict fences, rate-limit non-retry and competing first-send
writers. Separate tests exercise cancellation, denied/revoked authority (including
during readback), stale/deleted admission, conflicting routes/content/envelopes,
partial artifacts, malformed/ambiguous readback and transaction failure. A source
mutation replaces existing-attempt reconciliation with send; the independent
provider store exposes two sends and two destination effects. Network connections
are forbidden in the test processes. Temporary directories, closing handles and
bounded child termination/reaping provide cleanup.

Still blocked/not run: actual core transport/receipt mapping and authority bridge,
native Rust integration/toolchain, general multi-attachment delivery, safe retry
protocol, production sanitation, authenticated provider readback, real Slack/native
sessions, runtime activation and deployment. Existing source/native capability
fixture work in PR #14 is neither duplicated nor required by this component.
