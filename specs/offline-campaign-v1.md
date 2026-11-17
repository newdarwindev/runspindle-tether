# Offline durable campaign fixture v1

Issue #1 test scope only. `tether.campaign_testing.OfflineCampaign` composes the
existing `NativeSource`, `Sanitizer`, and `FakeSlack` contracts using a disposable
real SQLite store. It is not another Slack relay, a production native adapter,
a Core outbox, or permission to retry real Slack operations. It never opens a
socket or resolves a credential. External callbacks and fixture providers are
trusted test code, not authenticated observations.

## Admission and accounting

A NativeSource checks capabilities and source availability before invoking its
sink. Its observation list is the native-origin accounting source. Unsupported,
stale, disconnected and other rejected source observations do not reach this
campaign. Source `submitted` means only that the sink returned: a full campaign
can reject that event even though the source records `submitted`.

Campaign counters are separate, persisted integers:

- `origin_observation`: all enqueue invocations committed, including replay and
  rejection. This is **not** all native-origin observations.
- `origin_event`: unique admitted event identities, excluding replays/rejections.
- `queued`: successful initial queue insertions; retries do not increment it.
- `rejected`: enqueue observations rejected for dirty content/identity, wrong
  binding, unsupported schema, duplicate/gap, capacity, or a terminal event.
- `dispatch_reserved`: committed invocation fences, including a possible crash
  before the provider is actually called. Not a count of destination effects.
- `sent`: accepted synthetic transport acknowledgements durably recorded. This
  is a lower bound after interruption and can be zero for a confirmed lost-ack
  effect. It is not proof of delivery or a precise count of effects.
- `destination_confirmed`: first exact independent readback per operation, with
  exact route, operation, message identity, payload/attachment bytes and deletion
  state. Neither acceptance nor a retry deadline increments it.

Tests inspect destination records and request history separately from these
counters. `FakeSlack` marks its records synthetic. No counter implies live or
upstream compatibility, execution authority, Core acceptance, or Delivered.

## Persistence, ordering, retry and crash semantics

Existing stores require exact current-family schema admission through the existing
`tether.schema.open_store`, plus read-only config/counter validation before any
writable open. Missing/extra/changed schema objects, missing/corrupt counters,
missing config and unknown versions reject without repair. Only an absent file
initializes; an existing empty file does not silently become a new campaign.

SQLite `BEGIN IMMEDIATE` serializes deduplication and queue selection. Binding,
queue capacity (1–1024) and retry bound (0–8) are bound to the store configuration.
The complete allowlisted projection is sanitized before rendering/persistence;
immutable IDs and attachment bytes must already be clean or are rejected. Raw
rejected input/error text is never persisted. Event sequence must be contiguous;
confirmed/failed rows remain retained for deduplication, so capacity is a total
campaign bound, not an eviction policy. Final/delete admission seals the campaign
against new events. A pending unknown blocks later operations.

Each `tick` performs at most one dispatch or one readback. A dispatch is fenced
as unknown **before** the provider callback. Crash, cancellation, malformed reply,
uncertain effect or missing/ambiguous/wrong-route readback cannot re-enable send.
Unknown rows remain readback-only even if no actual provider effect happened.
After committing that fence, a writer transaction spans the bounded synchronous
FakeSlack call and acknowledgement persistence. Readback/validation/receipt commit
also share a writer transaction. A concurrent reader cannot confirm an effect or
advance successors while its original acknowledgement is pending; a conflicting
late acknowledgement remains unknown rather than being ignored. Same-instance
reentrancy rejects before touching a transaction. This serialization is specific
to the offline synchronous fixture, not a proposed network/provider locking model.
Only the existing FakeSlack contract's explicit **no-effect** rate-limited reply
permits a retry after its injected integer clock deadline. There is no sleep,
background worker or production retry permission. The fixture exhausts after
`1 + retries` dispatches; a classified before-effect failure is terminal rather
than automatically retried. Subsequent operations may proceed after confirmed,
proven no-effect failure, or no-effect retry exhaustion; never after uncertainty.

Checkpoints before/after persist, before/after dispatch, and before/after receipt
support fault injection. Tests use close/reopen, concurrent real SQLite writers,
and bounded fresh Python processes exiting before/after initial persistence, after reservation and actual CRUD
effects. `tests/offline_destination_peer.py` is a thin persistence wrapper around
FakeSlack, not a new transport: it commits **actual** generated destination records
and request history to a separate disposable SQLite store before returning.
Fresh processes reload these observations, never reseed expected effects. The
parent directly queries this destination store before journal reconciliation.

The artifact-only `ProviderJournal` is unchanged. Its existing stronger rule
(all attempted sends, including 429, become readback-only) is not replaced by
this test campaign. Existing ProviderJournal tests qualify that separate lane;
they are not substituted for this fixture's update/delete recovery tests.

## Reproduction and limitations

Python 3.12 standard library, no provider account/token required:

```
python3 -B -m unittest discover -s tests -p test_offline_campaign.py -v
python3 -B -O -m unittest discover -s tests -p test_offline_campaign.py -v
python3 tools/check_scaffold.py
```

Seed: deterministic message counter, virtual clock initially 100, synthetic
route `workspace/channel/thread`, invented task/host/session. No randomness or
wall-clock sleeping controls delivery. Thread joins/subprocesses have deadlines;
all stores and subprocess workspaces are disposable. Socket connections are
default-denied in test parents and explicit child programs. This is bounded
synthetic/offline integration evidence only; no live mirroring, production
credential helper, real native event source or trusted provider readback is
qualified. The deliberate unknown-resend source mutant is rejected by independently observed
duplicate destination effects, not a self-reported success flag. Schema/metadata
damage after an effect must reject without repair or a second effect. Arbitrary
privileged row rewriting and filesystem replacement remain outside this fixture's
contract.
