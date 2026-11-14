# Synthetic native-event capability fixture

Partial test infrastructure for Tether #1 and the capability obligations of #2/#10.
No parent issue closes. This is original Python standard-library test code, not
an imported runtime adapter, production wire schema or live-session integration.

## Entrypoints and limits

`tether.native_testing.NativeSource` accepts one immutable synthetic binding
(task, host, native session, exact workspace/channel/thread), capability mode,
injected integer clock, freshness bound and observation capacity. `Event` holds
that binding, event ID, positive sequence, observation time, exposed kind and
an existing `tether.testing.Payload`. Use invented, already sanitized fixture
content only. This layer does not implement whole-envelope sanitization or
credential handling. Existing ingress authentication and SQLite revision storage
are not duplicated or connected to execution.

The source is synchronous and process-local, with no thread/process concurrency
or restart guarantees. Its source binding and mode have no public update method;
constructing a replacement source resets history and is not durable deduplication.
Caller-supplied objects and callbacks are trusted test code, not authenticated
native observations. This fixture must not be installed as an authorization gate.

## Capability matrix

- events: lifecycle, public_summary, tool_start, tool_update, tool_complete,
  result, error, final and usage.
- final_only: final only; usage/tool/progress events remain unsupported.
- snapshot_only: snapshot only; it stays a snapshot, never a reconstructed event
  stream or transcript.
- unsupported: no emission.

Each mode independently exposes bound/unbound/stale/disconnected availability.
Hidden reasoning and unknown kinds are unsupported in every mode. The matrix
always reports synthetic evidence, no control capability and live coverage not_run.
It describes fake configurations, not measured capabilities of real adapters.

## Emission semantics

Every call checks exact binding, mode, availability and freshness before invoking
the caller-provided fake sink. Future or older-than-budget observations are stale.
Malformed fields and exhausted capacity raise fixed-category errors without a
callback. Valid-but-disallowed observations record a fixed outcome without raw
payloads. Histories are bounded and returned as immutable snapshots.

Only the next contiguous sequence and a new event ID can be submitted. Gaps are
rejected without advancing; replays after accepted submission are duplicates.
Rejected observations can be retried after prerequisites change, provided capacity
remains. A reconnect does not reset the sequence or IDs. This is fixture-local
ordering, not a shared protocol, replay service or durable outbox.

An accepted attempt is consumed and recorded unknown **before** the sink is called.
A normal callback return becomes submitted, never delivered or confirmed. An
exception remains unknown; its text is not retained. Cancellation propagates while
preserving unknown. Reentrant emission is rejected. No automatic retry, readback,
provider cancellation or network call exists. This prevents the fixture itself
from repeating a possibly accepted effect but is not real recovery orchestration.

Tests compose the sink with the existing FakeSlack, then independently count its
requests and destination records. They do not interpret NativeSource's own result
as independent destination evidence. A source mutation removing availability
rejection causes a forbidden destination effect detected by those counters.

## Reproduction and remaining acceptance

Run `python3 tools/validate.py` and
`python3 -O -m unittest discover -s tests -v`. The focused suite is
`python3 -m unittest tests.test_native_source -v`. Fixed clock starts at 100;
message/event IDs are deterministic counters. Socket connections are forbidden
in the tests. Mutation source exists only in a disposable temporary directory.

Still blocked/not run: root #43/core #16 production contract and authority
integration; real native/host capability discovery; whole-envelope production
sanitization; core-owned durable outbox/reconciliation; concurrency and restart
recovery; provider receipts; UI qualification, live acceptance and deployment.
No runner policy, source-import scope, credentials or service settings change.
