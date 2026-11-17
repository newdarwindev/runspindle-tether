# Exact Slack wire delivery beneath Core's outbox

This additive component is not live-provider qualification. Core remains the owner
of accepted artifact bytes, destination authority, delivery attempts, and Delivered
state. `WireDeliveryJournal` accepts an exact canonical legacy delivery-request
wire plus the exact sanitized artifact payload, current retained Admission, current
Core authorization, exact account/destination routing, and per-request authority.
There is no default credential source, transport, worker, or retry scheduler.

## Separate evidence and persistence

The wire family uses SQLite application ID 1414135815 and cannot adopt the
synthetic ProviderJournal family. It invokes the existing UploadJournal wire
protocol, not synthetic Reply/Record adapters. `content_confirmed` means matching
file bytes, filename, channel, thread, file identity, and message identity were
independently read back through the configured wire transport. The fixed evidence
class is `slack_wire_content_observation`; it is not a Core Delivered receipt.
The injected transport and authority implementations remain explicit trust seams.

An outer immutable reservation is committed before the inner upload begins. Only
its winning caller can invoke inner send. Every subsequent caller invokes lookup,
including when a crash left no inner reservation. Such a gap remains unknown and
cannot be resumed by this API. Allocation, upload, and completion remain bounded
by UploadJournal's durable phase fences. Lost acknowledgments, cancellation, 429
responses, partial bytes, and missing readback never grant an additional attempt.
Retry metadata is diagnostic only, never permission to retry.

All callers for one operation must share both database paths. Neither store may
be copied, restored, or replaced to acquire a new attempt. Operation bindings,
allocated identities, observed identities, and conflicts are immutable/sticky.
Each wire request rechecks current admission, exact bytes, account/destination,
Core authorization and both journals' retained conflict, including after the
request authorizer returns. Missing or changed authority fails closed.

After provider observation, retention acquires the outer write lock followed by
the inner write lock, refreshes the exact inner record, and holds it until the
outer record commits. No network is performed under either lock. This prevents
publishing a stale successful observation after a concurrent inner conflict has
already committed. It does not make external provider state or authority changes
atomic with future effects. A later independent observation can still reveal a
conflict; Core must retain/quarantine that conflict rather than erase it.

## Verification and limits

`tests/test_wire_delivery.py` exercises actual Admission, WireDeliveryJournal,
UploadJournal and wire parsing with an independently persisted SQLite fake HTTP
peer. It checks exact provider calls and durable effect counts, fresh-process
recovery, competing callers, before/after interruption, cancellation, 429, wrong
thread, partial content, binding changes, revocation, sticky conflict, and an
unsafe retry mutation. These are controlled offline tests, not a Slack workspace,
credential, permission, TLS/network deployment or filesystem power-loss proof.
Core adapter composition and independent review are required separately; this
component test suite alone does not close Tether #9 or its parent requirements.
