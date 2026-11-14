# tether specification

Status: planned contract, implementation and live acceptance not verified.

## Responsibility

Existing Tether integration boundary for sanitized Slack event delivery.

## Shared identifiers

Correlate task, intent revision, selected host, native session, browser instance, lease epoch, trace/span, artifact digest and Slack destination without placing credentials or raw private content in public receipts.

## Required behavior

Preserve explicit authority and unknown outcomes. Distinguish request admission, execution, validation, acceptance and delivery. Exact state transitions belong in component-specific specs added beside this file.

## Acceptance

1. Unit/contract tests with synthetic data.
2. Isolated integration tests against pinned upstream dependencies.
3. Bounded live acceptance in an authorized target.
4. Failure, restart, uncertain-effect reconciliation and rollback evidence.

None of these product gates has been run for this scaffold.

See the [mirroring acceptance contract](../docs/MIRRORING_ACCEPTANCE.md).

## Engineering direction

[Desired intent](desired-intent.md) connects this component to scoped access,
managed sessions, explicit human exceptions and evaluated maintained workflows.
It adds design and verification obligations without changing runtime schemas,
existing acceptance results or operational permissions.

## Bounded ingress library

[Authenticated ingress and durable revisions](admission-v1.md) documents the
original Python library seam and synthetic SQLite tests. The complete runtime
adapter and live transport remain unimplemented; this does not supersede the
product acceptance gates above.

## Synthetic outbound transport test seam

[The process-local transport fixture](synthetic-transport-v1.md) provides exact
routing and fault-injectable send/update/delete/readback tests. It does not own
core outbox persistence, retries or real provider integration.

## Durable provider-attempt component

[Provider attempt journal](provider-journal-v1.md) adds SQLite send fencing and
exact synthetic readback beneath the core-owned outbox. Native integration,
automatic retry and live-provider acceptance remain blocked/not implemented.

## Synthetic native-event test seam

[Capability fixtures](synthetic-native-events-v1.md) model exposed event, final-only,
snapshot-only and unavailable sources. They do not qualify real native adapters.

## Bounded sanitized event projections

[Sanitization v1](sanitization-v1.md) defines nested event projection limits,
configured-secret redaction, guarded SQLite persistence and escaped rendering.
It preserves existing capability truthfulness and rejects dirty immutable
admission/delivery identities or accepted bytes instead of rewriting authority.
It is not universal secret discovery or full production qualification.

- [Retained feedback evidence](retained-feedback-evidence.md): exact authenticated
  target bindings, immutable local history and separate consent boundaries.
