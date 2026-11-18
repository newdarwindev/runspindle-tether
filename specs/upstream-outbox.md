# Original upstream output ledger: bounded integration

The `runspindle_tether.upstream_outbox.Outbox` policy uses the pinned original
Tether `BridgeDelivery` SQLModel and `bridge_deliveries` table. It introduces no
second database or delivery service. Upstream owns database creation/migration;
the adapter refuses an absent database and never initializes its schema.

An authenticated `VerifiedAction`, exact payload digest and current authority are
required. The owner-issued workspace/event identity has one immutable reservation,
including actor, destination, session, host and lease epoch. Before any route call,
a SQLite writer transaction records `runspindle_unknown`, attempts=1. There is no
blind retry, even after a lost acknowledgement, cancellation, process reopening,
or a denied callback after reservation. Duplicate calls only perform separately
authorized readback. Conflicting terminal readbacks produce a sticky conflict;
an unknown fresh readback does not reuse historical confirmation as current proof.

Reserved statuses are not eligible for the original pending/sending retry worker.
The original worker remains disabled for protected output. Its automatic retries,
scalar callbacks and logging exception text are **not** adopted. The adapter
consumes original routing through the existing scoped `AuthorityGate`/`Sidecar`
seam, not arbitrary upstream app startup. No original platform SDK send, account,
IPC endpoint, native runner or production transport is qualified here.

## Boundary and privacy

This is a trusted-process integration, not a sandbox against arbitrary code with
access to the original database. Upstream administrative methods can rewrite rows
when called directly; only this policy may own protected rows. Authorization and
readback callbacks must be trusted, side-effect-free authority observations; they
must validate original source, current lease and exact destination. Rechecks catch
observed revocation and mutable payload changes but do not promise a distributed
atomic permission fence. Transport return is never proof of delivery.

The original table retains the authorized final output and its exact binding.
It must have the same private retention/access policy as the original upstream
session store. No raw thinking, tool output, credentials or exception strings
belong in that payload. Interrupted sends/readbacks expose only a fixed exception,
without retaining its secret-bearing exception chain. The adapter has a 64 KiB
binding bound and 1,024 protected-row capacity; it denies capacity overflow and
never silently evicts retained uncertainty.

## Evidence and remaining migration

`upstream/tests/test_outbox.py` runs actual original SQLModel models, Alembic
migrations, SQLite transactions, worker claim methods and BridgeManager routing
with synthetic effects. Tests cover exact conflicts, unknown-before-route,
readback-only reopening, sticky conflicting evidence, callback mutation/revocation,
no database bootstrap, capacity and interruption privacy. They are not live Slack
acceptance or full migration proof. Generic upstream singleton startup occurs only
in a temporary synthetic database test of original worker exclusion.

Do not delete compatibility effect/feedback code yet. Authenticated process IPC,
original platform transport privacy and independent readback, replacement of old
owner paths, supported surface parity, source revocation/feedback consent, process
crash races and full mandatory CI remain separate gates. No production activation
is implied by these component tests.

### Upstream ordinary lifecycle is not admitted

The pinned original `SessionStore.delete_session` and `clear_all_data` delete
associated delivery rows, including protected states. These ordinary deletion /
retention paths must remain disabled for protected sessions, not merely avoided
by convention in a live app. This adapter does not install that lifecycle hook.
An owner retirement/tombstone contract and a regression against the actual deletion
path are prerequisites before enabling the upstream application. If history is
lost, reconciliation denies; a new submission cannot distinguish prior history
loss from a genuinely new event, so the trusted owner must deny retired operations.
The test explicitly demonstrates original clear-all deletion and owner retirement
denial; it does not claim resilience to arbitrary history erasure. No ordinary
upstream lifecycle or production startup is enabled by this slice.
