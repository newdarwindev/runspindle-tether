# Fail-closed original SessionStore retirement hooks

The pinned original `SessionStore.delete_session` and `clear_all_data` erase
`BridgeDelivery` rows as part of ordinary lifecycle. That would erase the evidence
preventing an unknown effect from being submitted again. No new database or
retirement ledger is introduced to compensate for it.

`runspindle_tether.upstream_lifecycle.protect_session_history()` instead replaces
these two class entrypoints with a fixed, sanitized denial. Existing and future
original store instances are covered; repeated installation is idempotent. It
performs no retention queries, so there is no check-then-delete race. It disables
**all** session deletion/clear-all in this isolated process, including sessions
without protected outputs. No automatic eviction, backup, retirement authority or
uninstall is supplied. This deliberately trades deletion availability for retained
uncertainty until an owner-authorized retirement/tombstone protocol is qualified.

The trusted composition root must initialize and verify the pinned original app,
install this hook before binding any handlers/method references, and prevent other
code from retaining old method references or replacing class methods. Importing the
original store constructs its singleton; the hook is not a launcher, source
verifier, sandbox or defense against arbitrary SQL writers. Existing SQLite files
and credentials remain owned by the original application. No production startup
or persistent service is enabled here. Ordinary updates/readback remain original.

Two fresh-process tests exercise original migrations/models/store/outbox: an
unmodified clear-all really erases a synthetic protected row (negative control),
whereas installed hooks deny both APIs for existing and future original instances
without changing the row or session. They also verify no private exception chain
escapes the denial. These are actual upstream API tests with synthetic effects,
not live application retirement or complete migration qualification.

The remaining gates are original app composition with authenticated IPC, actual
single-attempt provider transport/readback, supported surface parity and deliberate
retirement semantics. Compatibility code is not removed by this slice.
