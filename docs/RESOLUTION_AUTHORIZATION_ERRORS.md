# Sanitized resolution authorization failures (partial Tether #10)

The existing explicit conflict-resolution authorizer now follows the fixed-error
boundary already used for wire request authorization. Ordinary callback errors
become a fixed denial. Async cancellation, generator exit, keyboard interruption,
system exit and other base exceptions retain their cancellation category with a
fresh fixed message, raised outside the original handler. Callback text, notes,
causes and contexts are not propagated.

The existing full decision binding, current-authority checks, immutable conflict
snapshot, append-only decisions, selected file/message matching and readback-only
behavior remain unchanged. Denial before readback makes zero provider calls.
Cancellation after readback or inside the commit lock leaves no decision and
releases/rolls back the actual SQLite transactions. Existing uncertain-readback
semantics and no-send/no-resend safeguards are preserved.

Tests use synthetic secret canaries, actual SQLite stores and an independently
recorded fake-wire effect ledger, with network denied. They inspect exceptions
and raw store files, reopen the decisions database, and remove the exception guard
in a deliberate mutation to demonstrate observable leakage. Normal and optimized
Python behavior is tested.

This is a callback boundary fix, not universal secret discovery. Debugger/frame
locals, hostile callbacks that deliberately transmit/log data, arbitrary caller
exception context, current production authority and live Slack remain outside the
claim. Tether #10 remains open for its real-adapter/production qualification.

```
python -m unittest tests.test_wire_resolution
python -O -m unittest tests.test_wire_resolution
python tools/validate.py
```
