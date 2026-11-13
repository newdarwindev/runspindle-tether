# Pinned synthetic fixture conformance

Partial work for [issue #1](https://github.com/newdarwindev/runspindle-tether/issues/1); the full component harness remains open. The original synthetic test-only subset is copied without modification from composition commit `e8cd5779968fede213443db13a591c992cd0e183`, `fixtures/v1`. No legacy code, private source, credentials or runtime adapter is imported. Source status and opaque historical provenance remain unchanged.

`fixtures/shared-v1.pin.json` pins the source repository/commit, schema, component and origin/subset manifest SHA-256 values. The consumer verifies the independent reviewed pin chain and all file hashes before importing the vendored validator. Changing content and rehashing the local manifest alone does not update the reviewed pin. Pin changes require source/compatibility diff review and old/new vector testing; internal hash consistency is not source authentication.

Run with preinstalled Python >=3.9, no sibling checkout, package installation or network:

```sh
python3 tools/check_shared_fixtures.py
python3 -m unittest discover -s tests -v
python3 tools/check_scaffold.py
```

Golden envelopes are checked against independent original identity/state/receipt observations. Every applicable negative vector must fail with its specified error; corrupted validator bytes, a self-rehashed changed manifest, wrong origin pin and an unexpected bundle file are separate negative regressions. Tests deny socket construction and assert zero network calls. Temporary fixture copies are removed after positive and exceptional tests. No child processes or services are started. Fixed fixture IDs/time and source seed 90210 are synthetic. Exact input hashes/tool versions and commands are recorded in `shared-fixture-evidence.json`.

This is Python fixture-format conformance only. No cross-language/runtime producer-consumer mapping, authenticated authority, external effects, durable restart, upstream compatibility, isolated integration, GitHub CI, live acceptance or deployment is established. Operational acceptance entrypoints and workflows are unchanged.

Remaining #1 blocker: Existing Tether source and exact runtime/event/transport contract are not present. Authenticated sender authority, durable journal/outbox, rate-limit/send/readback reconciliation and sanitization adapters are unimplemented. No Slack subsystem or relay is introduced. The test schema is provisional and does not decide these runtime interfaces. Fixture pins can be consumed in isolation; actual component adapter suites must be implemented and reviewed separately. No passing fixture can replace their blocked gates.
