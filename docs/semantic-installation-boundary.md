# Semantic journal installation boundary

`SemanticAdmission.snapshot_batch` binds every retained candidate's source
`app_id` and `account_id` to the opened store configuration before exporting a
batch. `pending_batch` and `reconcile_retention` use that same checked snapshot;
a misbound chain cannot invoke the retention readback callback or write a receipt.

A candidate can be internally well formed while belonging to another
installation. Previously, an intact chain combined with a coherently rebound
`intent_config` could pass the independent configuration and chain checks. The
new comparison detects that restore/configuration mismatch. This is not a
signature, external anchor, or protection against an attacker able to rewrite
all database contents and trusted configuration coherently.

## Reproduction and local evidence

`test_foreign_store_identity_rejected_before_export_or_readback` retains a real
SQLite semantic candidate, changes only the store configuration, and reopens it
under that changed configuration. It exercises app and account independently:

- snapshot and pending exports reject;
- retention reconciliation rejects before the synthetic readback is called;
- the complete database dump stays unchanged;
- a fresh Python process also rejects pending export;
- restoring the original configuration preserves the positive export case.

The regression fails against the pre-fix implementation. Component and full-suite
results are recorded in the PR. Fixtures, authentication and Core readback are
synthetic; SQLite, codecs and subprocess execution are real. No live Slack,
issuer, Core dispatch or external delivery was exercised.

## Remaining admission work

This advances the exact source binding required by #8; it does not close #8.
The existing signed-edit lane and deny-only source-observation lane remain
separate. Source-observation consumer enforcement, actor-attributed deletion,
and integrated/live acceptance are not implemented by this change. No schema,
grant, dispatch semantics, or legacy-store adoption is changed.
