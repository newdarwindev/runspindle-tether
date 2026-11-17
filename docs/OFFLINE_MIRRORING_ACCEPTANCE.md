# Offline mirroring campaign acceptance

Scope: Tether #1's synthetic transport and disposable durable-store harness.
This is not live Slack qualification, a new Slack relay, a Core outbox, or a
production retry policy. The artifact-only `ProviderJournal` retains its existing
reservation and no-blind-resend rules. The additive campaign is an explicitly
OFFLINE test adapter for progress send/update/delete behavior.

## Existing contracts reused

| Issue deliverable | Existing entrypoints and independent assertions |
|---|---|
| Fake send/update/delete/readback, exact route, request history and destination store | `tether.testing.FakeSlack`; `test_fake_transport.py`: exact readback, update/delete identity, wrong scope and wrong-thread collision tests |
| Exposed native events and capability/availability matrix | `tether.native_testing.NativeSource`; `test_native_source.py`: all public kinds, unsupported/final-only/snapshot-only, stale/unbound/disconnected, binding and clock tests |
| Authenticated duplicate/edit/delete/revision admission and echo rejection | `test_admission.py`, `test_slack_ingress.py`, `test_slack_revisions.py`: authority, exact scope, ordering, restart, tombstone and mirror-echo tests |
| Fault classes and unknown readback | `test_fake_transport.py`: 429, before-effect, lost acknowledgment, malformed and partial results, absent/ambiguous/wrong-thread readback |
| Existing artifact reservation durability | `test_provider_journal.py`: actual SQLite reservation, fresh-process crash/recovery, competing first sends and independently observed resend mutation |
| Whole-envelope canaries and truthful capabilities | `test_sanitization.py`: nested errors/URLs/attachments, secret authority metadata, receipt identifiers, persisted/output scans and deliberate bypass mutation |

These tests are reused, not reinterpreted. In particular, signed raw Slack
edit/delete events with unprovable actual actors remain deny-only. The synthetic
admission fixtures do not solve that live actor-attribution prerequisite.

## Additive functional gap

The new campaign must connect bounded virtual-time scheduling, sanitized durable
queueing, exact progress update/delete readback, restart/concurrent owners and
separate observation/admission/acknowledgment/confirmation counters. Existing
artifact-send tests alone do not prove these progress-operation properties.

A retry is eligible only under the fake transport's explicit no-effect 429
contract. Any reserved, interrupted or unknown operation must reconcile instead
of sending again. Missing/ambiguous/mismatched readback cannot authorize resend
or advance an uncertain predecessor. Callback completion and transport acceptance
are not destination confirmation.

Independent destination state and request history must survive the tested
restart boundary. Recreating an empty fake peer, or inserting expected effects
into a new peer, is not evidence of recovery. Tests of the new mutable-message
lane must exercise its actual durable store in fresh processes where claimed.

## Counter interpretation

Source observations include capability/availability rejections before the
campaign sink runs. Campaign admission observations are a separate population.
NativeSource's `submitted` outcome means only that its sink returned, not that
queueing or destination delivery succeeded. Distinguish unique queued origin IDs,
rejected admission observations, dispatch reservations, acknowledged sends and
exact destination confirmations. After an effect followed by a crash/lost
acknowledgment, the acknowledged-send count can be lower than actual effects;
independent provider observations must make that gap explicit.

## Additive acceptance evidence

All following cases are in `tests/test_offline_campaign.py`; the independent
provider backing is `tests/offline_destination_peer.py`.

| Requirement | Observed tests |
|---|---|
| Bounded virtual queue, no early retry, exhaustion and capacity | `test_429_virtual_retry_is_bounded_and_never_early`, `test_429_update_delete_retries_only_no_effect`, `test_capacity_and_unsupported_fields_fail_closed` |
| Lost acknowledgment, absent/ambiguous/wrong-thread readback and malformed replies | `test_lost_ack_missing_ambiguous_wrong_thread_never_resend`, `test_contradictory_reply_fields_never_retry_or_skip_unknown_effect` (11 contradictory shapes) |
| Exact progress updates/deletion and terminal ordering | `test_ordered_update_delete_exact_readback_terminal`, `test_before_effect_failure_is_terminal_not_a_blind_retry` |
| Actual-store crash/restart and concurrent writers | `test_fresh_process_persistence_checkpoints`, `test_fresh_process_exit_after_fence_never_dispatches_on_restart`, `test_fresh_process_after_send_update_delete_effects_recover_exactly`, `test_concurrent_connections_deduplicate_and_dispatch_once` |
| Before/after persistence, provider effect and receipt boundaries | `test_crash_checkpoints_preserve_effect_and_fence`, `test_before_persist_rollback_and_after_receipt_durable`, `test_before_receipt_interruption_retains_unknown_and_only_reads_again` |
| Exact counters, sanitized persistence and source distinction | `test_native_source_sanitized_queue_and_distinct_accounting`, `test_source_observations_are_separate_from_campaign_admission`, `test_provider_identity_canary_is_never_persisted` |
| Independent negative oracles and damage/race admission | `test_unknown_resend_source_mutation_causes_independent_duplicate_effect`, `test_existing_damaged_schema_or_metadata_never_repairs_after_effect` (seven damage cases), `test_pending_ack_blocks_concurrent_confirmation_and_successor`, `test_same_instance_reentrancy_cannot_rollback_outer_dispatch` |

The deliberate resend mutation produces two independently observed destination
effects instead of one. The normal implementation remains readback-only. Fresh
processes exit after real fake-provider send/update/delete effects; independently
committed destination records are queried before recovery. Process interruption
is not power loss, and this does not qualify arbitrary filesystems or privileged
row rewriting.

## Reproduce the complete issue acceptance set

From the repository root, with Python 3.12+ and no account or provider token:

```sh
PYTHONPATH=tests python3 -B -m unittest \
  test_admission test_admission_authority test_error_boundaries \
  test_fake_transport test_native_source test_offline_campaign \
  test_percent_case test_provider_journal test_sanitization test_schema \
  test_semantic_journal test_slack_ingress test_slack_revisions \
  test_source_observation test_shared_fixtures test_shared_fixture_upgrade
```

Repeat with `python3 -B -O -m unittest` and the same modules. Both runs passed
**220 tests, zero skips**. These 16 modules cover every issue #1 requirement;
HTTP/live-adapter and visual qualification are separate. The new campaign's 22
tests also passed independently in both modes on Strix with Python 3.14.8.
All stores are disposable, threads/processes have deadlines and cleanup, virtual
time starts at 100, and new test parents/children deny socket connections.

Exact implementation source: `02ec6ff4421fc3c803097901fc026f837ef0020c`, tree
`7599b753ec547831148d87c7d0928fe9dd0230a1`. Source, fixture and toolchain hashes
are recorded in [the receipt](offline-mirroring-evidence.json). Independent review
approved the code and criterion coverage, including fixes for schema repair,
pending acknowledgements and contradictory replies. Historical audit results
were not regenerated; only current metadata hashes have explicit continuity.

## Broader checks and limits

- Full normal suite: **472 tests, one existing optional native-browser skip**.
- Full optimized suite: **472 tests, two HTTP-loopback errors and that same
  skip**. `test_cancel_after_connect_no_effect_and_cleanup` and
  `test_cancellation_messages_are_sanitized_after_cleanup` raised
  `HTTP outcome unknown`. Both passed a separate optimized targeted rerun
  (2 tests). This does not turn the failed broad run into a pass or prove its
  root cause. Those source/test files are unchanged from the base.
- New-file Ruff, strict mypy, scaffold, artifact and mirroring-integrity checks
  passed. Required static quality is blocked by the missing repository-local
  ESLint package/toolchain. No debt baseline, deadline, check or invariant was
  weakened to obtain a pass. Required aggregate is therefore not green.
- Full-suite migration prerequisite is a clean existing checkout at
  `040b71f2213a34f34e6b6a40124ed1164b93ce30`, supplied through
  `RUNSPINDLE_TETHER_V1_SOURCE`. It is not fetched implicitly or repinned.

Closure scope is the offline test-harness issue #1 only. Live Slack, production
native capabilities, credential helpers, production retry permission, Core
outbox integration, runtime activation and deployment remain unqualified. No
broader functional/live issue inherits this fixture success.
