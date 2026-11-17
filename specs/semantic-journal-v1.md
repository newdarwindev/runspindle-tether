# Atomic semantic journal and batch recovery v1

This separate store lane contributes to Tether #8. It does not migrate legacy
stores, infer new grants, provision an issuer, subscribe to Slack, submit work,
or claim production acceptance. Raw Slack edit/delete attribution remains
unsupported and deny-only. Core's independently implemented atomic batch lane is
required; do not send these entries individually through an executable admission.

## Atomic ingestion and isolated store family

`SemanticAdmission` explicitly opens SQLite family `1413545987`, version 1.
Its schema includes existing admission tables plus immutable `intent_config`,
`intent_candidates` and `intent_observations`. The existing exact-family schema
checker rejects legacy and unknown stores without altering them. Trusted app and
account configuration is retained and checked on reopen and journal operations.
No legacy admission-family adoption, field inference or legacy task migration
occurs. The shared schema opener retains its existing exact-schema initialization
semantics; unknown or mismatched layouts reject.

The existing `Admission.ingest` verifies transport identity, resolves current
raw-ingress authority, locks its transaction, rechecks authority and enforces
source/event deduplication. An internal transaction hook retains the semantic
candidate before that SAME transaction commits. The legacy implementation of the
hook deliberately does nothing and preserves the legacy store and wire contract.
The new lane's hook fails the whole admission on any semantic/reference error.
There is no gap where admission is committed without its semantic candidate.
A duplicate checks the existing immutable candidate and never changes references.

Trusted application wiring supplies app/account and an `IntentReferences`
callback that explicitly returns a new v3 grant reference and delivery operation.
References are not permission or assertions. Reusing the raw ingress grant
reference rejects. A separate issuer must bind the latest full semantic wire to
fresh authority; no keys or assertions are discovered, stored or logged here.
The deterministic task ID and exact source, host, workspace and lease binding
are enforced. Policy revision may change under fresh explicit authority.

The journal retains canonical candidate bytes, their SHA256 and the original
raw-ingress SHA256, but no raw content. Per-intent sanitization checks exact
metadata without changing identity. There are at most 64 executable revisions
and one reserved final deletion. Revision 65/edit rejects atomically; revision
65/delete remains possible. The legacy admission capacity is unaffected.

`SignedSemanticIngress` reuses the existing signed ordinary-message verifier and
instance-bound proof, selecting only the new store family. Signed create and
retries reach the journal. Raw `message_changed`/`message_deleted` remain rejected
before authority resolution; the original message author is never inferred to be
the actor who edited/deleted. There is no HTTP server or live provider setup.

## Complete atomic batches, not sequential replay

`snapshot_batch(task_id)` uses one read snapshot to validate retained candidates,
raw digest/envelope/delivery/source bindings, current head and mirror exclusion.
It returns canonical:

```json
{"version":"runspindle.intent-batch.v1","intents":["full intent objects, not strings"]}
```

The actual `intents` array contains full objects from revision 1 through the
current head, with identical source, fixed host/workspace/lease, distinct operation
IDs, unique provider event IDs across the entire chain (even if a grant changes
delivery namespace), and exact predecessor request/full-wire hashes. Batch size is bounded to
1 MiB. A deleted head is terminal. A process can reopen and reconstruct the exact
complete batch without raw input or prior exports, including a missed create/edit
prefix followed by deletion. No regeneration of grant or operation identity is
permitted on retry.

Core must independently validate all bytes and exact accepted prefix, verify
current v3 authority for the latest intent (plus cancel permission for deletion),
then atomically install the chain before scheduling. Missing historical members
are superseded metadata, never executable intermediate jobs. Only the latest
permitted non-delete intent can execute. A deletion may cancel only the exact
ancestor proven by the chain, retaining unknown native cancellation outcomes.
This file documents a dependency requirement, not proof that Core executed it.

The legacy current-head-only `export_retained_intent` still cannot recover missing
history from an old store. Its explicit fail-closed limitation is unchanged.
The new family solves retention for newly ingested semantic events; it is not a
retroactive repair of information that legacy stores never retained.

## Lost responses and exact readback

`pending_batch` returns the exact current complete batch until a trusted Core
readback confirms retention. `reconcile_retention(batch, readback)` calls only an
explicit trusted read-only helper; absence, failure or mismatch leaves pending
state unchanged. `pending_batch` returning None describes only its captured
revision; a concurrent newer admission requires another poll and is not globally
acknowledged or drained. It accepts exactly:

- `status`: `retained`, never executed/delivered/cancelled;
- `workflow_id`: `intent-` + SHA256 of canonical array
  `[app_id, account_id, workspace_id, deterministic_task_id]`;
- `revision`: the submitted batch's last revision;
- `batch_sha256`: SHA256 of the complete submitted canonical batch.

Core readback must establish that the supplied batch is an exact retained prefix.
An observation is retained under its exact task/revision and cannot acknowledge a
later head. Late acknowledgments and duplicate readback are safe; history is not
removed. After a lost submission response, use the same immutable batch for query
reconciliation rather than issuing a new operation or manufacturing success.
Neither method submits or automatically retries anything.

A local read snapshot is not an end-to-end atomic freshness fence. A new local
revision may commit after a batch is exported or submitted. This does not revoke
an already authorized earlier submission at the remote boundary. Core's current
authority and state fencing remains required; local deletion alone never proves
remote cancellation. There is no exactly-once external-effect claim.

## Verification

Base prerequisite: Tether PR #38, producer commit
`e7c46a9c61a8a8a20bacc5f7d60f8724ffff1da6`.
Independent single and batch vectors live in `conformance/intent-v1` and
`conformance/intent-batch-v1`. Core qualification must pin both final source heads
and these exact artifact hashes.

Run with the exact prepared legacy fixture required by the existing full suite:

```sh
export RUNSPINDLE_TETHER_V1_SOURCE=/path/to/clean/prepared/tether-v1
# Exact fixture revision: 040b71f2213a34f34e6b6a40124ed1164b93ce30
python3 tools/check_scaffold.py
python3 -m unittest tests.test_intent tests.test_semantic_journal -v
python3 -O -m unittest tests.test_intent tests.test_semantic_journal -v
python3 -m unittest discover -s tests
python3 -O -m unittest discover -s tests
```

Tests use real SQLite, fresh child processes, and independent database readers.
Authentication/authorization and Core readback are explicitly synthetic callbacks;
signed-create tests exercise the actual HMAC verifier with synthetic signatures.
No socket/provider is allowed. A deliberate missing-hook mutant must fail an
independent SQL assertion. Process termination after candidate insertion but
before commit proves both records roll back together. Missed prefix exports,
reserved deletion capacity, wrong/absent/lost/late readback, concurrent newer
local ingestion and immutable identity reuse are tested. Native effects and
production transport/issuer compatibility remain separate qualification gates.


## Global provider event ownership correction

Provider event identity is unique across the entire app/account-bound semantic
store, not merely one task or one delivery namespace. The semantic transaction
hook queries every retained delivery with that event ID and requires exactly the
current namespace/digest row. A fresh grant choosing another namespace cannot
reuse an event for a different message/task. The whole competing admission rolls
back, including source, head, delivery and candidate rows. Exact repeated
namespace/event/digest requests remain duplicate without rewriting history.

Snapshot/export also checks this store-global ownership. A pre-fix or corrupted
store already containing conflicting cross-task entries rejects affected
snapshots, pending queries and replays without repairing or deleting records.
No automatic migration or retroactive authorization is introduced. Independent
SQLite dumps prove failed admission/export does not change either existing task.
The maintained global-guard-removal mutant must fail the competing-source
regression by assertion, not by import or database error.

Providers whose event IDs are only unique in a narrower scope must have their
trusted authenticated adapter construct canonical scoped event IDs before this
lane. Changing a grant delivery namespace must not weaken this ownership rule.
