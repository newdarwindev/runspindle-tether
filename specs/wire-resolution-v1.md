# Explicit reconciliation of a quarantined wire delivery

This version adds `ResolutionJournal`, a separate append-only SQLite family
(1414135816). It never clears original upload/delivery conflict flags, changes
attempt ownership, or calls allocation, upload or completion. Ordinary delivery
lookup remains quarantined. This is not an automatic conflict repair policy.

A trusted application must supply a fresh dedicated resolution authorizer in
addition to current delivery/admission, route, artifact and exact-request
authority. Ordinary delivery authority alone cannot resolve a conflict. The
resolver callback receives the exact original envelope, normalized payload hash,
and canonical full decision. It must authorize that selection and current policy;
the module does not mint grants or choose a winning message.

The canonical decision contains version `runspindle.wire-resolution.v1`,
`decision_id`, `policy_ref`, `authorization_ref`, `conflict_sha256`,
`core_resolution_sha256`, `file_id`, and `message_id`. The Core digest binds its
full independently authorized ConflictResolution, including quarantined generation
and prior receipt history. Selected file must equal the original immutable
allocation. Selected message must be independently observed, not merely asserted.

`conflict_snapshot` returns canonical JSON with version, original envelope,
normalized payload digest, scope, and each store's retained file identity,
observed message identity and conflict flag. Retry delays are deliberately
excluded. Both original conflict flags must be retained; missing, unadmitted or
tampered upload schema is rejected. SHA-256 of these exact bytes is the generation
token, not a signature or substitute for dedicated authority.

Each call performs fresh read-only WireClient file/message/content observation.
Only one exact content match at the selected file/message can be confirmed.
Wrong thread, partial bytes, extra conflicting exact matches, changed selected
message or absent evidence remains unknown. Every request and final retention
rechecks both authorities and exact original context. Retention uses lock order
outer delivery, inner upload, resolution decisions; no network under locks.
The current decision becomes immutable, with one owner per operation and conflict
snapshot. Reuse of a decision ID for different bytes or competing decisions is
rejected, including concurrent callers. Lost responses can replay the same
immutable decision, but still require fresh authority and independent readback.

The resulting state is `independently_reconciled_under_decision`, with evidence
class `slack_wire_resolution_observation` and the exact decision digest. It is not
normal `content_confirmed` and not itself a Core Delivered transition. The Core
adapter must use the explicit authorized resolution API and independently read
back the decision, not treat a mutation acknowledgment as delivery evidence.

## Deliberate limits

No automatic supersession is defined. A later different Core generation cannot
reuse the old grant or install a competing decision for the same snapshot.
Ordinary Tether lookup remains sticky-conflicted even after a decision; a caller
must use the explicit decision-bound resolution lane, with fresh authority, not
silently reinterpret normal lookup. Provider/authority changes after the final
snapshot remain possible; database locks do not make external effects atomic.
Only controlled fake-provider qualification is planned. No credential, service,
network/security setting, live Slack integration or parent closure is implied.
