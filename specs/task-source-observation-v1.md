# Deny-only observations of retained task sources v1

Partial #8/#10 work on reviewed source producer
3adbaa13d70d5daabad849c373283ba15d69b7ac. Runtime/test/tool source matches reviewed
4448e351ac599c4179317107ca2e7099cd74eea4; the public producer adds separate evidence
files. This contract adds no operational permission, actor impersonation, task
revision, cancellation, dispatch or live Slack qualification.

## Why a separate store

Existing FeedbackStore invalidation is bound to retained output artifacts and
feedback use/retention authority. A task's original input message has neither that
output target nor those permissions. Reusing feedback rows would conflate domains.
`tether.source_observation` therefore adds a separate exact SQLite family for
negative task-source facts, while reusing the existing SlackMessageVerifier for
HMAC, timestamp, app/workspace and callback verification. It does not introduce a
second signature parser. No existing Admission/Feedback schema is migrated or
changed, and no existing positive consumer automatically consults this store.

## Exact observation and historical link

`SourceKey` is exactly app_id, workspace_id, channel_id and message_ts. An
observation is exactly that source, event_id, SHA-256 of the original signed body,
and cause message_changed or message_deleted. Raw/previous/changed text, editor
identity, timestamps implying ordering, tokens and full raw bodies are not stored.

`SignedSlackSourceObserver.observe(raw, headers)` accepts only verified hidden
message mutations in the configured route. Changed-message identity comes from
nested message.ts; deletion identity comes from deleted_ts. Supplied original
author, channel, thread, workspace or previous-message hints must agree with the configured
original and retained identity. The top-level user field is not treated as a
deleting actor and is rejected. An edited.user value, when present, is validated
as an editor hint but never stored, treated as original authorship or used to
grant authority. Metadata/language-only changes conservatively fence too.

Before retention, the affected original must resolve through actual Admission
sources and its immutable revision-1 create row. Exact workspace/channel/thread,
message and original author must match the configured source. The linked task ID,
original author/thread and original normalized intent digest are historical
provenance, not a claim about who edited or deleted the message. Missing original
is rejected; this slice provides no pre-create fence. No source can acquire an
invented original author from a deletion callback. Admission does not retain the
original receiving app identity: the app in SourceKey binds the current verified
observation, not the original ingress installation. The trusted host must approve
linking this exact retained Slack message to that installation; no cross-app
original-ingress provenance is claimed.

## Separate host approval and durable state

The internal versioned decision is runspindle.tether.source-observation.v1, with
exact fields version, effect_scope, observation and original. effect_scope is
retain_deny_only_source_fence. A separate host callback defaults to deny and must
approve this exact decision. Provider signing alone is insufficient. The internal
proof binds the verified decision bytes to this observer instance. Direct store
calls without that proof are denied. No task-execution grant is fabricated.

Approval is checked before BEGIN IMMEDIATE and again under the writer lock. The
retained original is reread at both stages and must match exactly. Mutated callback
arguments reject. Trusted callbacks must be bounded, side-effect-free and avoid
reentrant/network work. Ordinary callback exceptions deny with fixed errors;
BaseException cancellation propagates and any local transaction rolls back.
Debuggers, arbitrary trusted callback side effects and captured frame locals are
not a secrecy boundary.

This API accepts nonempty ordinary file paths only, rejecting :memory: and all
file: URI forms before opening SQLite. Durability still relies on the host choosing
persistent storage; file paths on temporary filesystems are not permanent backups.

One transaction adds an immutable first fence and event deduplication row. The
replay/conflict namespace is exactly [app_id, workspace_id, channel_id] plus
event_id, not a workspace-global event-ID ledger. Exact
event/body/source replay remains duplicate after restart and still requires fresh
approval. Changed digest/source under an existing event identity rejects without
rewriting either ledger. Later distinct signed events for an already fenced source
can add event rows but never clear or retarget the original fence. Reordered changes
and deletes cannot resurrect the source. No timestamp is used to infer revision
order or authored intent. UPDATE/DELETE triggers preserve both ledgers.

Each ledger is bounded at 1,000 records across this store. New events exceeding a
bound reject without partial writes or eviction; exact known replay remains
available. This has no silent saturation fallback, automatic reset or grant to
fence other sources. A rejected/unrecorded event leaves unknown status where no
fence exists; it never creates positive permission.

`state(SourceKey)` returns only fenced or unknown. Unknown means no retained
negative fact here, not current, unchanged, valid, eligible, authorized or safe to
execute. Fenced is a retained negative source fact, not proof that a task stopped.
All records are component observations, not Core/delivery/acceptance receipts.

## Atomicity and remaining positive integration

The observation transaction is atomic only within the new store. Admission is
read through a separate existing connection; there is no cross-store atomicity,
remote revocation, dispatch barrier or automatic application to positive admission.
The original normalized intent is not changed or reinterpreted. Existing task,
provider and feedback ledgers remain unchanged. A future consumer must explicitly
bind and recheck these negative facts at its own authorized boundary; it may not
use unknown as permission.

Host-approved successor revision mapping is DEFERRED, not implemented by this
contract. Root runtime-v1 requires revision+1 and a prior observed terminal result;
requested/acknowledged cancellation is insufficient. Future positive mapping must
separately bind the signed source observation/body identity, exact normalized
candidate intent and full task/operation/policy/host/lease grant; distinguish editor
from original author; define metadata-only and stale/out-of-order behavior; and
revalidate the predecessor terminal state at the Core boundary. Provider deletion
alone is never an authored revision or cancellation. Existing Core Admission grant
semantics and envelope schemas are unchanged.

## Verification

`python3 -m unittest discover -s tests -p test_source_observation.py -v` and the
same command with python3 -O exercise real HMAC and SQLite using synthetic data.
Independent complete Admission dumps verify no positive task effects, direct
SQLite/file scans verify data minimization, and socket calls are forbidden.
Coverage includes unknown originals, mismatched routing/hints, editor separation,
metadata changes, ordering/replay/conflict, capacity, callback mutation/failure,
real writer-lock revocation, concurrent fresh processes, crash/cancellation between
inserts, crash after commit, and fresh-process retention. A disposable mutation
omitting fence insertion must fail the independent observer assertions.

Repository aggregate tests on this base also require its already-documented exact
v1 feedback checkout via RUNSPINDLE_TETHER_V1_SOURCE. No package installs, live
migration, account calls, services, permission changes or deployment are included.

Primary semantics were checked against Slack's official
[message_changed](https://docs.slack.dev/reference/events/message/message_changed/)
and [message_deleted](https://docs.slack.dev/reference/events/message/message_deleted)
documentation. The latter does not identify a deleting actor in its documented
minimal payload. These sources describe provider facts, not Runspindle authority.
