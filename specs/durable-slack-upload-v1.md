# Durable Slack file substeps v1

Partial implementation for [Tether #9](https://github.com/newdarwindev/runspindle-tether/issues/9)
and parent #1. Neither closes. This is a SQLite-backed coordinator of the existing
`tether.slack_wire.WireClient`, exercised against a separate synthetic HTTP store.
It is not a credential helper, HTTP implementation, Core adapter or live provider.

## Exact boundary

`tether.slack_upload.UploadJournal(path, transport, authorize, sanitizer)` exposes
explicit `send(scope, intent)` and read-only-provider `lookup(scope, intent)` calls.
The exact-request authorizer defaults to deny. The application must supply real
owner/Core authority, accepted artifact, current account/workspace/destination and
capability observations, including revocation and expiry checks. A boolean fixture
authorizer cannot establish any of those facts. No default transport exists.

The coordinator reuses the existing schema-family admission, canonical encoder,
payload sanitizer, wire requests, response parsing and independent byte readback.
It stores provider substeps in a separate exact-schema SQLite family; it does not
alter the ProviderJournal schema or duplicate Core's accepted-artifact reservation,
outbox ownership, retry policy or Delivered state. Every caller for an operation
must share this store. Passing a different store is not a global uniqueness fence.
No ProviderJournal/Core receipt conversion or production composition is provided.

An operation is immutably bound to account, workspace, channel, parent timestamp,
history scope and full payload digest. That digest covers text and exact artifact
ID, filename, length and byte hash. A duplicate operation with any changed binding
rejects before provider access. One allocated file ID can belong to only one
operation in the workspace. A conflicting file allocation cannot reach upload.

## Durable order and interruption policy

The sole invocation which inserts the operation with `BEGIN IMMEDIATE` may advance:

1. Commit `allocating` before the allocation request.
2. Validate the allocation and commit the immutable file ID and `uploading` before
   sending bytes. The upload URL exists only in this invocation's memory.
3. Observe a supported upload response, then commit `completing` before finalizing.
4. Independently read file info, exact destination thread and downloaded bytes.

Every later `send`, including a competing process or reentrant call, only attempts
readback. It never repeats allocation, upload or completion, even after an explicit
429, cancellation, missing file or an interrupted-before-effect reservation. This
is conservative at-most-once attempts, not exactly-once delivery or a liveness
guarantee. Stopped partial uploads cannot be resumed by this API. No automatic
cleanup/deletion, timer, lease expiry, retry or replacement operation is created.
Core and an authorized provider recovery protocol must resolve those later.

Slack documents allocation, byte upload, then completion, and completion as a
one-time call. No provider idempotency guarantee is assumed. Primary references
rechecked 2026-11-15: [allocation](https://docs.slack.dev/reference/methods/files.getUploadURLExternal/)
and [completion](https://docs.slack.dev/reference/methods/files.completeUploadExternal/).

The returned states are only `unknown` or `content_match`, always classified
`unqualified_wire_observation`. A 200 or parsed completion does not become accepted,
delivered or mirrored. Missing/unavailable/partial readback remains unknown, never
authoritative absence and never permission to resend. A matching readback uses the
retained file ID, exact scope and resupplied digest-matching content. A later exact
match with a different message timestamp permanently fences the operation as a
conflict. The historical match is not returned as current success after failure.

Authorization is checked before each request, including every readback request,
and after readback both before and after acquiring the observation write lock.
There are no network calls under SQLite locks. These checks are synchronous
observations, not distributed atomicity with remote revocation or provider changes.
Cancellation propagates; normal transport failures remain unknown. Valid 429 delay
and stage metadata are retained only for observation, never interpreted as retry
authority or a scheduled time. Readback delay metadata identifies the readback
stage, not a qualified Slack method-specific retry instruction.

## Stored and omitted data

SQLite contains the immutable scope/digest, attempted phase, file ID, retained
message timestamp/conflict and optional rate-limit metadata. SQL triggers retain
bindings, file identity and conflict fences and reject backward phase changes.
Unknown schemas are rejected using the existing read-only preflight. This is not
protection against privileged store/schema manipulation or filesystem replacement.

Text, filename, file bytes, upload capability URLs, download URLs and provider
errors are never stored. Configured-secret and immutable-payload checks reject
unsafe input before provider access. The sanitizer is bounded configured-secret
checking, not universal secret discovery. The application still owns permissions,
storage security and production sanitization. Public observations omit content,
URLs and error bodies; exceptions from authorization callbacks are detached.

## Reproducible evidence and remaining gaps

Run `python3 tools/validate.py && python3 -O -m unittest discover -s tests -v`.
Only Python and SQLite standard libraries are needed; no install or network.

The synthetic HTTP service parses actual request bytes into its own SQLite store.
Its independently queried call records capture the journal phase and file ID
visible at each invocation. Tests inspect actual content/destination effects and
scan journal files for content/capability persistence. Fresh subprocesses hard-exit
before and after all three mutating actions, then recover against both retained
stores. Four competing processes and reentrant invocation cannot duplicate effects.
Child processes inherit optimized Python mode; mutation assertions survive `-O`.
Deliberate repeated-completion and upload-before-binding mutations must fail by
independent assertion rather than import/parsing failure. Temporary stores/processes
are cleaned up on success, failure and timeout; no live provider cleanup is implied.

Still blocked/not run: the Core admission/reservation/authority/receipt bridge,
authenticated account-bound transport, actual Slack response qualification, partial
upload recovery/cleanup authority, production sanitization, full multi-attachment
behavior, native/runtime integration, deployment and live acceptance. Existing
wire/parser/readback, ProviderJournal, admission and feedback code is unchanged.
