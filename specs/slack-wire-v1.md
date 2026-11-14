# Bounded Slack wire protocol v1

Partial implementation for issue #9 and parent #1. Neither issue closes. This is
an original, no-network protocol library, not a live provider, Core transport,
credential helper or durable file-upload adapter. The existing ProviderJournal,
synthetic receipts, retained feedback and delivery authority are unchanged.

## Entrypoints and classification

`tether.slack_wire` provides `allocate_request`, `upload_request`,
`complete_request`, `info_request`, `replies_request` and `download_request`.
`WireClient.allocate`, `.upload` and `.complete` each perform one explicit request
through an injected `Transport.exchange`. They never advance to another upload
step, retry, discover credentials, activate a service or open a socket. Callers can
explicitly repeat calls: this library is NOT a single-send fence. Do not use it as
an outbox or attach it to ProviderJournal as a production provider.

Every request carries account, workspace, channel, parent timestamp, operation,
full payload SHA-256, method, endpoint, exact body, required OAuth scope and a
response-size bound. `Scope.history_scope` is explicit because a G-prefixed
conversation can require private-channel or multi-party-DM history access; a
prefix alone cannot establish the installed account's capability. The account and
workspace are caller-supplied context, not authenticated by this library. The
application must bind a real authorized credential separately if that integration
is ever implemented. No credential field or Authorization header is generated.
Upload URLs are capability-like values and, like content, are omitted from repr.

An injected authorization callback defaults to deny and is invoked before EVERY
request, including each readback page and byte download. It must inspect the exact
request, not merely approve its operation ID. This is an application seam, not a
production authority implementation. There is no post-request authority check,
atomic revocation guarantee or proof that an injected transport is authentic.
Any future acceptance bridge must revalidate current authority at its own commit
boundary. A revoked callback stops the next request. Ordinary exceptions return
unknown without retries; BaseException cancellation propagates without retry.

Results are always `unqualified_wire_observation`. `parsed` reports valid response
fields, `upload_response` reports an HTTP 200 upload response, and `content_match`
reports a bounded independent comparison. None means accepted, delivered, mirrored
or production-qualified. File IDs are NEVER substituted for message timestamps.
No `tether.testing.Reply`/`Record` or Core delivery receipt is constructed.

## Wire subset and independent observations

One file uses `files.getUploadURLExternal`, a raw-byte POST, then
`files.completeUploadExternal` with exactly one channel and parent `thread_ts`.
The library does not enforce or persist that sequence. Allocation provides a
scope-bound Ticket. `FileBinding` is caller input, not proof of an immutable,
durably retained operation-to-file binding. Completion may return only file IDs;
it does not prove a message identity or the original artifact's bytes.

`readback(binding, intent, max_pages=4)` independently obtains `files.info`, all
pages of a bounded `conversations.replies` traversal, and the exact private-file
bytes. It requires one matching message, exactly one file reference, exact text,
filename and size, and one exact workspace/channel/parent/message share. Parent
messages may omit thread_ts only when their own ts is the parent. Message
subtypes other than ordinary messages/file_share and nonempty blocks/structured
attachments are unsupported. Unknown fields are not used as evidence. All
timestamps remain strings, never floats. ContentFacts contains the parsed message
and file facts plus SHA-256 and length calculated from downloaded response bytes.
Expected outgoing bytes are NEVER used as the downloaded observation.

Missing, partial, transformed, multi-shared, duplicated, cross-thread, inaccessible,
ambiguous or rate-limited responses remain unknown. A digest claimed in a provider
object, filename, URL, upload status, size or preview cannot prove bytes. Queries
and byte downloads are sequential observations, not an atomic Slack snapshot;
mutation/deletion can occur between or after them. No read acknowledgment by a
human, lasting availability, original provenance or eventual delivery is claimed.

## Bounds and failure policy

- Local payload limit: 1 MiB combined text and file bytes; filename 256 UTF-8 bytes;
  initial comment at most 4,000 characters. These are deliberately narrower local
  limits, not a claim to support all Slack payloads. Any server warning stays unknown.
- Responses: 1 MiB maximum, and successful downloads at most the expected size.
  The injected transport must enforce that bound BEFORE buffering. This library
  additionally checks the returned bytes. It cannot control a supplied transport's
  memory use, deadlines, DNS, authentication, streaming or redirect behavior.
- JSON rejects duplicate keys at any level, nonfinite numbers, floats (including
  exponent overflow), invalid UTF-8/surrogates, excess depth/nodes and out-of-range
  integers. The supported subset needs only bounded integers and timestamp strings.
  Header duplicates, unexpected compression, inconsistent lengths and non-200
  responses cannot become successful observations.
- Exactly `https://slack.com/api/` method targets and `https://files.slack.com`
  file targets are constructed. Upload paths must be under `/upload/v1/`; downloads
  under `/files-pri/{workspace}-{file}/`. Userinfo, ports, query/fragment, control
  characters, backslashes, traversal and nested percent encoding reject. No redirect
  is followed by this library. The injected transport contract must also disable
  redirects. Remote files are unsupported. No bearer token is sent to an upload URL.
- Readback requests 15 messages/page, permits 1–8 pages, at most 120 messages and
  512-byte cursors. Repeated cursors/messages, absent required pagination metadata,
  contradictory has_more/cursor or exhausted budgets stay unknown. It never treats
  incomplete traversal as absence or permission to resend.
- HTTP 429 retains a valid integer Retry-After of 0–86,400 seconds as metadata on an
  unknown result. Missing, malformed, duplicated or larger values stay unknown
  without a delay. No scheduling, sleeping, retry or new authority follows. Limits
  are method/app/workspace-specific, not global retry permission.

## Current primary references

Checked 2026-11-14 UTC. These exact URLs are documentation observations, not immutable
upstream source commits or copied SDK implementation. No SDK dependency was added.
Base code pin: Tether `22546d6b414cb298a6ec60433505ef6cf7ca9883`.

- [Upload allocation](https://docs.slack.dev/reference/methods/files.getUploadURLExternal/):
  obtain file ID/upload URL, POST bytes, then finalize; asynchronous processing is
  possible. Allocation is documented Tier 4 (100+ requests/minute).
- [Finalize upload](https://docs.slack.dev/reference/methods/files.completeUploadExternal/):
  files/channel_id/thread_ts/initial_comment; parent thread timestamp required; the
  method is documented callable once. Tier 4. No retry/idempotency guarantee is inferred.
- [File info](https://docs.slack.dev/reference/methods/files.info/): files:read, file
  metadata and share identities, Tier 4.
- [File object](https://docs.slack.dev/reference/objects/file-object/) and
  [download guidance](https://docs.slack.dev/messaging/working-with-files/): private
  download URLs need file access, remote URLs can point outside Slack, exact host
  validation and controlled redirects are required. No documented SHA-256 field
  replaces an independent byte download.
- [Thread replies](https://docs.slack.dev/reference/methods/conversations.replies/):
  parent/channel and cursor pagination. Access/scopes depend on actual installation;
  this library does not infer a usable token or grant scopes.
- [Rate limits](https://docs.slack.dev/apis/web-api/rate-limits/) and
  [distribution-specific clarification](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/):
  429 Retry-After is seconds for the same method/app/workspace. The current
  clarification limits affected new commercial non-Marketplace apps/installations
  to 1 request/minute and 15 history/reply objects; internal customer-built apps
  retain their rate tier. Installation classification is unknown here.
- [Message posting](https://docs.slack.dev/reference/methods/chat.postMessage/):
  structured attachments are not native file-byte uploads. Message posting generally
  permits one/second/channel with additional workspace limits; 4,000 characters are
  recommended and more than 40,000 may be truncated. Not implemented here. Its
  client_msg_id-related errors do not document a contractual deduplication window
  or exactly-once guarantee; no resend policy relies on client_msg_id.

## Verification and remaining dependencies

`python3 tools/validate.py && python3 -O -m unittest discover -s tests -v`

The tests inject an independent synthetic HTTP model which parses outbound wire
bytes, counts all calls and allocation/upload/share effects, and returns literal
readback fixtures or separately retained submitted bytes. Socket connections are
forbidden. Negative cases include equal-size wrong bytes, wrong thread/workspace,
partial/extra files, changed text, scoped denial, pagination, malicious URLs/JSON,
response bounds, 429s and interruption. Deliberate source mutations bypass byte
comparison and thread comparison: the independent regressions must fail by
assertion, not an import error. Public data is synthetic only.

Remaining blockers: durable file-allocation/substep binding and crash/restart
protocol; Core reservation/artifact/authority bridge; real account/origin/lease-bound
credential helper; authenticated provider readback; supported live response-shape
qualification; production sanitization; runtime deployment. This slice creates no
new SQLite schema and establishes no durability. Existing journal behavior is
unchanged; no copied production trust or automatic retry is introduced.
