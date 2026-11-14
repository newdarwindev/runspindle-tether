# Synthetic transport test seam

Related: Tether #1 (test harness), #3 (functional parent), #9 (future durable
outbound integration). This is an original, process-local test adapter, not a
Slack SDK, wire protocol, provider authentication mechanism or second relay.
It completes a bounded test-fixture slice only. All three issues remain open.

## Contract and evidence

`tether.testing.FakeSlack` accepts one explicit synthetic workspace/channel/thread
destination, an injected integer clock and injected message-ID factory. Its
send/update/delete/readback operations record a bounded request history and a
bounded in-memory destination store. IDs use the existing runtime identifier
grammar. Payloads contain text and up to eight attachments with exact IDs,
filenames and bytes. Payloads are capped at 1 MiB and filenames at 256 UTF-8 bytes.
All records and replies are explicitly classified `synthetic`.

Request history retains a payload digest, not raw text or attachment bytes. The
synthetic destination store intentionally contains fixture content for independent
inspection. It is **not** a sanitized production journal. Use invented, already
sanitized fixture content only. Whole-envelope sanitization, native capabilities,
durable persistence, restart/concurrent-writer ownership and real transport
integration remain separate work; this fixture cannot qualify those criteria.

A send acknowledgement is `accepted`, never destination-confirmed. Explicit
`confirm_readback` compares exactly one observed record against full destination,
operation, optional message identity, complete text and attachment bytes/metadata,
and delete state. Missing, malformed, conflicting, partial, ambiguous or wrong
thread observations remain `unknown`. A lost or malformed acknowledgement after
an effect is also `unknown`, never safely retryable failure.

The fake intentionally does **not** deduplicate send calls: two sends with the
same operation can create two effects and ambiguous readback. The real existing
core outbox, not this fixture, must own durable deduplication, reconciliation,
retry scheduling and concurrency. Tests demonstrate lost-ack readback without a
second send, not an implemented automatic recovery worker.

Updates and deletes preserve message identity. Deletes retain synthetic tombstones
and reject subsequent update/delete attempts. Readback observes only current state;
if a newer operation replaces a message, old-operation readback is absent/unknown,
not a fabricated historical receipt. Request history and destination observations
are separate; there is no combined success counter or delivery promotion.

## Fault matrix

- send/update: rate limit, before-effect failure, lost acknowledgement, partial
  attachments and malformed acknowledgement after effect.
- delete: rate limit, before-effect failure, lost/malformed acknowledgement.
- readback: missing, ambiguous, malformed or wrong-thread response. The injected
  wrong thread is always a distinct valid identifier, even when the requested
  thread is named `wrong-thread`.
- Rate limit returns `retry_at = injected_now + 3` with no effect. The fake never
  sleeps, schedules or retries. The caller must implement bounded retries later.
- Partial-attachment faults require at least one attachment; otherwise they fail
  before any destination effect rather than silently simulating success.
- Unknown operation/fault combinations, capacity exhaustion, invalid payloads and
  message-ID collisions fail visibly without overwriting destination effects.
- Wrong destination operations never consume the queued valid-route fault or
  alter the destination store.

## Reproduction and limits

Run `python3 tools/validate.py && python3 -O -m unittest discover -s tests -v`.
No packages, credentials or network access are needed. Test clock starts at 100;
IDs are deterministic counters; no random source or wall clock is used.
`tests/test_fake_transport.py` traps socket connections and independently inspects
request history, exact stored payloads, attachment bytes and destination identities.
A disposable source mutation removes the destination comparison and produces a
false confirmation contradicted by the independently observed wrong destination.

One test composes confirmed synthetic readback with the existing SQLite ingress
mirror registration and proves zero re-admitted command envelopes. It does not
claim that a live outbound adapter registers identities atomically. Test mutation
and SQLite files use temporary directories and finally/cleanup blocks. Fake state
is process-local and discarded with each test; no durable or concurrency guarantee
is claimed, so a new process has no fake destination state to recover.

Still blocked/not run: full issue #1 sanitization/capability matrix, core #16
trusted execution integration, issue #9 durable journal/outbox and retry ownership,
provider readback authentication, live Slack/native events and deployment.
Existing acceptance gates and runner policy are unchanged.
