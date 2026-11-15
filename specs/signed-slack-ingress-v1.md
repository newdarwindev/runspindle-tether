# Signed Slack Events API ingress v1

Bounded implementation for [issue #8](https://github.com/newdarwindev/runspindle-tether/issues/8)
and parent #3. Neither closes. This is an original standard-library adapter that
actually verifies signed request bytes and calls the existing durable admission
consumer. It is not a server, deployed Slack integration or Core authority
implementation. No SDK or upstream implementation was copied.

## Supported entrypoint and authority

`SignedSlackIngress(path, signing_secret, route, clock, authorize, sanitizer)` owns
an existing `Admission` instance. `ingest(raw, headers)` returns its `admitted` or
`duplicate` result. Signature and supported-shape rejection raises a fixed-category
`Rejected`; downstream Admission, Sanitizer and SQLite exceptions keep their
existing behavior, and `BaseException` cancellation propagates. A successful
return means a local admission record exists, not that work ran or a message was
delivered.
The supported subset is an ordinary text-only `message` create in an
`event_callback`, exactly matching the trusted `Route` app, workspace, actor,
channel and parent timestamp. A root message may omit `thread_ts` only when its
own timestamp matches the configured parent. IDs and timestamps remain strings.

The signing secret is supplied explicitly in memory by trusted application code.
No credentials are discovered, generated, persisted, logged or rotated here.
This work's tests use synthetic secrets only. The caller owns secure storage,
rotation and authorized provisioning before any real integration. Configuring a
route does not grant task authority. The separate existing authorization callback
must return a current exact identity/digest/revision-bound `Grant`; absence,
revocation, mismatch or callback failure blocks admission. The signing secret
proves the request's application origin, not the human's permission to execute.

The adapter normalizes the authenticated message into existing
`runspindle.tether.ingress.v1`, revision 1/create, with exact event/message/actor/
workspace/channel/thread identities and original text. It constructs an internal
instance-and-normalized-byte-bound proof consumed by `Admission.authenticate`.
The digest passed to Core authority is of these normalized bytes, not HTTP bytes.
The existing SQLite source, delivery and revision bindings, transaction, duplicate
conflict checks and readback mirror suppression perform the durable work.

`admission` remains a trusted application seam for existing local record/query
operations, including `record_mirror`. Do not expose it, the proof, route, clock or
authority callback as user-controlled RPC inputs. Python private attributes are
not a security boundary against arbitrary in-process code. Single-threaded use
follows the existing SQLite connection contract. This adds no atomic revocation
or post-lock authority guarantee beyond the existing Admission component.

## Request verification

1. Require immutable raw bytes, 1 byte–1 MiB. An upstream HTTP integration must
   enforce this bound while reading, before buffering or decoding.
2. Require original header pairs as a tuple, not a mapping that might have lost
   duplicates. At most 64 headers and 16,384 ASCII name/value characters. Header
   names are case-insensitive; all duplicate names, controls and malformed pairs
   reject. This intentionally rejects some otherwise legal HTTP headers.
3. Require JSON content type, optionally `charset=utf-8`; reject compression and
   transfer-encoding. Optional Content-Length must exactly match the raw bytes.
   Framing, request method/path, TLS, deadlines and rate limits remain the server's
   responsibility. No HTTP server or socket is opened here.
4. Require a canonical positive integer Unix timestamp and `v0=` plus 64 lowercase
   hex digits. An injected clock must return bounded integer Unix seconds. There
   is no clock fallback. Reject a timestamp more than 300 seconds in either
   direction from that clock. A caller may narrow, never widen, that window.
5. Compute HMAC-SHA256 over `v0:timestamp:raw_body` and use `hmac.compare_digest`.
   Verify before JSON parsing, normalization, authority calls or admission writes.
6. Parse using the existing bounded JSON decoder, rejecting duplicate members,
   invalid UTF-8/surrogates, floats/nonfinite numbers and excess complexity. Bind
   the installation, actor and destination before invoking task authority.

Within-window repeats are not globally forbidden: Slack retries are expected.
The existing durable event/digest namespace and source bindings reconcile them.
A signature alone does not make old content new. Retry headers never grant
permission, change revision or bypass fresh authority. Different HTTP formatting
of the same normalized event remains a duplicate; changed normalized content
under the same event identity is a conflict. The adapter sends no acknowledgment,
retry instruction or HTTP response and never retries on its own.

## Explicit exclusions

Only a create is implemented. Edit/delete actor attribution and ordered revision
mapping remain separate work. Every message subtype, bot/app marker, hidden or
edited marker, nested historical message, file, attachment, block or metadata
field rejects, even when empty. Modern Slack messages containing rich-text blocks
are therefore unsupported, including ones with plain-text fallback. The library
does not silently drop those structures and claim complete message support.

Slack Connect/external shared channels, Enterprise routing, conflicting context
workspace and multi-installation authorization lists reject. Optional supported
installation metadata never grants execution permission. Unknown informational
fields are ignored, not persisted or interpreted as authority. URL verification,
app mentions, rate-limit callbacks and every other event kind are rejected; a
future challenge handler must remain separate from task admission.

`Admission` continues to retain envelope identities/digests rather than raw
message content. HMAC proof/header/body/secret are not persisted. Existing
configured sanitization still guards retained metadata. This is not universal
secret detection or debugger/frame-local confidentiality. JSON and clock failures
are translated outside their exception handlers so local exception context is
not retained. `BaseException` cancellation is not swallowed.

## Primary protocol references

Documentation checked 2026-11-15 UTC; these URLs are protocol observations, not
immutable SDK pins. Implementation base: Tether
`a444b21e53edbaa86d1cf9fab08f52a0d347dbbb`.

- [Request signatures](https://docs.slack.dev/authentication/verifying-requests-from-slack/):
  app signing secret, exact raw request body, timestamp, v0 HMAC-SHA256,
  constant-time comparison and a five-minute freshness window.
- [Events API](https://docs.slack.dev/apis/events-api/): callback/app/team/event
  identity, installation metadata and delivery retries. Actual server
  acknowledgment and subscription setup are outside this implementation.
- [Message events](https://docs.slack.dev/reference/events/message/): message user,
  channel, text, timestamp, optional thread and distinct subtype semantics. This
  adapter supports a deliberately narrower subset, not the whole event catalog.

## Reproduction and evidence

From this checkout:

`python3 tools/validate.py && python3 -O -m unittest discover -s tests -v`

Focused suite: `python3 -m unittest tests.test_slack_ingress -v`.
See [the bounded evidence](../docs/signed-slack-ingress-evidence.json).

Tests exercise actual HMAC verification and existing SQLite admission with an
independent synthetic signer and explicitly fake authority. Socket creation is
forbidden. Independent SQLite connections inspect rows; byte scans verify that
secrets, raw message and signatures are not retained. Fresh Python processes,
normal and optimized, replay admitted and mirrored events. Wrong signatures,
header framing, stale/future timestamps, unbound scope, callback failure, malformed
JSON, missing/revoked grants, unsupported event types and duplicates are checked.

Maintained source mutants bypass the signature, freshness and actor/channel
binding checks. The actual independent regressions must fail by assertion, never
an import failure. An initial thread-only mutant remained rejected by downstream
identity binding; that was residual defense, not successful mutation detection.
It was replaced by the effective actor/channel mutant, with no production guard
weakened. Full image-bound CI, native/Core integration, real transport compatibility,
provider/live acceptance, deployment and full issue #8 completion remain pending.
