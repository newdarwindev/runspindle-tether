# Bounded single-shot Slack HTTP transport

Partial implementation for #9 and parent #1, with #10 error-boundary coverage.
These issues remain open. `tether.slack_http.HTTPSingleShotTransport` implements
`slack_wire.Transport.exchange` with actual socket HTTP I/O. Its evidence is
synthetic loopback component integration, not real Slack, real TLS, account,
Core authority, production credential-helper or delivery qualification.

## Host trust and exact routing

The constructor requires both a credential provider and an authorization callback.
Neither has a default or discovers credentials from environment/files. The host
must authenticate current account/workspace/lease authority and approve the exact
Request including method, URL, body, digest, destination and OAuth scope. Scope
alone is not authority. The transport checks endpoint/method/scope/content type
but does not decode allocation/completion bodies to authenticate their intent.
Use the reviewed WireClient builders and durable upload fence; do not construct
arbitrary requests or turn this single-shot client into an automatic retry loop.
A Credential binds a hidden bearer to the exact Request; it is host attestation,
not proof that the token belongs to an account or has valid Slack scopes.

Exactly these routes are supported, preserving the existing wire subset:

- POST https://slack.com/api/files.getUploadURLExternal, files:write, form body.
- POST https://slack.com/api/files.completeUploadExternal, files:write, JSON body.
- GET https://slack.com/api/files.info, files:read, one file query parameter.
- GET https://slack.com/api/conversations.replies, declared history scope, exact
  scope channel/parent, limit 15 and optional bounded cursor.
- POST https://files.slack.com/upload/v1/... with raw bytes. The credential
  provider is NEVER invoked and no Authorization header is sent on this route.
- GET https://files.slack.com/files-pri/{workspace}-{file}/..., files:read.

File URLs retain the wire codec's strict path checks. HTTPS only; no explicit
ports, userinfo, alternate hosts, fragments, arbitrary queries or caller headers.
No proxy environment support, redirects, retries, token fallback, cookie store,
connection reuse or implicit API calls. Fixed Host and Content-Length are emitted;
Accept-Encoding is identity. Only a validated single DNS answer is connected,
with all answers rejected if any is non-global, multicast or reserved. System
certificate trust and hostname verification remain enabled via the standard TLS
context, using the original allowed hostname for SNI. No insecure TLS switch or
production connection-factory parameter exists.

## Authority, deadlines and cancellation

An initial exact authorization happens before the child starts. An ephemeral
spawned process resolves DNS and connects TLS, then pauses. The parent resolves
the exact scoped credential (except for upload), rechecks authorization and request
snapshot, and only then permits HTTP emission. A nonblocking instance lock rejects
concurrent or recursively invoked exchange calls. This is not cross-instance
idempotency, a Core lease implementation, or atomic remote revocation. Trusted
callbacks may perform host work and must not mutate request state or block forever.
They execute in the parent outside enforceable callback deadlines. The network
budget is checked again after callbacks before allowing a send.

A 0 < timeout <= 30 second absolute budget includes child startup, DNS, TLS, writes,
response reads and IPC. The child also uses socket timeout. On timeout, cancellation,
malformed response or lost acknowledgment the outcome remains unknown; effects may
already have happened. There is no automatic repeat or next upload stage. Existing
WireClient returns unknown for ordinary errors; cancellation propagates. The child
is terminated and joined on every exit, with a kill fallback and at most two
additional one-second cleanup waits. No background sender or persistent job exists.
An uninterruptible OS process cannot be guaranteed reaped within that bound.

The parent receives bounded result frames, never child exception objects. Ordinary
public errors have fixed text without chained original exceptions. KeyboardInterrupt
and SystemExit preserve those cancellation categories with fixed messages; other
BaseException subclasses become a generic sanitized BaseException. No stack-local
memory scrubbing, protection against trusted code introspection, or universal
secret discovery is claimed. Body observations may contain private data and remain
subject to the caller's existing sanitization/sharing boundary. TLS endpoint
requests and response bodies are not logged by this component.

## Strict HTTP subset

A minimal strict parser is used because the standard high-level HTTP parsers
accept duplicate/ambiguous framing and larger headers before an application guard
can inspect them. Supported: HTTP/1.0 or HTTP/1.1 final 2xx–5xx statuses, a single
bounded Content-Length, or exactly chunked transfer coding with plain hexadecimal
chunk sizes and no trailers/extensions. Unsupported: interim 1xx, close-delimited
bodies, compressed bodies, folded/control/non-ASCII headers, duplicate header names,
Content-Length plus Transfer-Encoding, extra coding chains, chunk extensions and
trailers. These conservative rejections can leave legitimate Slack variants unknown;
they are not evidence that current Slack responses universally fit this subset.

Bounds before buffering: request/body 1 MiB, URL 2048 characters; status line 256
bytes; at most 32 headers, 128-byte names, 2048-byte values, 8192 total header bytes;
response body at most 1 MiB (successful downloads additionally use the exact
expected size); at most 4096 chunk records; parent IPC at most 2 MiB. Only
Content-Type and Retry-After response headers are returned. Redirect locations,
cookies and arbitrary diagnostics are not propagated or followed. HTTP 429 is an
observation only, leaving WireClient's bounded Retry-After metadata policy intact.

## Reproducible evidence

Base: 789380df2a8fd0da5a9757e5312d66daa07bef2d. Original standard-library code; no
upstream implementation copied and no package installs or new dependencies.

Run `python3 -m unittest discover -s tests -p test_slack_http.py -v` and the same
command with `python3 -O`, then repository `python3 tools/validate.py`.
The executable host must support multiprocessing spawn and guard script startup
with the normal `if __name__ == '__main__'` convention. No credentials or network
configuration are needed for the tests.

Tests inject a loopback-only connector into the PRIVATE exchange runner, retaining
real HTTP byte parsing, IPC and process cleanup. Production TLS connection is
separately checked with mocks for exact sockaddr/hostname and forbidden DNS answers;
real TLS handshakes are NOT tested here. Independent server request bytes establish
one-call counts, exact bearer presence/absence and zero sends after denial. Coverage
includes full 1 MiB IPC, truncated/malformed framing, duplicate/large headers,
chunk restrictions, redirects, 429, timeouts, cancellation, reentrancy and drift.
Two isolated deliberate mutations remove multicast rejection or omit bearer headers;
independent observer tests must fail by assertion, not import/runtime setup failure.
All identities, content, capabilities and credentials in tests are synthetic.

Remaining: real origin/account/lease credential integration, Core reservation and
artifact bridge, real Slack/TLS response qualification, full runtime composition,
production sanitization/operational qualification and separately authorized live
acceptance. No ProviderJournal or Core acceptance receipt is synthesized.

## Primary protocol references

Checked 2026-11-15 UTC, not immutable source pins:

- [Upload URL allocation](https://docs.slack.dev/reference/methods/files.getUploadURLExternal/)
  documents API authorization and posting bytes to the returned capability URL.
- [Upload completion](https://docs.slack.dev/reference/methods/files.completeUploadExternal/)
  documents finalization separately from byte upload.
- [Working with files](https://docs.slack.dev/messaging/working-with-files/) and
  [file objects](https://docs.slack.dev/reference/objects/file-object/) document
  private-download Bearer authorization and the need to validate file destinations.

The narrow origin/path allowlist is the existing reviewed codec policy, not a claim
that Slack never uses other origins. Unknown variants fail closed pending review.
