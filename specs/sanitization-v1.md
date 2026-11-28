# Bounded event-projection sanitization

Partial issue #10 / parent #2 implementation on main `791ba48eda97248b304322b0177c0a9e4d85b890`. Root #43 and core
#16/live integration are not completed by this change. This is an original local
component, not a new relay, authentication scheme or universal secret detector.

## Defined boundary

`Sanitizer(secrets, limits)` accepts an explicitly supplied tuple of known secret
strings. Empty configuration cannot discover unknown secrets. It normalizes NFC
and redacts both exact original and NFC supplied values plus their URL-quoted
and padded or unpadded standard and URL-safe base64 representations. URL
authorities retain their
original spelling until redaction, so hostname case conversion cannot hide a
configured value. Resolved workspace/channel/thread identities must already be
clean before reservation or provider effects; they are rejected, never rewritten. It does not decode arbitrary encodings, infer sensitive
facts, recognize every credential format, or scan arbitrary binary formats.
Default sensitive key names (password/token/authorization/cookie/private-key and
hidden-reasoning forms) redact their values independent of the known list;
separator/case variants are recognized. All input is validated before redaction,
including a sensitive subtree that would otherwise be discarded.

The projection schema is exactly `runspindle.projection.v1`, required `version`
and `kind`, with optional `message`, `arguments`, `result`, `error`, `url`,
`attachments`, and `capabilities`. Other top-level fields fail. Nested JSON values
are allowed in arguments/results/errors; custom objects, non-string keys,
nonfinite floats, cycles and excessive nesting/node/byte counts fail. Normalized
key collisions and known secrets in keys reject instead of merging keys silently.
Attachment metadata accepts only filename, URL, media_type, size and caption; it
never imports or renders attachment bytes. Unknown fields/types reject.

Default limits: depth 12, 2048 nodes, 256 KiB total source string/key bytes plus
bounded primitive allowances, and 2048 retained characters per string. Higher
limits have hard implementation maxima. Redaction happens before truncation,
which carries an explicit `[truncated]` suffix. Fixed schema/capability metadata
must not change under normalization or truncation. Residual configured values,
including a collision with a redaction marker, fail closed.

HTTP(S) URLs in URL fields or embedded in text are decoded at most twice, stripped
of userinfo/query/fragment and redacted; unsupported URL schemes in URL fields
reject. This is an inert presentation boundary, not URL-origin authorization or
navigation. Rendering returns an escaped JSON `<pre>` fragment with no active
links. Consumers must not unescape it or reinterpret strings as trusted HTML.

## Existing storage and transport integration

Admission now checks immutable inbound identity/metadata and generated envelope
fields before storing them. Original signed bytes and authority digests are never
rewritten. Raw incoming text remains outside the admission history; callers may
explicitly call `persist_projection(task_id, revision, value)` to store a sanitized
projection for an already retained admission. This adds no task admission or
sending authority. The SQLite transaction inserts once; an exact replay is a
no-op, a conflicting projection cannot replace the revision, and exceptions or
cancellation roll back. `render_projection` revalidates/sanitizes retained content
before escaped output. Mirror identities receive the same immutable-data check.

ProviderJournal checks the exact envelope, text/attachment metadata, configured
secret bytes in accepted artifacts, and provider receipt identities. Dirty bound
content rejects before persistence/provider calls; dirty acknowledgements or
readback IDs stay unknown and are never retained or returned. Accepted artifact
bytes, identifiers and digests are never redacted/rebound silently. Content must
be sanitized before core acceptance and authorization; changing an artifact needs
a new accepted digest and authority. A caller cannot use this sanitizer to expand
transport permissions. The provider remains synthetic-only and core-owned delivery
acceptance is unchanged.

`NativeSource` remains the source of capability declarations. Projection validation
reuses its modes and supported-event mapping, requires a valid availability and
retains `evidence_class=synthetic`, `control=false`, `live_coverage=not_run`.
Unavailable/unsupported modes are never promoted to live. Existing source gating
is tested alongside this projection and still produces no destination effects for
unavailable/unsupported events. No real adapter discovery or legacy source lift
is claimed.

## Evidence and remaining limits

Run `python3 tools/validate.py && python3 -O -m unittest discover -s tests -v`.
Tests use invented canaries only. Independent scans query actual SQLite rows,
read database file bytes and inspect rendered/provider outputs; no sanitization
counter is used as the proof. Fresh-process reopening exercises the actual
projection store. Tests cover SQL failure/cancellation rollback, malformed/cyclic
inputs, oversized/truncated content, Unicode/encoded/embedded URLs, nested errors,
attachment metadata, immutable authority/artifact/receipt guards and every
synthetic capability mode/availability combination. A disposable mutation bypasses
the projection sink sanitizer; an independent database scan observes the canary.
Network is forbidden; temporary files/processes are bounded and cleaned up.

Earlier admission/journal manifests retain their historical hashes; this change's
manifest supersedes their current-source verification. No baseline regeneration,
runner/image change, live provider, deployment or standing service is introduced.
Known-secret configuration and the defined schema bound the result. Unknown
secrets, arbitrary encoded/binary content, real provider compatibility, native
core integration and full production sanitization remain outside acceptance.

## Bounded rejection exception metadata

The follow-up on base `7130373187ff70e59c4593ce56f37d8417900738` keeps the
existing error classes and fixed public categories while removing retained local
exception chains. Admission authentication/authority, journal authority/route
resolution, and feedback authentication/retention-authority/target-verification
callbacks translate `Exception` failures only after leaving their local handler.
A new fixed-category error has no callback-derived arguments, notes, cause or
context, so ordinary `traceback.format_exception` output does not include the
callback exception. `raise ... from None` alone is insufficient: it hides the
printed chain but still exposes the original through `__context__`.

The same boundary applies to existing ingress, delivery and feedback decoding,
Slack wire JSON/string decoding, and sanitizer Unicode, URL and capability-state
parsing. These wrappers preserve their prior accepted inputs, rejected-input
categories and caught exception types. Parser errors are discarded, not copied
or interpolated. This is a bounded public exception boundary, not a generic
exception scrubber. It does not promise secrecy for debugger/traceback frame
locals, rich formatters that capture locals, arbitrary caller exception context,
exceptions outside these wrappers, or malicious callbacks with their own side
effects or mutation of exception/runtime objects.

Default-deny decisions, authority rechecks and transaction boundaries are
unchanged. Admission rejection adds no rows; feedback rejection, including the
check after obtaining the write lock, rolls back without partial revisions.
Journal denial after reservation retains the uncertain attempt and never permits
another send. Denial after provider readback, including after the journal lock,
does not promote or persist an observation. `BaseException` cancellation still
propagates; rollback and durable send fences remain in force. A successful call
or an exact later readback retains its existing semantics.

`tests/test_error_boundaries.py` checks unique synthetic canaries in exception
arguments, strings, reprs, notes, causes, contexts and ordinary formatted
tracebacks. Independent SQLite read connections and file scans verify retained
state; the separate synthetic provider database verifies call/effect counts.
Tests cover callback failures before/after locks and reservation, restart/retry
without duplicate sends, malformed/oversized nesting and Unicode, successful
paths and cancellation. Disposable mutations restore both explicit chaining and
`from None` inside an authentication handler; the same canary guard must fail.
Issue #10 stays open for broader real-adapter and production qualification.

## Unpadded base64 of configured secrets

The same bounded matcher handles both base64 alphabets with or without trailing
padding in projections and immutable artifact bytes. This includes base64url
text carried in an attachment URL path. Configured secret variants are redacted
before inserting a projection. An accepted artifact with a matching byte sequence
is denied before reservation and provider dispatch. This does not migrate any
previously retained bytes.

The two `test_unpadded_base64_*` tests in `tests/test_sanitization.py` exercise
SQLite persistence, escaped rendering, and `ProviderJournal.send` with a fake
provider and a network guard. They independently read the database and inspect
provider calls. Both failed on base `bb1aa8695896f54057d1b64aab5eac6288cc2e73`
with the new tests applied. Run the containing suite with
`python3 -B -m unittest tests.test_sanitization`.

## Structured HTTP headers and retained projection reads

Nested `headers`, `httpHeaders`, `requestHeaders`, `responseHeaders` and
`trailers` can be header maps or lists of two-element pairs or name/value
records. Case and separators are normalized when identifying a header field
or known sensitive name. Authorization, proxy authorization, cookie,
set-cookie and the configured conventional API or access-token header names
are redacted even when their values are carried in a separate field. Ordinary
entries keep their shape and go through the usual recursive sanitization.
Ambiguous entry shapes and raw header blocks reject before any projection
write. The initial structural bounds apply even to values that will be
discarded.

Rendering checks retained SQLite text as bounded UTF-8 canonical JSON before
the current sanitizer runs. A damaged row produces a fixed rejection category
with no parser cause or context. Current header handling applies to previously
stored supported shapes at render time. Historical rows retain their original
bytes, so this check does not erase already stored content. Remote transport,
live sanitization and arbitrary wire encodings remain outside this receipt.

Independent SQLite and file reads verify that new header values are absent
before rendering. The regression suite also checks historic readback after
reopen, malformed UTF-8 and JSON, and retained-byte preservation. See the
[local evidence record](../docs/structured-header-privacy-evidence.json).
