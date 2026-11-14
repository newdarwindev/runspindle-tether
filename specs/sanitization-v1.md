# Bounded event-projection sanitization

Partial issue #10 / parent #2 implementation on main `791ba48eda97248b304322b0177c0a9e4d85b890`. Root #43 and core
#16/live integration are not completed by this change. This is an original local
component, not a new relay, authentication scheme or universal secret detector.

## Defined boundary

`Sanitizer(secrets, limits)` accepts an explicitly supplied tuple of known secret
strings. Empty configuration cannot discover unknown secrets. It normalizes NFC
and redacts both exact original and NFC supplied values plus their URL-quoted
and standard/URL-safe base64 representations. URL authorities retain their
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
