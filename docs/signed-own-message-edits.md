# Opt-in signed own-message edits (controlled qualification)

`SignedRevisionIngress` is a separate store family. It does not migrate or adopt
legacy create-only or semantic stores. Existing APIs remain create-only.

The official [message schema](https://docs.slack.dev/reference/events/message/)
defines `edited.user` as the editor. The adapter requires that explicit editor to
match the configured actor and current/previous message author. It never infers
an editor from the author, installation authorization, or previous message alone.
The [message_changed example](https://docs.slack.dev/reference/events/message/message_changed/)
does not guarantee `previous_message`; this adapter deliberately supports only
callbacks containing an exact predecessor snapshot. Missing predecessors are
unsupported and rejected, not synthesized. No universal or live Slack coverage
is claimed. Fixtures use controlled synthetic identities and signing secrets.

Original callback bytes are authenticated by the existing HMAC verifier before
normalization. App, workspace, channel, thread, message, author, explicit editor,
and current/previous snapshots are checked. Nested channel, when present, must
match the configured channel. Bot, subtype, attachment, file, block, and ambiguous
content shapes are denied. Provider edit timestamps use exact integer microsecond
ordering, not floats or wrapper delivery timestamps. Metadata-only callbacks with
an unchanged edit token are denied. No text means no attribution shortcut.

A new provider version must name the exact retained predecessor version and text
hash. Edit-before-create is rejected without writing a tombstone; a valid create
can subsequently establish history. Every accepted event persists provider token,
callback-byte hash, normalized hash, and semantic candidate in one SQLite admission
transaction. Concurrent stale preparations are rejected under the existing lock.
Exact event retries retain their original logical revision even after newer heads;
changed callback bytes under the same event ID are conflicts, including whitespace
changes. Raw text, signatures, and secrets are not stored in the provider journal.

Existing semantic batch snapshots/readback remain metadata-only. Local acceptance
is not remote execution, cancellation, or delivery. Fresh trusted authority and
separate v3 references remain required; no issuer, network endpoint, service,
credentials, or live integration is created here. Ordinary SDK signature validation
does not substitute for grants.

The [message_deleted schema](https://docs.slack.dev/reference/events/message/message_deleted/)
does not establish a deleter identity. Deletes remain denied. This partial lane
therefore does not complete issue #8 or establish production readiness.
