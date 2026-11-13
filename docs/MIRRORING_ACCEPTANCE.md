# Tether event mirroring and acceptance

## Evidence boundaries

Source support, installed executables, service definitions and running process counts do not establish live event delivery. Deployment acceptance must independently verify the exact runtime revision, enrolled session identity, routing binding and destination receipts.

Synthetic adapter tests are contract tests, not live delivery receipts. An adapter that formats tool events does not establish that another adapter forwards them. Snapshot visibility does not establish event mirroring. Unsupported native events must remain explicitly unsupported rather than reconstructed.

Live all-session/all-event coverage is unverified until the acceptance checks below pass.

## Adapter coverage contract

Maintain an explicit capability matrix for each supported adapter:

- Session lifecycle and native session identity.
- Public progress and reasoning summaries.
- Tool-call start, update and completion.
- Tool results and errors.
- Final responses and usage.
- Unsupported or unavailable native events.

Private hidden reasoning is never a deliverable. A final-only output adapter must be labeled final-only. Status-snapshot integrations must be labeled as snapshots and must not request transcripts or timelines merely to imply broader coverage.

## Event mirroring requirements

Extend Tether’s adapters, exact-thread router and durable delivery journal rather than introducing a second relay. Preserve native session identity and the task, host and session correlation contract.

1. Every explicitly enrolled session has a verified host, native session ID and exact workspace, channel and thread binding. Distinguish unbound, unsupported, stale and disconnected sessions. Running process counts are not session coverage.
2. Normalize supported session lifecycle, public progress summaries, tool lifecycle, results, errors, final responses and usage into structured event envelopes. Include event ID, operation and attempt IDs, sequence and provenance. Mark unavailable native events explicitly. Never reconstruct private hidden reasoning.
3. Sanitize credentials and sensitive content before persistence or rendering using secret references and whole-envelope sanitization. Final-response token matching alone is insufficient for expanded tool payloads.
4. Preserve ordered, bounded updates in the existing destination thread. Use the durable journal for deduplication, restart reconciliation and uncertain outcomes. Mirrored output must never be interpreted as a new command. Keep origin-event, queued, rejected, sent and destination-confirmed counts separate.
5. Verify passive mirroring independently from remote control and permission forwarding. Visibility alone grants no control capability.

## Required live acceptance evidence

For each supported host and adapter, an explicitly authorized bounded test must record exact source revision and installed runtime, native session identity, exact destination routing binding, sanitized emitted-event manifest, corresponding journal state and exact destination receipts.

Exercise tool lifecycle, progress, failure and final output. Distinguish unsupported events from event loss. Record normal delivery separately from reconnect and replay, duplicate suppression, and uncertain-send reconciliation. An absent or ambiguous receipt must remain uncertain; never blindly resend. Use invented fixture content, never real credentials or private history.

Passing source or contract tests does not authorize service activation, new permissions or production rollout. Those require their own authorization and deployment evidence.

## Provenance

This is a sanitized adaptation of source SRC-014. The original dated installation snapshot, exact revision and source locations are preserved privately. Historical uncertainty has not been relabeled as a pass.

Retained source notice: [MIT license](LICENSE-SRC-014.txt), Copyright (c) 2026 Lars de Ridder.
