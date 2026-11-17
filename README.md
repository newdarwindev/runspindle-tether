# RUNSPINDLE TETHER

## Keep the conversation attached to the work, not just its final answer.

**TETHER — SANITIZED WORKFLOW COMMUNICATION** implements the boundary between
conversation events and attributable work: exact source/destination identities,
ordered revisions, sanitization, durable journals and explicit delivery uncertainty.
Its atomic semantic journal connects to **CORE** without treating replayed metadata
as permission to repeat an external effect.

[Slack's event and Web APIs](https://docs.slack.dev/) supply the communication surface;
native runtimes supply the progress events they actually expose. **TETHER** adds
trusted admission, event mapping and recoverable delivery around them. It does not
invent hidden reasoning or claim coverage for events a runtime never provides.

The implemented [signed own-message edit lane](docs/signed-own-message-edits.md)
requires explicit editor attribution and the exact retained predecessor. It supports
a constrained callback shape, not universal Slack edits. Raw deletions remain denied:
the prior message's author is not evidence of who deleted it.

**DELIVERY COORDINATION** uses SQLite substep fences and independent readback for
single-attempt uploads. Contradictory matching observations remain a durable conflict;
missing evidence remains unknown. Local acceptance is not remote execution or delivery.

*UPCOMING — complete trustworthy deletion semantics, live authenticated ingress,
provider-backed delivery/readback and measured event coverage on supported native
runtimes. Controlled signing secrets and HTTP peers are test fixtures, not a live
Slack deployment. Issue #8 remains open until its complete acceptance is verified.*

[![Conceptual intent and recurring work source map, gallery page 23](https://newdarwindev.github.io/runspindle_for_bloomberg/gallery/23.webp)](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle_Gallery_Index.html#page-23)

**Conceptual source map, not a live Slack transcript.** Identity, authority and
recovery stay attached to the same job.
[Slide/source index](https://newdarwindev.github.io/runspindle_for_bloomberg/assets/Runspindle_Gallery_Index.html#page-23)
· [Product concept slides](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/main/assets/runspindle_bloomberg_product.pdf)
· [40 proposed workflows](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/main/assets/runspindle_bloomberg_workflows.csv).
These are fictional/synthetic concepts, not live trading, measured outcomes or
Bloomberg endorsement. [Asset provenance and claim limits](https://github.com/newdarwindev/runspindle_for_bloomberg/blob/main/ASSETS.md).

### Follow the implementation

- [Atomic semantic journal](specs/semantic-journal-v1.md) and [Core bridge](https://github.com/newdarwindev/runspindle-core/blob/main/docs/INTENT_BRIDGE.md).
- [Signed ingress](specs/signed-slack-ingress-v1.md), [sanitization](specs/sanitization-v1.md), and [signed edits](docs/signed-own-message-edits.md).
- [Durable upload coordination](specs/durable-slack-upload-v1.md) and [conflict evidence](docs/upload-conflict-evidence.json).
- [Mirroring coverage](docs/MIRRORING_COVERAGE.md), [source](tether/), [tests](tests/) and [status](STATUS.json).

## Development and qualification boundaries

Existing Tether integration boundary for sanitized Slack event delivery.

**Status: public scaffold, not a deployed or production-ready implementation.**

This repository is one boundary of [Runspindle](https://github.com/newdarwindev/runspindle). Repository boundaries do not require one microservice each.

- Read [specifications](specs/README.md), [agent guidance](AGENTS.md), [provenance](provenance.json), [status](STATUS.json) and [legal status](LEGAL.md).
- Run `python3 tools/check_scaffold.py` for structural validation only.
- Operational entrypoints and acceptance gates deliberately fail closed until implemented.
- GitHub Actions use isolated **self-hosted local runners only**. No GitHub-hosted fallback. Runner capacity is not established by publishing workflows.
- No credentials, real sessions, messages, datasets, browser profiles or live host inventory belong here.

No old repository is retired by this scaffold. Migration and archival are separate verified gates.

## Implemented validation

Run `python3 tools/validate.py` for all implemented structural, language, fixture, artifact and mutation checks in this repository. The same entrypoint runs on trusted `main` and `ci/*` pushes and manual qualification using disposable Strix x64 guests. Logs include the checkout SHA, image/tool identities, command results and applicable artifact checksums. Unimplemented builds and product acceptance remain explicit in `STATUS.json`; blocked acceptance workflows retain their failing conclusions. ARM64 and native macOS qualification remain pending.

## Desired technical direction

Sanitized workflow communication: this component contributes to turning authorized one-off work into
repeatable, maintained cross-application workflows. Scoped access, managed
sessions, explicit human exceptions and evaluated DSPy candidates are intended
to compose into that capability; no automatic improvement or live integration
is implied.

Read [the component-specific technical intent](specs/desired-intent.md) for its
interfaces, privacy boundaries, failure cases and acceptance obligations. Current
implementation and evidence limits above remain unchanged.

## Durable upload coordination (bounded component)

[Single-attempt Slack upload coordination](specs/durable-slack-upload-v1.md) now
wraps the existing wire client with SQLite substep fences and exact independent
readback. [Current local evidence](docs/durable-slack-upload-evidence.json) records
synthetic HTTP tests, interruption/race checks and remaining gaps. Earlier
STATUS records and earlier test counts remain historical component coverage; the bare
wire client still has no durability by itself. Core/ProviderJournal composition,
authenticated transport, partial-upload resume and live acceptance remain blocked.

[Contradictory exact readback](docs/upload-conflict-evidence.json) now retains a
sticky SQLite conflict when the same file has multiple independently matching
message identities, including recovery after restart. Missing or malformed
observations remain unknown; this adds no send retries or delivery qualification.
