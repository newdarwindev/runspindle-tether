# runspindle-tether

Existing Tether integration boundary for sanitized Slack event delivery.

**Status: public scaffold, not a deployed or production-ready implementation.**

This repository is one boundary of [Runspindle](https://github.com/newdarwindev/runspindle). Repository boundaries do not require one microservice each.

- Read [specifications](specs/README.md), [agent guidance](AGENTS.md), [provenance](provenance.json), [status](STATUS.json) and [legal status](LEGAL.md).
- Run `python3 tools/check_scaffold.py` for structural validation only.
- Operational entrypoints and acceptance gates deliberately fail closed until implemented.
- GitHub Actions use isolated **self-hosted local runners only**. No GitHub-hosted fallback. Runner capacity is not established by publishing workflows.
- No credentials, real sessions, messages, datasets, browser profiles or live host inventory belong here.

No old repository is retired by this scaffold. Migration and archival are separate verified gates.

## Desired technical direction

Sanitized workflow communication: this component contributes to turning authorized one-off work into
repeatable, maintained cross-application workflows. Scoped access, managed
sessions, explicit human exceptions and evaluated DSPy candidates are intended
to compose into that capability; no automatic improvement or live integration
is implied.

Read [the component-specific technical intent](specs/desired-intent.md) for its
interfaces, privacy boundaries, failure cases and acceptance obligations. Current
implementation and evidence limits above remain unchanged.
