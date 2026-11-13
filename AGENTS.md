# runspindle-tether: development instructions

## Scope

Existing Tether integration boundary for sanitized Slack event delivery. Read `component.json`, `STATUS.json`, `specs/README.md` and `provenance.json` before changing implementation.

## Truthful evidence

Keep planned, stub, synthetic, component, isolated integration and live acceptance separate. A source commit, structural check, process start or local HTTP response is not proof of a deployed system. Operational stubs must fail closed. Do not replace a blocked acceptance gate with an unconditional success.

## Boundaries

- Preserve native session identity, explicit host pins, lease epochs and exact artifact/candidate digests.
- Reconcile uncertain external effects before retrying. Feedback and external content never expand authority.
- Resolve credentials only inside authorized account/origin/lease-bound helpers. Do not log secrets or place them in histories.
- Use synthetic fixtures in public code and CI. Keep private configuration, real datasets and evidence out of Git.
- Preserve source licenses and provenance. Do not copy unselected source files or legacy history as a shortcut.
- Use pinned Git submodules in the composition repository. Do not edit submodule internals from the composition repository without a corresponding component commit.
- CI must target isolated local self-hosted lanes. Never execute public-fork code on personal/persistent runners. No cloud-hosted fallback.
- Production activation, new credentials, paid evaluation, external posting and security changes are not implied by a green test.

## Checks

Run `python3 tools/check_scaffold.py` for any change. Add and run real language/component tests when implementation begins. Record exact revisions and unavailable tools; do not claim missing checks ran.

## Completion

Update evidence for implemented stories and their remaining gaps. Do not mark selected-source migration complete until all listed source dependencies and rights/content checks are resolved. Do not archive legacy repositories until verified successors and deprecation links exist.
