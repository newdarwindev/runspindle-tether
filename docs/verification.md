# Approved verification hygiene

Run `python3 tools/validate.py` from the repository root. `hygiene.json` is the
reviewed mandatory inventory: removing a checker file does not remove the check.
A required tool or input that is unavailable fails visibly; an inapplicable lane
must have an explicit reviewed reason in the manifest. Verification never installs
or silently substitutes dependencies.

## Provisioning and use

Provision the exact tools in `requirements-quality.txt` and the static-quality
configuration before verification; see `tools/static_quality.py` for version checks.
For a dedicated development environment, provision with `python3 -m venv /tmp/runspindle-quality`
and `/tmp/runspindle-quality/bin/pip install -r requirements-quality.txt`.
Select that environment on PATH for `python3 tools/validate.py`. Repositories with
`tools/quality-node/package-lock.json` also require an explicit provisioning step:
`npm ci --prefix tools/quality-node --ignore-scripts`. Provisioning needs registry
access; validation must not acquire packages. Review package/lock changes separately.
Do this as a separate, deliberate environment-preparation operation, not a fallback
inside verification. Existing fleet images may require a separately reviewed update.
Rust checks require the existing pinned toolchain and offline dependency cache.
No runner, permission, authentication, activation or storage policy is changed here.

Run `python3 tools/hygiene.py --preflight-only` for input checks only. A partial
receipt is not a completed validation. Lock inputs must be tracked and unchanged
relative to the index; intentional lock updates must be staged/reviewed. Observed changes to source bytes, HEAD or index between the before/after
verification snapshots fail. This optimistic boundary does not detect a mutation
restored between observations. Composition gitlinks must agree with its lock, without
upgrading them as a side effect.

## Reports and profiling

`.verification/evidence.json` and `.verification/report.md` are generated locally
and ignored by Git. They preserve source and base identity, check outcomes, missing
inputs, explicit N/A, checksums, timings and limitations. Raw process output and
argument values are not persisted; the manifest and command fingerprint identify
the command. Reports are not automatically uploaded, and no retention policy is set.

Profiling is report-only and identifies hardware. Initial workloads exercise offline
regression paths and are labeled validation workloads, not production benchmarks.
Wall time, child CPU and the explicitly process-wide child RSS high-water are recorded.
These are single samples without statistical thresholds; no provider-cost, native
performance or production-latency claim follows. Establish stable repeated baselines
on comparable hardware before proposing regression enforcement.

See [repository discipline](repository-hygiene.md) for PR body validation, generated
template checks, provenance, ownership and exceptions. Existing acceptance and
runner trust boundaries remain unchanged. No additional coverage floors, automatic
PR triggers, security scanners, cross-repository compatibility policy, retention
policy or UI quality policy is introduced by this change.
