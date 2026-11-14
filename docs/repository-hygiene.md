# Repository discipline

This policy implements the approved D12 repository-hygiene scope only. It does
not change repository permissions, branch protection, workflow triggers or
product acceptance requirements.

## Accountability and review

The repository account `newdarwindev` is the default accountable owner, not an
assertion that any other named person has accepted a maintainer role. Each PR
must identify its actual accountable owner. Keep scope bounded, link the issue
or specification, state non-goals, and give concrete Given/When/Then criteria.
Link changed tests and their evidence, preserving failed or unavailable checks.
A PR template is guidance until its filled body is explicitly checked.

## Reproducible checks

Run `python3 tools/check_repo_hygiene.py` to check the versioned policy,
exception expiry, required provenance fields and deterministic template bytes.
Run `python3 tools/check_repo_hygiene.py --pr-body /path/to/body.md` to validate a
filled PR description. Comments/placeholders do not satisfy required sections.
This is a structural check, not proof that a link exists or a review occurred.
No PR API query, permission change or automated PR execution is performed.

The only generated output managed by this new checker is
`.github/PULL_REQUEST_TEMPLATE.md`. Regenerate it with
`python3 tools/check_repo_hygiene.py --write-template`, inspect the diff, and
commit the generator and output together. Existing component artifact/reference
checkers remain responsible for their declared outputs. This policy does not
claim all historical generated files are reproducible or add UI/rendering gates.

## Provenance

Link `provenance.json` in the PR, explain which files are original or adapted,
and identify required source references/notices without publishing private source
records. Keep existing provenance and licensing constraints. The local checker
checks presence and shape, not legal sufficiency or authenticity of claims.

## Exceptions

`repository-hygiene.json` is versioned. Its initially empty `exceptions` list
may contain explicit reviewed records with `id`, `owner`, `scope`, `reason`,
`issue` (a GitHub issue URL), and `expires_utc` (YYYY-MM-DD). The expiry date is
exclusive at UTC midnight; expired or incomplete records fail the check.
Exceptions document reviewable debt; they do not disable other checkers or
waive permissions. List the applicable ID in the PR or explicitly say none.
Do not create a future expiry merely to make a failed check pass.
