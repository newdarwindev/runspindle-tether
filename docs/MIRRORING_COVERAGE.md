# SRC-014 artifact coverage and review

This completes the selected audit's **artifact adaptation**, not a runtime
adapter, provider integration or live acceptance. The canonical requirements are
[the acceptance contract](MIRRORING_ACCEPTANCE.md). The reviewable
[coverage register](mirroring-coverage.json) accounts for every source section,
paragraph, table row and numbered obligation using opaque ordinal IDs. It also
records the exact current capability, component, failure and evidence-slot matrices.
No original installation snapshot or implementation code is imported.

## Review and exclusions

The retained audit and its companion MIT notice were compared with the private
source record. Their original hashes and original revision remain in that private
record. The notice is byte-preserved in [LICENSE-SRC-014.txt](LICENSE-SRC-014.txt).
Only sanitized distinctions and requirements are adapted. This adds no dependencies,
SDK source, binaries, figures, historical tests or unrelated source expression.
The navigation-only companion excerpt is not an additional selected artifact.

The audit contains four sections with 19 substantive disposition units:

| Section | Units | Review decision |
| --- | --- | --- |
| S1: historical verification | introduction, four snapshot rows, method | Adapt observation limits and bounded non-secret inspection. Exclude all four device-specific rows and dated operational details. |
| S2: source capability coverage | four adapter rows, test limitation paragraph | Adapt final-only, separate exposed-event formatting and snapshot distinctions. Exclude private source paths and historical tool/installation facts. |
| S3: rebuild story | introduction, requirements 1–5 | Adapt all five obligations into the existing Tether contract and concrete evidence references. |
| S4: acceptance | procedure, concluding uncertainty | Adapt the complete test procedure into empty evidence slots. Preserve unverified status and separate activation authority. |

The source title, section headings and table headers supply structure, not
additional behavior; the four section entries account for those headings. Each unit's
`destinations` and `evidence` references resolve locally. Excluded snapshot rows
resolve to this review decision, not an executable test. The checker ensures the
complete ordinal inventory, but source fidelity still depends on the private
source/rights review; public checks cannot inspect the excluded material.

Private devices, enrolled identities, source repository locations, local paths,
operational revisions, raw messages, credentials and hidden reasoning are not
publication targets. Hidden reasoning is forbidden in every matrix row. The
privacy check is a bounded guard against known unsafe forms, not a universal
personal-data or secret detector. No denied inspection is bypassed.

## Adapter and event coverage

The matrix names actual fixture configurations separately from historical adapter
profiles. `synthetic_supported` means a local fixture accepts that exposed kind;
`unsupported` means that mode rejects it. `unverified_unavailable` means there is
no qualified current runtime adapter here, not that its real provider lacks the
feature. `forbidden` is a publication boundary, not a missing implementation.

| Adapter/configuration | Lifecycle | Public summary | Tool start/update/complete | Result/error | Final | Usage | Snapshot | Current evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| synthetic.events | synthetic | synthetic | synthetic | synthetic | synthetic | synthetic | unsupported | NativeSource and fake destination tests |
| synthetic.final_only | unsupported | unsupported | unsupported | unsupported | synthetic | unsupported | unsupported | Mode rejection and destination-effect checks |
| synthetic.snapshot_only | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | synthetic | Snapshot is not a transcript/event stream |
| synthetic.unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | unsupported | Zero emission |
| historical.guarded_cli | unverified | unverified | unverified | unverified | unverified | unverified | unverified | Thread identity, retained completion/failure; no intermediate progress/tools |
| historical.final_output_router | unverified | unverified | unverified | unverified | unverified | unverified | unverified | Historical exact-thread/journal final-only output |
| historical.exposed_sdk | unverified | unverified | unverified | unverified | unverified | unverified | unverified | Separate public summaries, commands, file changes, MCP names/search/steps; no forwarding proof |
| historical.status_snapshot | unverified | unverified | unverified | unverified | unverified | unverified | unverified | Historical allowlisted snapshots, no timeline reconstruction |

All rows have `control: false` and `live_coverage: not_run`. Each synthetic mode
independently models bound, unbound, stale and disconnected state. The source is
process-local: a newly constructed source has no durable event history. Neither
these modes nor the historical profiles identify an installed adapter. The exact
per-event cells and implementation/spec/test references are in the register.

## Evidence layers and failure modes

1. **Native observation:** [NativeSource](../specs/synthetic-native-events-v1.md)
   supplies binding, event ID, sequence, kind, observation time and synthetic
   classification. An accepted callback is `submitted`, not delivered. Operation/
   attempt IDs and authoritative provenance in a real normalized envelope remain
   integration obligations, not inferred fixture fields.
2. **Transport acknowledgement:** [FakeSlack](../specs/synthetic-transport-v1.md)
   can acknowledge `accepted`; only independent exact destination readback can
   confirm a synthetic record. The fake deliberately permits duplicate sends so
   tests can expose them. It is not a Slack protocol or durable store.
3. **Durable attempt fence:** [ProviderJournal](../specs/provider-journal-v1.md)
   commits one attempt before effects and reconciles existing attempts through
   readback. Fresh-process crash and competing-writer tests inspect a separate
   synthetic SQLite provider store. This is not a production Core bridge, retry
   scheduler or proof of Slack delivery. It never creates Core's Delivered state.
4. **Sanitized projection:** [Sanitizer](../specs/sanitization-v1.md) checks bounded
   schemas and explicitly configured secrets before local persistence/rendering.
   Dirty immutable identities and accepted artifact bytes are rejected, not
   silently rewritten. Secret resolution, unknown-secret discovery, arbitrary
   binary scanning and production qualification remain outside this evidence.
   The source's OpenBao-reference requirement remains an integration obligation;
   configured-secret tests are not an OpenBao credential resolver.
5. **Credential-free wire component:** [the bounded wire library](../specs/slack-wire-v1.md)
   parses Slack file requests and independently compares synthetic HTTP readback.
   Its merged source is included in the reviewed base and linked in the register.
   Even matching bytes and thread identity yield only unqualified wire observations,
   not authenticated receipts, durable upload recovery, Core authority or live
   acceptance. Every call is explicit and may be repeated by a caller; there is no
   durable substep fence, credential helper or concrete HTTP client.
6. **Live destination receipt:** no real native adapter or Slack provider is
   qualified here. This layer remains not-run. Final output, snapshot visibility,
   upload status, parsed metadata and a local HTTP response cannot fill that gap.

The register's failure matrix links executable test methods for exact routing,
unavailable capabilities, ordering/reconnect, duplicates/restart/competing writers,
unknown/conflicting receipts, partial artifacts, rate limits, updates/deletes,
mirror-loop prevention, revocation/cancellation and sanitized persistence. Its
mutation controls independently observe a forbidden sink call, false receipt,
duplicate provider effects and leaked synthetic canaries, plus wire byte/thread
comparison bypasses. They run in the existing
suites; this artifact lift does not duplicate the relay or those suites.

Keep origin-event, queued, rejected, sent and destination-confirmed counts separate.
Current fixture request/record counters and SQLite call/effect rows are local test
observations, not one aggregate production coverage counter. An unknown outcome is
never silently promoted to delivery or permission to resend.

## Live evidence slots

`live_evidence_template` is intentionally empty and `not_run`. For each explicitly
authorized host/adapter pair, populate a **separate private evidence record** with:

- Authorization and bounded scope; exact source revision and installed runtime.
- Host/native-session identity and exact workspace/channel/thread binding.
- Supported versus unavailable kinds; sanitized emitted-event manifest; event,
  operation, attempt, sequence and provenance correlations.
- Journal states and independently obtained exact destination receipts, including
  message identity and accepted artifact bytes. Record each count separately.
- Normal delivery, reconnect/replay, duplicates, uncertain sends and reconciliation.
- Tool start/update/completion, progress, failure and final-output exercises.
- Before-persistence/rendering sanitization and secret-reference review; passive
  visibility separate from control/permission forwarding.
- Inspection denials, unavailable tools and ambiguous/missing evidence. Respect
  bounded inspection and do not bypass denied access or import private histories.

Use invented fixture content. Unsupported events are not event loss; missing or
ambiguous receipts stay uncertain. Tool availability, executable/service discovery
and process counts do not establish runtime revision, enrolled identity or delivery.
No activation, credentials, permissions, service, installation or production rollout
is authorized by the contract or by a passing local test.

## Reproduction and completion scope

Run from the repository root, with Python standard library and Git:

- `python3 tools/check_mirroring_audit.py`
- `python3 -m unittest tests.test_native_source tests.test_fake_transport tests.test_provider_journal tests.test_sanitization tests.test_slack_wire tests.test_mirroring_audit -v`
- `python3 tools/validate.py`
- `python3 -O tools/validate.py`
- `python3 -O -m unittest discover -s tests -v`

[Retained evidence](mirroring-audit-evidence.json) records observed results and
current file hashes; older component evidence remains historical at its recorded
pins. [The artifact manifest](evidence-artifacts.json) checks adapted bytes and
notice integrity. The audit checker uses explicit exceptions rather than Python
`assert`, so its negative checks remain effective under `-O`.

The containing Git commit identifies the exact reviewed result. Use `git rev-parse
HEAD` and `git rev-parse HEAD^{tree}` after freezing, and `git show
<reviewed-commit>:docs/evidence-artifacts.json` to reproduce the retained bytes.
An in-tree record cannot contain its own final Git hash; the exact frozen commit,
tree and manifest hash belong in the publication receipt and private SRC-014
mapping. Revalidate after any subsequent content change. No old test result
transfers automatically.

This scope can close only [artifact issue #2](https://github.com/newdarwindev/runspindle-tether/issues/2)
after review and actual validation. Issues #1, #3, #8, #9 and #10 and product gate
F01 remain open/not-run according to their own scope. Component-level
`selected_source_migration` remains partial: accounting for this selected document
is not the same as porting a runtime, verifying live behavior or archiving a source.
