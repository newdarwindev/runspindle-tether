# Shared synthetic fixture upgrade

Source composition commit: `e283957d80aebc48fb0bd3b6e2a600850ff6dc97`.
This is the tether consumer portion of composition #1, not runtime integration,
upstream/native compatibility, a live receipt or parent feature closure.

The checked-in bundle exactly matches the standalone reviewed root export.
`shared-fixture-compatibility.json` records old/new byte and manifest metadata
diffs and actual validator decisions. Existing golden envelopes remain accepted;
malformed floating-point independent identity counters previously accepted through
Python equality are now rejected. Schema/contract meanings are unchanged.
Fault schedules are newly included in each subset.

Run without sibling checkouts or services:

```sh
python3 -B -m unittest discover -s tests -p 'test_shared_fixture*.py'
python3 -O -B -m unittest discover -s tests -p 'test_shared_fixture*.py'
```

Both invocations passed 8 tests on Python 3.12.14. Existing tamper/pin tests
remain; the new module requires the exact reviewed pin before loading a verified
source snapshot, with forbidden network/process guards already active.
Per-step synthetic model observations and actual spy-call identities are checked
against independent fault contracts; double sends, incorrect order, sequence
regression, unauthorized retry and wrong effect identity are rejected.
The model restart remains blocked until a real durable adapter, not simulated
success. No source code is imported from sibling repositories during these runs.

These focused tests cover this fixture-only upgrade, not the complete component
aggregate. Broad test and aggregate outcomes are reported separately in the PR;
unavailable prerequisites and unrelated baseline failures are not waived or
reclassified. Runtime code, component dependency pins and quality baseline remain
unchanged. Historical evidence remains historical.
