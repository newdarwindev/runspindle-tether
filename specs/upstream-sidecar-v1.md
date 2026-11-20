# Upstream-first sidecar migration, stage 1

The owner approved replacing generic communications and supervision with original
`larsderidder/tether` at `0a5e8fc89390d383d4f5b4dfb827c5ea3128ad0a`
and `larsderidder/agent-tether` at `1256d1a260abb10fdf16a9b842b942b2ccac1310`.
The README/license discrepancy is accepted; actual MIT license bytes are retained
in `upstream/notices`. Source files and Git trees are pinned in `upstream/pins.json`.
Version-pinned minimal dependency requirements are supplied; a complete cross-platform
wheel/license closure is not claimed by this first slice.

## Implemented versus remaining

`runspindle_tether` is a separate namespace. Its source-qualified test subprocess
imports the actual original upstream `BridgeManager`, `BridgeCallbacks`, and main
Tether `BridgeTurnAccumulator`. Generic output routing and final-output accumulation
are upstream code, not local rewrites. The tests use synthetic registered output
boundaries and injected original-event authentication/Core authority callbacks.
No model runner, upstream global store, chat SDK or live service is initialized.
The upstream native runner is deliberately not another execution owner: Core/Host
remains the sole owner. Creation, attachment, history/discovery and unsupported
callbacks are denied, not silently delegated to upstream defaults.

The Runspindle seam preserves authenticated actor/workspace/channel/thread/message,
source event, selected host/session, lease epoch and exact action payload digest.
A callback without the original verified context is rejected. Context cannot escape
into an asynchronous child task or survive the originating invocation. Authority
is checked immediately before each effect, and one invocation permits one effect.
Auto-approval timers or upstream scalar callbacks alone cannot confer Core authority.

This is NOT a complete platform-event interception patch or authenticated Core RPC.
The authenticator and Core authority/effect boundary are explicit injected trusted
interfaces in this first stage. Durable event replay, ownership fencing and exact
provider readback remain the retained authoritative boundary's responsibility;
process-local one-shot guards do not claim cross-process replay protection.
A distinct mandatory `output_execute(VerifiedAction, payload, route)` hook owns
the durable output reservation, unknown state and independent readback. Missing
output executor denies before routing, and only output actions may carry a route.
The gate passes only a scoped route wrapper to that executor. The wrapper rechecks
original invocation lifetime, task identity, exact payload and current authority
immediately before the real route, denying deferred or child-task dispatch. Its opaque current destination is
bound in the authenticated workspace/channel/thread and platform proof. The
registered bridge cannot be swapped during the deferred operation. The test uses
an actual SQLite reservation fixture retained across fresh adapter instances to
prove unknown delivery is not replayed, not a production outbox replacement.
Output callback return is not proof of delivery; the adapter never marks an upstream
final as sent solely because that callback returned. Unknown exceptions propagate,
with no automatic retry. Whole-output current permission/sanitization must precede
the authorized output seam. Thinking, tool streams and history are not forwarded.

Existing `tether/` signed admission, journal, exact readback, feedback and revocation
code remains unchanged and compatible until actual upstream parity is demonstrated.
Do not replace it with copied JSON, bypasses or a new generic queue. Upstream's
ambiguous-send retry and outbox-ack behavior are NOT enabled by this slice.

## Reproducible local check

In a dedicated Python >=3.11 environment install `upstream/requirements.txt` from
the official package registry. Supply clean, exact pinned source checkouts:

```
python -B tools/check_upstream_sidecar.py /path/to/tether /path/to/agent-tether
```

The runner rejects changed source/tree/ignored files before imports, then runs
isolated subprocess tests with a 60-second bound and no inherited provider settings.
No actual Slack/Discord/Telegram delivery, model invocation, new credentials,
persistent daemon, hidden history collection or production activation is qualified.

## Parity work before retiring local generic code

1. Add the minimal original-platform actor-context hook before upstream callback
   information is discarded; test signature and all destination identity mismatches.
2. Connect the sidecar to exact existing Core/Host request/receipt protocols and
   authoritative replay storage; verify no duplicate native owner on restart.
3. Integrate existing exact effect/readback outcomes into upstream outbox hooks,
   disabling ambiguous automatic retries without replacing generic upstream queues.
4. Feed authenticated reaction events through retained signed feedback and sticky
   revocation fences; keep gold separate from use consent and deployment authority.
5. Apply existing envelope privacy checks before upstream persistence/rendering;
   prove no thinking/history/error/attachment canary leaks.
6. Compare all existing compatibility tests, actual upstream tests and bounded
   real-component negative campaigns before removing superseded implementations.

### Initial local observations
16 original-upstream adapter tests pass normally and with optimized Python.
Existing compatibility discovery ran 523 tests with seven explicit skips and one
Mac-specific pre-existing provenance-test error (`platform.architecture` receives a
mocked string where it expects bytes). The same error reproduces in the unchanged
baseline checkout. Thus the full suite is not reported green; the new adapter tests,
scaffold and mirroring-audit checks pass separately. No existing runtime files were
changed or retired. Linux/full dependency qualification and independent source review
remain required before declaring migration parity.

The sidecar is trusted application code, not a hostile-plugin sandbox. Source
provenance is enforced by the isolated test launcher, not arbitrary direct library
imports. Git verification has per-command time bounds. Production source loading,
durable Core RPC and platform interception remain unqualified.

## Actual signed parent input seam

`runspindle_tether.signed_parent.SignedInputAuthenticator` now uses the original
Runspindle `SlackMessageVerifier`, not a copied authentication algorithm or a
caller-supplied actor JSON field. It verifies the original bytes/headers and current
signature window, rejects mismatched installation/actor/channel/thread and mutation
or bot events, then binds the trusted selected Host/session/lease to the exact input
payload. Whitespace trimming matches the pinned upstream Slack handler. Commands
and empty input remain denied until their separate action hooks are qualified.

This module runs in the existing parent namespace. It does not import upstream
Tether or initialize a Slack SDK. Four actual-HMAC tests exercise actor preservation,
forgery/wrong-scope/mutation rejection, changed content and stale lease denial with
the existing gate. They are distinct from the original-upstream subprocess tests.
The production pipe/endpoint connecting this parent to the upstream sidecar and
Core's authenticated authority remains unimplemented. A verified actor record
requires the gate's fresh Core authority check for every effect. Authenticated
cross-process transport remains unqualified.

## Durable admission before the signed parent callback

For Tether #8 and #3, configure the callable parent with
`SignedInputAuthenticator.open` and the existing local admission store. The
parent checks the original signed body and its input policy, then admits the
original normalized event through `SignedSlackIngress`. The selected host and
lease must match the grant both before and after the SQLite write lock.
Verified session, host, lease, actor and content remain bound to the callback.
Read-only `verify` stays available without a store.

Only a newly retained create reaches the callback. A duplicate, conflicting
event, recorded outbound mirror, wrong owner or denied grant cannot reach it.
The application uses the same existing mirror ledger and schema. A fresh
Core authorization remains mandatory immediately before an effect. If the
callback fails, or its response is lost after admission, the caller must
reconcile the outcome through its authoritative effect boundary. The parent
never turns a replay into a new attempt, and a retained admission alone gives
no execution receipt.

Run `python3 -B -m unittest tests.test_signed_upstream_parent -v`. Tests use
synthetic signatures, real SQLite admission and a separate effect ledger.
Three fresh processes cover an effect with a lost response followed by two
replays. The independent ledger observes one recorded input. A deliberate
mutation allowing the retained duplicate to reach the callback fails the
fresh-process test. Recorded mirrors and a grant that changes host during
admission are denied before the callback. This covers signed ordinary creates.
Provider edit/delete ordering and the authenticated production effect
transport remain separate work. No live Slack or native runtime was used.

Local verification used base `bb1aa8695896f54057d1b64aab5eac6288cc2e73`,
Python 3.13.18 on macOS arm64, and the upstream revisions specified above.
The compatibility suite passed 528 tests with seven skips in each of normal
and optimized Python, with the exact legacy fixture at
`040b71f2213a34f34e6b6a40124ed1164b93ce30`. The pinned upstream adapter suite
passed 16 tests in each mode. Scaffold, Ruff and the mirroring audit passed.
Repo-wide static quality reported the same eight diagnostics for unavailable
visual dependencies and Linux process APIs on base and candidate.

```text
1c12ebe6f719e6e79bf1ecc9fa0fba9a8a0b1193b7a5ae259aaf48fcd6124bbe  runspindle_tether/signed_parent.py
a7c69f2e653eeb85089b999f64829a3d4e75df763dc43d077362a65b03b322e6  tests/test_signed_upstream_parent.py
c00a02eeb8405751a2b32da2b79bafa582a55c70f1a4b591e036e34f09b997a8  upstream/requirements.txt
96737a88d40a6157cb4487f67a160b7261edc639450b69695885b7aaa0bdec68  upstream/pins.json
```
