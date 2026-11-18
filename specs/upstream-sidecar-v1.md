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
The gate never invokes that route directly. Its opaque current destination is
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
13 original-upstream adapter tests pass normally and with optimized Python.
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
