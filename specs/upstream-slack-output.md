# Original Slack output pre-effect interception

`runspindle_tether.upstream_slack_output.SlackOutput` installs a deliberately
narrow client seam on an inactive **actual pinned original**
`agent_tether.slack.bot.SlackBridge`. The original `on_output` method still selects
its session thread and invokes `chat_postMessage`; the seam checks the final
channel/thread/text immediately before the injected one-attempt transport call.
It composes the original `BridgeManager`/turn accumulator and `AuthorityGate` with
[the original-table outbox](upstream-outbox.md). There is no additional ledger.

Only one final-text output within the current task's exact authorized scope may
reach transport. Scope ends in `finally`; child tasks, late calls, nested scopes,
wrong text/destination, extra SDK arguments, duplicate calls and observed authority
revocation do not send. The original callback's return remains non-evidence;
independent outbox readback remains mandatory. A provider or authority exception
is contained before the original Slack method's exception logger, so its message
and traceback are not forwarded there. Cancellation propagates through the outbox's
sanitized unknown-effect boundary and never authorizes a repost.

## Qualification boundary

Tests execute the original SlackBridge constructor and on_output, actual manager,
original SQLModel/Alembic/SQLite, and synthetic transport/readback. They do **not**
start Slack, obtain credentials, launch the app or call the real Slack SDK. The
injected `send_once` must itself make at most one external attempt; no claim about
SDK automatic retries is made. Transport, actor source/current authorization and
independent readback remain trusted injected boundaries, not authenticated IPC.

This is a trusted isolated-process seam, not protection against arbitrary Python
code replacing `_client`, modifying the adapter, or writing the database. Runtime
ownership must prohibit such replacement and upstream app startup. The existing
ordinary upstream deletion/retention prohibition still applies. Other original
methods (commands, approval shortcuts, history, attachments, progress and autoapprove
notifications) are **not** enabled or qualified by this final-output adapter.
Do not install a real token, start the bridge, activate the old retry worker, remove
compatibility code, or label this live Slack parity based on these tests.
