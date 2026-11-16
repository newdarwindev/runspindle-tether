# Exact upload authority callback binding

Partial #9/#10, extending the existing `WireClient` and `UploadJournal`. This is
synthetic component validation, not live Slack, authenticated authority or Core
outbox integration.

The baseline allowed a callback to mutate the shared frozen `Scope` (using
`object.__setattr__`) from channel C100 to C200. The upload journal had captured the
C100 binding, but allocation/upload/completion subsequently used C200. The existing
independent synthetic provider stored the completed file in C200, and only later
did lookup reject the journal binding conflict. The error came after the effect.

The wire boundary now snapshots canonical request/scope metadata and exact body
bytes before invoking its authorizer. Only closed primitive fields are read;
foreign field values are denied without invoking equality or deepcopy hooks. A changed request is rejected before the
transport call, even if the callback returns true. False and raising callbacks
remain denial; cancellation propagates with fixed diagnostics outside exception
handlers so callback text is not retained in an exception chain. Standard
KeyboardInterrupt, SystemExit, GeneratorExit and asyncio.CancelledError categories
are preserved with fixed messages.

Upload orchestration also pins original scope and intent to each invocation's
client callback, rechecking them around authorization and before the durable
claim. This covers callbacks that mutate `FileIntent` through a closure as well
as shared nested scope. The client is invocation-local, not a mutable shared
current-context slot. Existing transport/protocol and phase journal are reused;
no parallel sender or ownership system is introduced.

Early mutation produces no provider calls and no upload reservation. Mutation
observed after a durable phase claim leaves the existing unknown-outcome fence;
reopening does not retry allocation, upload or completion. Successful responses
still require the existing independent exact content/share readback. Missing or
mutated context never becomes a receipt or new send permission.

These guards detect persistent changes at observed boundaries. They are not an
adversarial in-process sandbox: authority callbacks, transport and host connections
remain trusted, and transient mutate-and-restore behavior or external mutations
after a final check are outside this guarantee. Caller-owned objects are not
repaired or restored. This does not authenticate a callback or make frozen Python
dataclasses cryptographically immutable.

Tests use existing `StoredHTTP` with a separate SQLite provider-effect database.
They inspect zero early calls/rows, exact recorded channels, later-phase call
counts, fresh-process unknown recovery, denied/raising/cancelled callbacks,
direct wire mutation and a removed-guard fault. Existing duplicate-completion
and premature-upload mutation fixtures retain their effects/assertions; only
`self.client` source anchors change to the invocation-local `client` spelling.

```
python3 -m unittest discover -s tests -p test_upload_authority_binding.py -v
python3 -O -m unittest discover -s tests -p test_upload_authority_binding.py -v
```

Actual results and unavailable qualification tools are in
`docs/upload-authority-binding-evidence.json`. No live Slack/provider calls,
credentials, deployment, access changes, migration, persistent jobs, installations
or backups are part of this work. Broader issue completion remains unclaimed.
