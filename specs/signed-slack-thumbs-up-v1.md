# Signed Slack thumbs-up feedback

Implemented local component boundary: `SignedSlackFeedback.react(raw, headers)`
accepts signed Slack `reaction_added` / `reaction_removed` callbacks for `thumbsup`
or `+1` on the exact configured retained output message. It verifies the existing
installation, timestamp/HMAC and actor route, then resolves the artifact revision,
content hash and delivery identity from the existing provider journal. It performs
no provider calls and does not admit tasks. Ordinary message ingress remains
message-only. Other emoji, files, wrong actors/destinations/messages and unsupported
shared-workspace routing are rejected.

Retained `runspindle.tether.feedback.v1` events use `judgment: thumbs_up`. This is a
separate authenticated signal, not a reinterpretation of ordinary `positive`.
Consumers may use it as automatic gold-label judgment without a second quality
adjudication, but must still require independent collection/use consent, exact
output binding, current source authority, and absence of conflicts/revocation.
It never grants execution, optimization spend, model promotion or deployment.
The journal proves historical delivery, not that Slack still displays unchanged
content. `invalidate_target(raw, headers)` now records authenticated edits/deletes for the
exact configured output, including bot output without confusing its author with
the reacting human. Independent invalidation authorization remains required.
Thumbs-up intake checks the target fence before and inside its write transaction;
evidence checks it in the same read snapshot as reaction history. A target mutation
before first reaction blocks it; existing reactions become invalidated without
rewriting historical labels. No event subscription or receipt completeness is
implied: the independent target verifier/consumer must still reject stale or
unknown current output validity. Absence of a retained event is not freshness proof.
Custom FeedbackStore authenticators remain trusted adapters: merely submitting
JSON with this judgment is not authentication.

Reaction identity is `reaction:` plus SHA256 of canonical
`[namespace, actor_id, target_message_id, "thumbs_up"]`. Same-event retries are
idempotent; conflicting retained creates fail closed. Removal is an authenticated
provider invalidation with `cause: reaction_removed`, using the same identity and
independent invalidation authorization. A removal arriving before its add also
fences it. Re-add is deliberately not supported: no delayed add/replay can revive
revoked eligibility. A new reviewed lifecycle is required to change that policy.

Scope: synthetic signed callback tests and real local SQLite retention only.
No live Slack subscription, signing-secret installation, HTTP dispatch change,
external training or universal surface routing is implied. Slack is the existing
supported authenticated feedback surface; other surfaces and skin-tone aliases
remain unimplemented rather than trusted by inference. Bare emoji messages are
not reactions and are not upgraded automatically by this API.

Provider event contracts:
- https://docs.slack.dev/reference/events/reaction_added/
- https://docs.slack.dev/reference/events/reaction_removed/
