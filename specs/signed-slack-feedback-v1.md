# Signed Slack feedback creates

Partial prerequisite for Refinery #15, not completion of that issue. This adapter
records authenticated **historical create events**, not current-message freshness.
It uses the existing Slack signature and routing implementation and existing
FeedbackStore/ProviderJournal. No parallel provider, collector, task executor or
new custom signing protocol is introduced.

## Entry points and trust

`SlackMessageVerifier.verify` in `tether/slack_ingress.py` verifies the raw body,
Slack v0 HMAC timestamp/signature and configured exact app/workspace/actor/channel/
thread, before returning normalized ordinary message bytes. `SignedSlackIngress`
continues using it for independent task admission; the feedback path never calls
Admission.ingest. Duplicate headers, wrong body signatures, expired requests,
alternate routing, bot messages, edits, deletes, structured content and unsupported
callbacks retain the existing fail-closed behavior.

`SignedSlackFeedback` in `tether/slack_feedback.py` requires explicit trusted
configuration of one signing secret, route, clock, existing journal and
`FeedbackTarget(delivery_raw, payload, message_id)`. No credential discovery occurs.
The provider producer is Slack's existing signed Events API ordinary-message
callback shape, exercised locally with invented provider-shaped bytes and an
independent HMAC signer. Real Slack, secret custody/rotation, HTTP framing/listener,
Core material authority and installation qualification are not exercised.

Only these exact, case-sensitive commands are accepted:

- `feedback positive`
- `feedback negative`
- `feedback correction <nonblank correction>`

Correction text is data, never instructions. There is no free-form message
classification, implicit reaction mapping or command that authorizes work. The
configured journal resolves the exact retained output, delivery and content digest;
the incoming message cannot nominate or override it. Both independent retention
and material-target callbacks still default to deny. Feedback authentication uses
an instance-owned in-process proof bound to normalized bytes, unavailable as a
caller-provided wire credential. Callers/process/code remain trusted, not sandboxed.

The feedback namespace hashes app/workspace/channel, feedback identity is the
signed message timestamp, and event identity is Slack's signed event ID. All new
records use revision 1. Existing SQLite duplicate/conflict rules and immutable
attribution persist across process restart. Normalized record digests, not the
raw signature/secret, are retained. This is not an archival signed-body signature
receipt that can be independently reverified later.

## Deliberate limits

An edit/delete provider notification is rejected, **not** converted into a revision
or tombstone. A stored create may therefore describe a message subsequently edited
or deleted. Consumers must not regard `state=active` as proof that the Slack message
is still current. Do not activate automatic collection/training from this adapter
until mutable-event handling and source freshness are qualified. The existing
Refinery source pin is unchanged; its bridge is not qualified against this new
adapter. Refinery #15 stays open, including edited/deleted feedback and full
cross-component family/holdout integration acceptance.

A valid signature proves configured Slack transport/actor binding, not permission
to retain, collect, train, evaluate, execute, deploy or expand account access.
FeedbackStore evidence continues declaring collection/training false. No service,
background job, dependency, credential or network configuration is added.

## Reproduction

From this source revision on an isolated runner with Python 3.12.14:

`python3 -m unittest tests.test_slack_feedback tests.test_slack_ingress -v`

The focused tests exercise real HMAC verification and actual local SQLite stores;
provider delivery and Core/retention authority are explicitly synthetic. Fixtures
are source-pinned in the tests; there are no third-party runtime dependencies.
Temporary files are cleaned by unittest cleanup and child-process finally blocks.
Independent forbidden socket/Popen observations and unchanged task/provider
ledgers check that feedback creates do not execute work. Fresh-process replay and
conflict readback use the same stores. A deliberately removed signature guard is
run against the forgery regression and must fail it. Full normal/optimized suites,
scaffold and mandatory hygiene checks are reported separately in the evidence.
