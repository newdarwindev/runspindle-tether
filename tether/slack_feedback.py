"""Explicit signed Slack feedback creates into the existing retained store.

No task admission, provider calls, collector, training or implicit target selection.
Feedback-message edits/deletes and reaction removals revoke their own identities.
Explicit target-output invalidation fences linked reaction eligibility. The
independent target verifier must still establish current output validity. Reaction intake
remains a separate API, not task admission. See specs/signed-slack-feedback-v1.md.
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tether.admission import Identity, Rejected, canonical, identifier
from tether.feedback import FeedbackGrant, FeedbackStore
from tether.journal import ProviderJournal
from tether.sanitization import Sanitizer
from tether.slack_ingress import (
    MAX_SKEW_SECONDS,
    Route,
    SlackMessageVerifier,
    _routing_fields,
)
from tether.slack_wire import _id, _ts
from tether.testing import Payload


@dataclass(frozen=True)
class FeedbackTarget:
    """Trusted configuration, never fields supplied by the incoming message."""

    delivery_raw: bytes
    payload: Payload
    message_id: str


@dataclass(frozen=True)
class _Proof:
    owner: object = field(repr=False)
    digest: str


@dataclass(frozen=True)
class _InvalidationProof:
    owner: object = field(repr=False)
    digest: str


class SignedSlackFeedback:
    """One installation/actor/thread and one exact retained output per instance.

    A signing secret authenticates Slack transport, not retention consent. The
    caller must provide independent retention and source-target authority. Secret
    custody and the ingress HTTP listener remain the caller's responsibility.
    """

    def __init__(
        self,
        path: str,
        signing_secret: bytes,
        route: Route,
        clock: Callable[[], int],
        journal: ProviderJournal,
        target: FeedbackTarget,
        authorize_retention: Callable[[Identity, str, str], FeedbackGrant | None]
        | None = None,
        verify_target: Callable[[bytes, Payload, dict[str, Any]], bool] | None = None,
        sanitizer: Sanitizer | None = None,
        max_skew_seconds: int = MAX_SKEW_SECONDS,
        *,
        authorize_invalidation: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        self._verifier = SlackMessageVerifier(
            signing_secret, route, clock, max_skew_seconds
        )
        if (
            type(target) is not FeedbackTarget
            or type(target.delivery_raw) is not bytes
            or type(target.payload) is not Payload
        ):
            raise Rejected("feedback target configuration")
        identifier(target.message_id)
        self._route = route
        self._target = target
        self._owner = object()
        # The app/workspace/channel scope prevents independent installations or
        # channels from colliding on a Slack message timestamp.
        self.namespace = (
            "slack:"
            + hashlib.sha256(
                canonical([route.app_id, route.workspace_id, route.channel_id])
            ).hexdigest()
        )
        self.store = FeedbackStore(
            path,
            journal,
            self._authenticate,
            authorize_retention,
            verify_target,
            sanitizer,
            authenticate_invalidation=self._authenticate_invalidation,
            authorize_invalidation=authorize_invalidation,
        )

    def close(self) -> None:
        self.store.close()

    def _authenticate(self, raw: bytes, proof: object) -> Identity | None:
        if (
            type(proof) is _Proof
            and proof.owner is self._owner
            and proof.digest == hashlib.sha256(raw).hexdigest()
        ):
            return self._route.identity
        return None

    def ingest(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> str:
        message = json.loads(self._verifier.verify(raw, headers))
        text = message["text"]
        correction = None
        if text == "feedback positive":
            judgment = "positive"
        elif text == "feedback negative":
            judgment = "negative"
        elif text.startswith("feedback correction ") and text[20:].strip():
            judgment = "correction"
            correction = text[20:]
        else:
            raise Rejected("unsupported feedback command")
        # Resolve from actual retained delivery evidence. No target identifiers
        # from the signed message or free-form correction are used as authority.
        target = self.store.journal.retained_target(
            self._target.delivery_raw, self._target.payload, self._target.message_id
        )
        event = canonical(
            {
                "version": "runspindle.tether.feedback.v1",
                "namespace": self.namespace,
                "event_id": message["event_id"],
                "feedback_id": message["message_id"],
                "revision": 1,
                "predecessor": None,
                "actor_id": message["actor_id"],
                "workspace_id": message["workspace_id"],
                "channel_id": message["channel_id"],
                "thread_id": message["thread_id"],
                "kind": "create",
                "judgment": judgment,
                "correction": correction,
                "target": target,
            }
        )
        proof = _Proof(self._owner, hashlib.sha256(event).hexdigest())
        return self.store.ingest(
            event, proof, self._target.delivery_raw, self._target.payload
        )

    def react(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> str:
        """Retain an exact-output thumbs-up, or fence its removal permanently.

        No implicit retention/use consent, task authority or deployment approval.
        Re-add after removal requires a new reviewed lifecycle; it cannot revive
        this identity because delayed provider events have no total ordering.
        """
        value = self._verifier.verify_callback(raw, headers, reaction=True)
        event = value["event"]
        route = self._route
        _routing_fields(event, route.workspace_id)
        item = event.get("item")
        if (
            event.get("user") != route.actor_id
            or event.get("reaction") not in ("+1", "thumbsup")
            or type(item) is not dict
            or set(item) != {"type", "channel", "ts"}
            or item.get("type") != "message"
            or item.get("channel") != route.channel_id
            or item.get("ts") != self._target.message_id
        ):
            raise Rejected("Slack reaction actor, kind or exact target")
        _ts(event.get("event_ts"))
        if any(k in event for k in ("bot_id", "bot_profile", "app_id", "subtype")):
            raise Rejected("unsupported Slack reaction identity")
        target = self.store.journal.retained_target(
            self._target.delivery_raw, self._target.payload, self._target.message_id
        )
        feedback_id = (
            "reaction:"
            + hashlib.sha256(
                canonical(
                    [
                        self.namespace,
                        route.actor_id,
                        self._target.message_id,
                        "thumbs_up",
                    ]
                )
            ).hexdigest()
        )
        if event["type"] == "reaction_removed":
            normalized = canonical(
                dict(
                    version="runspindle.tether.provider-invalidation.v1",
                    namespace=self.namespace,
                    app_id=route.app_id,
                    workspace_id=route.workspace_id,
                    channel_id=route.channel_id,
                    feedback_id=feedback_id,
                    event_id=value["event_id"],
                    body_sha256=hashlib.sha256(raw).hexdigest(),
                    cause="reaction_removed",
                    author_hint=route.actor_id,
                    thread_hint=route.thread_ts,
                    target=target,
                )
            )
            return self.store.invalidate(
                normalized,
                _InvalidationProof(self._owner, hashlib.sha256(normalized).hexdigest()),
                self._target.delivery_raw,
                self._target.payload,
            )
        normalized = canonical(
            dict(
                version="runspindle.tether.feedback.v1",
                namespace=self.namespace,
                event_id=value["event_id"],
                feedback_id=feedback_id,
                revision=1,
                predecessor=None,
                actor_id=route.actor_id,
                workspace_id=route.workspace_id,
                channel_id=route.channel_id,
                thread_id=route.thread_ts,
                kind="create",
                judgment="thumbs_up",
                correction=None,
                target=target,
            )
        )
        return self.store.ingest(
            normalized,
            _Proof(self._owner, hashlib.sha256(normalized).hexdigest()),
            self._target.delivery_raw,
            self._target.payload,
        )

    def _authenticate_invalidation(self, raw: bytes, proof: object) -> bool:
        return (
            type(proof) is _InvalidationProof
            and proof.owner is self._owner
            and proof.digest == hashlib.sha256(raw).hexdigest()
        )

    def invalidate_target(
        self, raw: bytes, headers: tuple[tuple[str, str], ...]
    ) -> str:
        """Fence the exact delivered output, not its reacting human's message.

        Bot/user authorship is not inferred as the reactor. Signature, installation,
        exact destination and retained target plus independent revocation authority
        authorize this negative observation only.
        """
        value = self._verifier.verify_callback(raw, headers)
        event = value["event"]
        route = self._route
        if event.get("channel") != route.channel_id or event.get("hidden") is not True:
            raise Rejected("Slack target invalidation route")
        _routing_fields(event, route.workspace_id)
        cause = event.get("subtype")
        if cause == "message_changed":
            message = event.get("message")
            if type(message) is not dict or message.get("type") != "message":
                raise Rejected("Slack target invalidation message")
            stamp = _ts(message.get("ts"))
            _routing_fields(message, route.workspace_id)
        elif cause == "message_deleted":
            stamp = _ts(event.get("deleted_ts"))
            message = {}
        else:
            raise Rejected("unsupported Slack target invalidation")
        if stamp != self._target.message_id:
            raise Rejected("Slack target invalidation exact output")
        previous = event.get("previous_message", {})
        if type(previous) is not dict or previous.get("ts", stamp) != stamp:
            raise Rejected("Slack target previous identity")
        for item in (event, message, previous):
            _routing_fields(item, route.workspace_id)
            if item.get("thread_ts", route.thread_ts) != route.thread_ts:
                raise Rejected("Slack target thread mismatch")
        target = self.store.journal.retained_target(
            self._target.delivery_raw, self._target.payload, self._target.message_id
        )
        normalized = canonical(
            dict(
                version="runspindle.tether.provider-invalidation.v1",
                namespace=self.namespace,
                app_id=route.app_id,
                workspace_id=route.workspace_id,
                channel_id=route.channel_id,
                feedback_id=stamp,
                event_id=value["event_id"],
                body_sha256=hashlib.sha256(raw).hexdigest(),
                cause=cause,
                author_hint=None,
                thread_hint=route.thread_ts,
                target=target,
            )
        )
        return self.store.invalidate(
            normalized,
            _InvalidationProof(self._owner, hashlib.sha256(normalized).hexdigest()),
            self._target.delivery_raw,
            self._target.payload,
        )

    def invalidate(self, raw: bytes, headers: tuple[tuple[str, str], ...]) -> str:
        """Authenticated provider mutation is a negative observation, never authored feedback."""
        value = self._verifier.verify_callback(raw, headers)
        event = value["event"]
        route = self._route
        if event.get("channel") != route.channel_id or event.get("hidden") is not True:
            raise Rejected("Slack invalidation route or kind")
        _routing_fields(event, route.workspace_id)
        cause = event.get("subtype")
        author = thread = None
        if cause == "message_changed":
            message = event.get("message")
            if type(message) is not dict or message.get("type") != "message":
                raise Rejected("Slack invalidation message")
            stamp = _ts(message.get("ts"))
            author = message.get("user")
            thread = message.get("thread_ts")
            _routing_fields(message, route.workspace_id)
            if any(
                k in message for k in ("bot_id", "bot_profile", "app_id", "subtype")
            ):
                raise Rejected("Slack invalidation message type")
        elif cause == "message_deleted":
            stamp = _ts(event.get("deleted_ts"))
        else:
            raise Rejected("unsupported Slack invalidation")
        # Previous content is never retained. Validate any routing/identity hints,
        # but do not require them: Slack documents deletes without these fields.
        previous = event.get("previous_message")
        if previous is not None:
            if type(previous) is not dict or previous.get("ts") != stamp:
                raise Rejected("Slack invalidation previous identity")
            _routing_fields(previous, route.workspace_id)
            if author is not None and previous.get("user", author) != author:
                raise Rejected("Slack invalidation author mismatch")
            author = previous.get("user", author)
            if thread is not None and previous.get("thread_ts", thread) != thread:
                raise Rejected("Slack invalidation thread mismatch")
            thread = previous.get("thread_ts", thread)
        for item in (event,):
            if item.get("user") is not None:
                # Top-level user is not documented as original author/editor for
                # these subtypes. Do not interpret it or grant it authority.
                raise Rejected("unsupported Slack invalidation actor hint")
            if (
                item.get("thread_ts") is not None
                and item["thread_ts"] != route.thread_ts
            ):
                raise Rejected("Slack invalidation thread mismatch")
        if author is not None:
            _id(author, "UW")
            if author != route.actor_id:
                raise Rejected("Slack invalidation author mismatch")
        if thread is not None and (_ts(thread) != route.thread_ts):
            raise Rejected("Slack invalidation thread mismatch")
        target = self.store.journal.retained_target(
            self._target.delivery_raw, self._target.payload, self._target.message_id
        )
        normalized = canonical(
            dict(
                version="runspindle.tether.provider-invalidation.v1",
                namespace=self.namespace,
                app_id=route.app_id,
                workspace_id=route.workspace_id,
                channel_id=route.channel_id,
                feedback_id=stamp,
                event_id=value["event_id"],
                body_sha256=hashlib.sha256(raw).hexdigest(),
                cause=cause,
                author_hint=author,
                thread_hint=thread,
                target=target,
            )
        )
        proof = _InvalidationProof(self._owner, hashlib.sha256(normalized).hexdigest())
        return self.store.invalidate(
            normalized, proof, self._target.delivery_raw, self._target.payload
        )
