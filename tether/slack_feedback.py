"""Explicit signed Slack feedback creates into the existing retained store.

No task admission, provider calls, collector, training or implicit target selection.
Edited/deleted provider messages remain unsupported: this records historical facts,
not current-message freshness. See specs/signed-slack-feedback-v1.md.
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
from tether.slack_ingress import MAX_SKEW_SECONDS, Route, SlackMessageVerifier
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
