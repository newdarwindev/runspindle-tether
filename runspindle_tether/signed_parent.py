"""Parent-process original Slack verification; no upstream namespace or transport.

Use in the existing Runspindle Tether parent, not the upstream application's process.
The parent still owns the actual authenticated IPC/Core authority integration.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable

from tether.admission import Admission, Grant, Identity
from tether.sanitization import Sanitizer
from tether.slack_ingress import (
    MAX_SKEW_SECONDS,
    Route,
    SignedSlackIngress,
    SlackMessageVerifier,
)

from .authority import Denied, VerifiedAction, digest


@dataclass(frozen=True)
class OwnerBinding:
    session_id: str
    host_id: str
    lease_epoch: int

    def validate(self) -> None:
        if any(
            type(x) is not str or not 1 <= len(x) <= 512
            for x in (self.session_id, self.host_id)
        ):
            raise Denied("explicit selected session and host required")
        if type(self.lease_epoch) is not int or self.lease_epoch < 0:
            raise Denied("exact selected lease epoch required")


@dataclass(frozen=True)
class VerifiedSlackInput:
    action: VerifiedAction
    text: str
    original_sha256: str


class SignedInputAuthenticator:
    def __init__(self, verifier: SlackMessageVerifier, owner: OwnerBinding):
        if (
            type(verifier) is not SlackMessageVerifier
            or type(owner) is not OwnerBinding
        ):
            raise Denied("original message verifier and explicit owner required")
        owner.validate()
        self.verifier, self.owner = verifier, owner
        self._retained: tuple[OwnerBinding, SignedSlackIngress] | None = None

    @classmethod
    def open(
        cls,
        path: str,
        signing_secret: bytes,
        route: Route,
        clock: Callable[[], int],
        owner: OwnerBinding,
        authorize: Callable[[Identity, str], Grant | None],
        *,
        sanitizer: Sanitizer | None = None,
        max_skew_seconds: int = MAX_SKEW_SECONDS,
    ) -> SignedInputAuthenticator:
        """Own the existing durable ingress for this exact selected owner."""
        parent = cls(
            SlackMessageVerifier(signing_secret, route, clock, max_skew_seconds), owner
        )

        def bound_grant(identity: Identity, event_digest: str) -> Grant | None:
            grant = authorize(identity, event_digest)
            if type(grant) is Grant and (grant.host_id, grant.lease_epoch) == (
                owner.host_id,
                owner.lease_epoch,
            ):
                return grant
            return None

        ingress = SignedSlackIngress(
            path,
            signing_secret,
            route,
            clock,
            bound_grant,
            sanitizer,
            max_skew_seconds,
        )
        parent._retained = (owner, ingress)
        return parent

    @property
    def admission(self) -> Admission:
        """Trusted local readback and existing outbound mirror registration."""
        if self._retained is None:
            raise Denied("durable signed input admission required")
        return self._retained[1].admission

    def close(self) -> None:
        if self._retained is not None:
            self._retained[1].close()

    def verify(
        self, raw: bytes, headers: tuple[tuple[str, str], ...]
    ) -> VerifiedSlackInput:
        owner = self.owner
        owner.validate()
        # Original verifier validates HMAC/framing/clock/installation/actor/thread,
        # rejects edits/deletes/bot output, then returns its canonical new-message.
        value = json.loads(self.verifier.verify(raw, headers))
        text = value["text"].strip()  # Exact original upstream Slack input behavior.
        if not text or text.startswith("!"):
            raise Denied("commands and empty input require separately qualified hooks")
        action = VerifiedAction(
            value["event_id"],
            value["actor_id"],
            value["workspace_id"],
            value["channel_id"],
            value["thread_id"],
            value["message_id"],
            owner.session_id,
            owner.host_id,
            owner.lease_epoch,
            "send_input",
            digest({"text": text}),
        )
        return VerifiedSlackInput(action, text, hashlib.sha256(raw).hexdigest())

    def __call__(
        self, raw: bytes, headers: tuple[tuple[str, str], ...]
    ) -> VerifiedAction:
        if self._retained is None or self.owner != self._retained[0]:
            raise Denied("durable signed input admission required for selected owner")
        # Apply the parent input policy before retaining the original message.
        verified = self.verify(raw, headers)
        if self._retained[1].ingest(raw, headers) != "admitted":
            raise Denied("signed input already retained; reconcile before dispatch")
        return verified.action
