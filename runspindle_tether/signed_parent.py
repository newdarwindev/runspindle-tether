"""Parent-process original Slack verification; no upstream namespace or transport.

Use in the existing Runspindle Tether parent, not the upstream application's process.
The parent still owns the actual authenticated IPC/Core authority integration.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from tether.slack_ingress import SlackMessageVerifier

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

    def verify(
        self, raw: bytes, headers: tuple[tuple[str, str], ...]
    ) -> VerifiedSlackInput:
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
            self.owner.session_id,
            self.owner.host_id,
            self.owner.lease_epoch,
            "send_input",
            digest({"text": text}),
        )
        return VerifiedSlackInput(action, text, hashlib.sha256(raw).hexdigest())

    def __call__(
        self, raw: bytes, headers: tuple[tuple[str, str], ...]
    ) -> VerifiedAction:
        return self.verify(raw, headers).action
