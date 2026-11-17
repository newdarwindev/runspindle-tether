"""Existing signed ordinary-create verifier wired to the new semantic store.

Raw Slack edits/deletes remain unsupported and rejected by the shared verifier.
This creates neither a server nor an issuer, subscription or execution authority.
"""

from collections.abc import Callable
from typing import Any

from tether.admission import Grant, Identity
from tether.sanitization import Sanitizer
from tether.semantic_journal import IntentReferences, SemanticAdmission
from tether.slack_ingress import (
    MAX_SKEW_SECONDS,
    Route,
    SignedSlackIngress,
    SlackMessageVerifier,
)


class SignedSemanticIngress(SignedSlackIngress):
    def __init__(
        self,
        path: str,
        signing_secret: bytes,
        route: Route,
        clock: Callable[[], int],
        *,
        account_id: str,
        references: Callable[[dict[str, Any]], IntentReferences | None] | None = None,
        authorize: Callable[[Identity, str], Grant | None] | None = None,
        sanitizer: Sanitizer | None = None,
        max_skew_seconds: int = MAX_SKEW_SECONDS,
    ) -> None:
        # Reuse byte verification and instance-bound proof unchanged, but select
        # the isolated new family explicitly instead of creating a legacy store.
        SlackMessageVerifier.__init__(
            self, signing_secret, route, clock, max_skew_seconds
        )
        self._owner = object()
        self.admission = SemanticAdmission(
            path,
            app_id=route.app_id,
            account_id=account_id,
            references=references,
            authenticate=self._authenticate,
            authorize=authorize,
            sanitizer=sanitizer,
        )
