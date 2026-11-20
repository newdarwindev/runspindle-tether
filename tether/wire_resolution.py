"""Explicit append-only reconciliation of a retained wire conflict, never resend."""

import asyncio
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

from tether.admission import Rejected, canonical
from tether.schema import open_store
from tether.slack_upload import ReadbackCooldown, open_upload_store
from tether.slack_wire import (
    ContentFacts,
    FileBinding,
    Request,
    WireClient,
    authorize_request,
)
from tether.testing import Payload
from tether.wire_delivery import WireDeliveryJournal

VERSION = "runspindle.wire-resolution.v1"
SCHEMA = """
CREATE TABLE decisions (
 decision_id TEXT PRIMARY KEY, operation TEXT NOT NULL,
 conflict_sha256 TEXT NOT NULL, decision BLOB NOT NULL, snapshot BLOB NOT NULL,
 UNIQUE(operation,conflict_sha256));
CREATE TRIGGER resolution_immutable BEFORE UPDATE ON decisions
 BEGIN SELECT RAISE(ABORT,'immutable resolution decision'); END;
CREATE TRIGGER resolution_retained BEFORE DELETE ON decisions
 BEGIN SELECT RAISE(ABORT,'retain resolution decision'); END;
"""


@dataclass(frozen=True)
class ResolutionDecision:
    decision_id: str
    policy_ref: str
    authorization_ref: str
    conflict_sha256: str
    core_resolution_sha256: str
    file_id: str
    message_id: str
    version: str = VERSION

    def encode(self) -> bytes:
        if self.version != VERSION:
            raise Rejected("resolution version")
        for value in (self.decision_id, self.policy_ref, self.authorization_ref):
            if not isinstance(value, str) or not re.fullmatch(
                r"[A-Za-z0-9_.:-]{1,255}", value
            ):
                raise Rejected("resolution identity")
        for value in (self.conflict_sha256, self.core_resolution_sha256):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise Rejected("resolution digest")
        if (
            not isinstance(self.file_id, str)
            or not isinstance(self.message_id, str)
            or len(self.file_id) > 255
            or len(self.message_id) > 64
            or not re.fullmatch(r"F[A-Z0-9]+", self.file_id)
            or not re.fullmatch(r"[0-9]+\.[0-9]{6}", self.message_id)
        ):
            raise Rejected("resolution selected identity")
        return canonical(asdict(self))


@dataclass(frozen=True)
class ResolutionObservation:
    state: str = "unknown"
    decision_sha256: str | None = None
    file_id: str | None = None
    message_id: str | None = None
    evidence_class: str = "slack_wire_resolution_observation"


class ResolutionJournal:
    """Original conflicts remain sticky. Every successful call reobserves bytes.

    The dedicated authorizer must validate the full canonical decision against
    current resolver policy; ordinary delivery authority alone is insufficient.
    This API never selects a winner or supplies resolver authorization itself.
    """

    def __init__(
        self,
        path: str,
        bridge: WireDeliveryJournal,
        authorize_resolution: Callable[[bytes, str, bytes], bool] | None = None,
    ) -> None:
        self.bridge = bridge
        self.authorize_resolution = authorize_resolution
        self.db = open_store(path, SCHEMA, 1414135816)
        try:
            self.inner = open_upload_store(bridge.upload_path, require_initialized=True)
        except BaseException:
            self.db.close()
            raise
        self.cooldown = ReadbackCooldown(self.inner, bridge.clock_ns)

    def close(self) -> None:
        self.inner.close()
        self.db.close()

    def _snapshot(self, raw: bytes, payload: Payload) -> bytes:
        scope, _ = self.bridge._context(raw, payload)
        outer = self.bridge._row(raw, scope)
        inner = self.inner.execute(
            "SELECT scope,file_id,observed,conflict FROM uploads WHERE operation=?",
            (scope.operation_id,),
        ).fetchone()
        if (
            outer is None
            or inner is None
            or outer[5] != 1
            or inner[3] != 1
            or outer[3] is None
            or outer[3] != inner[1]
            or inner[0] != canonical(asdict(scope))
        ):
            raise Rejected("missing exact retained conflict")
        return canonical(
            {
                "version": VERSION,
                "envelope": json.loads(raw),
                "payload_sha256": payload.digest(),
                "scope": asdict(scope),
                "outer": {
                    "file_id": outer[3],
                    "observed": outer[4],
                    "conflict": outer[5],
                },
                "inner": {
                    "file_id": inner[1],
                    "observed": inner[2],
                    "conflict": inner[3],
                },
            }
        )

    def conflict_snapshot(self, raw: bytes, payload: Payload) -> bytes:
        self.bridge.db.execute("BEGIN IMMEDIATE")
        try:
            self.inner.execute("BEGIN IMMEDIATE")
            return self._snapshot(raw, payload)
        finally:
            self.inner.rollback()
            self.bridge.db.rollback()

    def _ownership(
        self, operation: str, decision: ResolutionDecision, encoded: bytes
    ) -> None:
        rows = self.db.execute(
            "SELECT decision FROM decisions WHERE decision_id=? OR (operation=? AND conflict_sha256=?)",
            (decision.decision_id, operation, decision.conflict_sha256),
        ).fetchall()
        if any(row[0] != encoded for row in rows) or len(rows) > 1:
            raise Rejected("resolution ownership conflict")

    def _authorized(self, raw: bytes, digest: str, encoded: bytes) -> bool:
        allowed, cancelled = False, ""
        try:
            allowed = (
                self.authorize_resolution is not None
                and self.authorize_resolution(raw, digest, encoded) is True
            )
        except Exception:
            pass
        except asyncio.CancelledError:
            cancelled = "async"
        except GeneratorExit:
            cancelled = "generator"
        except KeyboardInterrupt:
            cancelled = "interrupt"
        except SystemExit:
            cancelled = "exit"
        except BaseException:
            cancelled = "other"
        # Outside handlers: discard callback causes, contexts, notes and text.
        if cancelled == "async":
            raise asyncio.CancelledError(
                "resolution authorization cancelled; outcome unknown"
            )
        if cancelled == "generator":
            raise GeneratorExit("resolution authorization cancelled; outcome unknown")
        if cancelled == "interrupt":
            raise KeyboardInterrupt(
                "resolution authorization cancelled; outcome unknown"
            )
        if cancelled == "exit":
            raise SystemExit("resolution authorization cancelled; outcome unknown")
        if cancelled:
            raise BaseException("resolution authorization cancelled; outcome unknown")
        return allowed

    def resolve(
        self, raw: bytes, payload: Payload, decision: ResolutionDecision
    ) -> ResolutionObservation:
        if (
            type(decision) is not ResolutionDecision
            or self.authorize_resolution is None
        ):
            raise Rejected("dedicated resolution authority required")
        encoded = decision.encode()
        snapshot = self.conflict_snapshot(raw, payload)
        if hashlib.sha256(snapshot).hexdigest() != decision.conflict_sha256:
            raise Rejected("resolution conflict generation changed")
        scope, intent = self.bridge._context(raw, payload)
        if json.loads(snapshot)["inner"]["file_id"] != decision.file_id:
            raise Rejected("resolution file not retained allocation")

        def current() -> None:
            if (
                self.bridge._context(raw, payload) != (scope, intent)
                or self._snapshot(raw, payload) != snapshot
            ):
                raise Rejected("resolution context changed")
            self._ownership(scope.operation_id, decision, encoded)
            if not self._authorized(raw, payload.digest(), encoded):
                raise Rejected("resolution authority denied")
            if (
                self.bridge._context(raw, payload) != (scope, intent)
                or self._snapshot(raw, payload) != snapshot
            ):
                raise Rejected("resolution authority changed context")
            self._ownership(scope.operation_id, decision, encoded)

        def allowed(request: Request) -> bool:
            current()
            if request.scope != scope or request.action not in (
                "info",
                "replies",
                "download",
            ):
                raise Rejected("resolution is readback only")
            result = authorize_request(request, self.bridge.authorize_wire)
            current()
            return result and self.cooldown.allows(scope.operation_id)

        current()
        if not self.cooldown.allows(scope.operation_id):
            return ResolutionObservation()
        result = WireClient(self.bridge.transport, allowed).readback(
            FileBinding(scope, decision.file_id),
            intent,
            sanitizer=self.bridge.sanitizer,
        )
        self.cooldown.record(scope.operation_id, "readback", result)
        current()
        if result.state != "content_match" or type(result.facts) is not ContentFacts:
            return ResolutionObservation()
        if (
            result.facts.file.file_id != decision.file_id
            or result.facts.message.message_ts != decision.message_id
        ):
            return ResolutionObservation()
        self.bridge.db.execute("BEGIN IMMEDIATE")
        try:
            self.inner.execute("BEGIN IMMEDIATE")
            self.db.execute("BEGIN IMMEDIATE")
            current()
            if not self.cooldown.allows(scope.operation_id):
                self.db.rollback()
                return ResolutionObservation()
            self.db.execute(
                "INSERT OR IGNORE INTO decisions VALUES (?,?,?,?,?)",
                (
                    decision.decision_id,
                    scope.operation_id,
                    decision.conflict_sha256,
                    encoded,
                    snapshot,
                ),
            )
            self._ownership(scope.operation_id, decision, encoded)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        finally:
            self.inner.rollback()
            self.bridge.db.rollback()
        return ResolutionObservation(
            "independently_reconciled_under_decision",
            hashlib.sha256(encoded).hexdigest(),
            decision.file_id,
            decision.message_id,
        )
