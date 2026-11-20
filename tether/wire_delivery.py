"""Version-isolated exact wire delivery beneath Core's existing outbox.

The application supplies current Core authority, retained admission, exact routing,
and request authorization. No credentials, default transport, retries or worker.
Wire readback is not a Core Delivered receipt or live-provider qualification.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from time import time_ns
from typing import Any, cast

from tether.admission import Admission, Rejected, canonical
from tether.journal import delivery, validate_context
from tether.sanitization import Sanitizer
from tether.schema import open_store
from tether.slack_upload import UploadJournal, UploadObservation
from tether.slack_wire import (
    FileBinding,
    FileIntent,
    Request,
    Scope,
    Transport,
    authorize_request,
    info_request,
)
from tether.testing import Destination, Payload

SCHEMA = """
CREATE TABLE wire_deliveries (
 operation TEXT PRIMARY KEY, envelope BLOB NOT NULL, payload_digest TEXT NOT NULL,
 scope BLOB NOT NULL, workspace TEXT NOT NULL, file_id TEXT, observed TEXT,
 conflict INTEGER NOT NULL DEFAULT 0 CHECK(conflict IN (0,1)),
 retry_action TEXT, retry_after INTEGER, UNIQUE(workspace,file_id));
CREATE TRIGGER wire_binding_immutable BEFORE UPDATE OF operation,envelope,payload_digest,scope,workspace ON wire_deliveries
 BEGIN SELECT RAISE(ABORT,'immutable wire delivery binding'); END;
CREATE TRIGGER wire_file_immutable BEFORE UPDATE OF file_id ON wire_deliveries
 WHEN OLD.file_id IS NOT NULL AND NEW.file_id IS NOT OLD.file_id
 BEGIN SELECT RAISE(ABORT,'immutable wire file identity'); END;
CREATE TRIGGER wire_observed_immutable BEFORE UPDATE OF observed ON wire_deliveries
 WHEN OLD.observed IS NOT NULL AND NEW.observed IS NOT OLD.observed
 BEGIN SELECT RAISE(ABORT,'immutable wire observed identity'); END;
CREATE TRIGGER wire_conflict_retained BEFORE UPDATE OF conflict ON wire_deliveries
 WHEN OLD.conflict=1 AND NEW.conflict!=1
 BEGIN SELECT RAISE(ABORT,'retain wire conflict'); END;
CREATE TRIGGER wire_attempt_retained BEFORE DELETE ON wire_deliveries
 BEGIN SELECT RAISE(ABORT,'retain uncertain wire attempt'); END;
"""


@dataclass(frozen=True)
class WireDeliveryObservation:
    state: str = "unknown"
    file_id: str | None = None
    message_id: str | None = None
    conflict: bool = False
    retry_action: str | None = None
    retry_after: int | None = None
    evidence_class: str = field(default="slack_wire_content_observation", init=False)


def _journal_conflict(outer: tuple[Any, ...], inner: tuple[Any, ...] | None) -> bool:
    file_id, observed, conflict, retry_action, retry_after = outer[3:]
    if conflict:
        return True
    if inner is None:
        # An unobserved reservation can precede the first inner write. Any
        # retained inner evidence proves that this is no longer that crash gap.
        return any(
            value is not None
            for value in (file_id, observed, retry_action, retry_after)
        )
    return (
        bool(inner[3])
        or (file_id is not None and file_id != inner[1])
        or (observed is not None and observed != inner[2])
    )


class WireDeliveryJournal:
    """An outer reservation permits one invocation of UploadJournal.send only.

    A crash before the inner reservation strands unknown, never grants a retry.
    Every cooperating caller must share both store paths. This class cannot adopt
    a legacy synthetic ProviderJournal database or manufacture its receipt types.
    """

    def __init__(
        self,
        path: str,
        upload_path: str,
        transport: Transport,
        admission: Admission | None = None,
        authorize: Callable[[bytes, str], bool] | None = None,
        resolve: Callable[[str, str], Destination | None] | None = None,
        authorize_wire: Callable[[Request], bool] | None = None,
        sanitizer: Sanitizer | None = None,
        history_scope: str = "channels:history",
        *,
        clock_ns: Callable[[], int] = time_ns,
    ) -> None:
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.admission, self.authorize, self.resolve = admission, authorize, resolve
        self.authorize_wire, self.transport = authorize_wire, transport
        self.upload_path, self.history_scope = upload_path, history_scope
        self.clock_ns = clock_ns
        self.db: sqlite3.Connection = open_store(path, SCHEMA, 1414135815)

    def close(self) -> None:
        self.db.close()

    def _context(self, raw: bytes, payload: Payload) -> tuple[Scope, FileIntent]:
        if self.authorize_wire is None:
            raise Rejected("wire request authority unavailable")
        operation, destination, digest = validate_context(
            raw, payload, self.sanitizer, self.admission, self.authorize, self.resolve
        )
        account = delivery(raw)["payload"]["account_id"]
        attachment = payload.attachments[0]
        intent = FileIntent(
            attachment.attachment_id,
            attachment.filename,
            attachment.content,
            payload.text,
        )
        scope = Scope(
            account,
            destination.workspace_id,
            destination.channel_id,
            destination.thread_id,
            operation,
            digest,
            self.history_scope,
        )
        scope.bind(intent)
        return scope, intent

    def _row(self, raw: bytes, scope: Scope) -> tuple[Any, ...] | None:
        row = self.db.execute(
            "SELECT envelope,payload_digest,scope,file_id,observed,conflict,retry_action,retry_after "
            "FROM wire_deliveries WHERE operation=?",
            (scope.operation_id,),
        ).fetchone()
        if row is not None and row[:3] != (
            raw,
            scope.payload_sha256,
            canonical(asdict(scope)),
        ):
            raise Rejected("wire operation binding conflict")
        return cast(tuple[Any, ...] | None, row)

    def _current(
        self, raw: bytes, payload: Payload, scope: Scope, intent: FileIntent
    ) -> None:
        if (
            self._context(raw, payload) != (scope, intent)
            or self._row(raw, scope) is None
        ):
            raise Rejected("wire delivery context changed")

    def send(self, raw: bytes, payload: Payload) -> WireDeliveryObservation:
        scope, intent = self._context(raw, payload)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self._context(raw, payload) != (scope, intent):
                raise Rejected("wire context changed awaiting reservation")
            existing = self._row(raw, scope) is not None
            if not existing:
                self.db.execute(
                    "INSERT INTO wire_deliveries(operation,envelope,payload_digest,scope,workspace) VALUES (?,?,?,?,?)",
                    (
                        scope.operation_id,
                        raw,
                        scope.payload_sha256,
                        canonical(asdict(scope)),
                        scope.workspace_id,
                    ),
                )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        # The winner alone may reach an inner send. Existing reservations must
        # never recover a missing inner reservation by starting a new upload.
        return self._observe(raw, payload, scope, intent, begin=not existing)

    def lookup(self, raw: bytes, payload: Payload) -> WireDeliveryObservation:
        scope, intent = self._context(raw, payload)
        if self._row(raw, scope) is None:
            raise Rejected("no Core-owned wire reservation")
        return self._observe(raw, payload, scope, intent, begin=False)

    def _observe(
        self,
        raw: bytes,
        payload: Payload,
        scope: Scope,
        intent: FileIntent,
        *,
        begin: bool,
    ) -> WireDeliveryObservation:
        self._current(raw, payload, scope, intent)
        row = self._row(raw, scope)
        if row is not None and row[5]:
            return WireDeliveryObservation(conflict=True)

        def retained_pair() -> tuple[tuple[Any, ...], tuple[Any, ...] | None]:
            outer = self._row(raw, scope)
            if outer is None:
                raise Rejected("wire reservation missing")
            inner = upload.db.execute(
                "SELECT scope,file_id,observed,conflict,retry_action,retry_after FROM uploads WHERE operation=?",
                (scope.operation_id,),
            ).fetchone()
            if inner is not None and inner[0] != canonical(asdict(scope)):
                raise Rejected("upload store binding conflict")
            return outer, inner

        def conflict_retained() -> bool:
            return _journal_conflict(*retained_pair())

        def allowed(request: Request) -> bool:
            self._current(raw, payload, scope, intent)
            if request.scope != scope:
                raise Rejected("wire request scope changed")
            if conflict_retained():
                return False
            result = authorize_request(request, self.authorize_wire)
            self._current(raw, payload, scope, intent)
            if request.scope != scope:
                raise Rejected("wire request scope changed")
            return result and not conflict_retained()

        # Never accept an externally preauthorized journal or mutate a shared
        # authorizer. This closure belongs only to this exact call/binding.
        upload = UploadJournal(
            self.upload_path,
            self.transport,
            allowed,
            self.sanitizer,
            clock_ns=self.clock_ns,
        )
        try:
            if conflict_retained():
                observation = UploadObservation()
            else:
                observation = (
                    upload.send(scope, intent)
                    if begin
                    else upload.lookup(scope, intent)
                )
            if type(observation) is not UploadObservation:
                raise Rejected("invalid upload observation")
            self._current(raw, payload, scope, intent)
            # Consistent lock order: outer then inner, after all provider calls.
            # Refresh the inner snapshot only after acquiring both locks and hold
            # it until the outer observation commits. No network under locks.
            self.db.execute("BEGIN IMMEDIATE")
            upload.db.execute("BEGIN IMMEDIATE")
            self._current(raw, payload, scope, intent)
            old, inner = retained_pair()
            file_id, observed = old[3], old[4]
            conflict = _journal_conflict(old, inner)
            if file_id is None and inner is not None:
                file_id = inner[1]
            confirmed = (
                observation.state == "content_match"
                and upload.cooldown.allows(scope.operation_id)
                and inner is not None
                and (
                    observation.file_id == inner[1]
                    and observation.message_ts == inner[2]
                    and observation.file_id is not None
                    and observation.message_ts is not None
                )
            )
            if confirmed and not conflict:
                # The inner read grant can change while waiting for the outer locks.
                confirmed = allowed(info_request(FileBinding(scope, file_id)))
                conflict = conflict_retained()
                if confirmed and not conflict:
                    observed = observation.message_ts
            retry_action, retry_after = (
                (inner[4], inner[5]) if inner is not None else (old[6], old[7])
            )
            self.db.execute(
                "UPDATE wire_deliveries SET file_id=?,observed=?,conflict=?,retry_action=?,retry_after=? WHERE operation=?",
                (
                    file_id,
                    observed,
                    int(conflict),
                    retry_action,
                    retry_after,
                    scope.operation_id,
                ),
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        finally:
            upload.db.rollback()
            upload.close()
        return WireDeliveryObservation(
            "content_confirmed" if confirmed and not conflict else "unknown",
            file_id,
            observed if confirmed and not conflict else None,
            conflict,
            retry_action,
            retry_after,
        )
