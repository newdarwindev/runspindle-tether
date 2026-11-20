"""Durable single-attempt Slack file orchestration, using the existing wire client.

No credentials, sockets, Core receipts, retry authority or background worker.
An injected transport and exact-request authorizer remain unqualified trust seams.
"""

import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, cast

from tether.admission import canonical
from tether.sanitization import Sanitizer
from tether.schema import open_store
from tether.slack_wire import (
    ContentConflict,
    ContentFacts,
    FileBinding,
    FileIntent,
    MessageFacts,
    Request,
    Result,
    Scope,
    Ticket,
    Transport,
    WireClient,
    WireRejected,
    allocate_request,
    authorize_request,
    complete_request,
    info_request,
    upload_request,
)
from tether.testing import Attachment, Payload

SCHEMA = """
CREATE TABLE uploads (
    operation TEXT PRIMARY KEY, scope BLOB NOT NULL, workspace TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('allocating','uploading','completing')),
    file_id TEXT, observed TEXT, conflict INTEGER NOT NULL DEFAULT 0
    CHECK(conflict IN (0,1)), retry_action TEXT, retry_after INTEGER,
    UNIQUE(workspace,file_id));
CREATE TRIGGER upload_binding_immutable
    BEFORE UPDATE OF operation,scope,workspace ON uploads
    BEGIN SELECT RAISE(ABORT,'immutable upload binding'); END;
CREATE TRIGGER upload_file_immutable BEFORE UPDATE OF file_id ON uploads
    WHEN OLD.file_id IS NOT NULL OR NEW.file_id IS NULL
    BEGIN SELECT RAISE(ABORT,'immutable allocated file'); END;
CREATE TRIGGER upload_phase_forward BEFORE UPDATE OF phase ON uploads
    WHEN NOT ((OLD.phase='allocating' AND NEW.phase='uploading' AND NEW.file_id IS NOT NULL)
      OR (OLD.phase='uploading' AND NEW.phase='completing'))
    BEGIN SELECT RAISE(ABORT,'invalid upload phase'); END;
CREATE TRIGGER upload_conflict_retained BEFORE UPDATE OF conflict ON uploads
    WHEN OLD.conflict=1 AND NEW.conflict!=1
    BEGIN SELECT RAISE(ABORT,'retain upload conflict'); END;
CREATE TRIGGER upload_retained BEFORE DELETE ON uploads
    BEGIN SELECT RAISE(ABORT,'retain upload attempt'); END;
"""


@dataclass(frozen=True)
class UploadObservation:
    state: str = "unknown"
    file_id: str | None = None
    message_ts: str | None = None
    retry_action: str | None = None
    retry_after: int | None = None
    evidence_class: str = field(default="unqualified_wire_observation", init=False)


class UploadJournal:
    """One caller can attempt each upload step once; all later calls only read.

    The store must be shared by all callers for an operation. It is subordinate
    to, not a replacement for, the Core reservation and ProviderJournal. No
    conversion into their synthetic/accepted/delivered receipts is provided.
    """

    def __init__(
        self,
        path: str,
        transport: Transport,
        authorize: Callable[[Request], bool] | None = None,
        sanitizer: Sanitizer | None = None,
    ) -> None:
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.authorize = authorize
        self.client = WireClient(transport, self._allowed)
        self.db: sqlite3.Connection = open_store(path, SCHEMA, 1414135811)

    def close(self) -> None:
        self.db.close()

    def _allowed(self, request: Request) -> bool:
        return authorize_request(request, self.authorize)

    def _bound_client(
        self, scope: Scope, intent: FileIntent, binding: bytes
    ) -> tuple[WireClient, Callable[[Request], bool]]:
        def allowed(request: Request) -> bool:
            if self._context(scope, intent) != binding:
                raise WireRejected("upload context changed")
            result = self._allowed(request)
            if self._context(scope, intent) != binding:
                raise WireRejected("upload context changed")
            return result

        return WireClient(self.client.transport, allowed), allowed

    def _context(self, scope: Scope, intent: FileIntent) -> bytes:
        if type(scope) is not Scope or type(intent) is not FileIntent:
            raise WireRejected("upload context type")
        scope.bind(intent)
        fields = asdict(scope)
        self.sanitizer.require_clean(fields)
        self.sanitizer.require_payload(
            Payload(
                intent.text,
                (Attachment(intent.artifact_id, intent.filename, intent.content),),
            )
        )
        return canonical(fields)

    def _row(self, scope: Scope, binding: bytes) -> tuple[Any, ...] | None:
        row = self.db.execute(
            "SELECT scope,phase,file_id,observed,conflict,retry_action,retry_after "
            "FROM uploads WHERE operation=?",
            (scope.operation_id,),
        ).fetchone()
        if row is not None and row[0] != binding:
            raise WireRejected("upload operation binding conflict")
        return cast(tuple[Any, ...] | None, row)

    def _record_delay(self, scope: Scope, action: str, result: Result) -> None:
        if result.retry_after is not None:
            self.db.execute(
                "UPDATE uploads SET retry_action=?,retry_after=? WHERE operation=?",
                (action, result.retry_after, scope.operation_id),
            )

    def send(self, scope: Scope, intent: FileIntent) -> UploadObservation:
        binding = self._context(scope, intent)
        client, allowed = self._bound_client(scope, intent, binding)
        # Existing operations need only read authority, never new send authority.
        if self._row(scope, binding) is not None:
            return self.lookup(scope, intent)
        first = allocate_request(scope, intent)
        if not allowed(first):
            raise WireRejected("upload request not authorized")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self._context(scope, intent) != binding:
                raise WireRejected("upload context changed")
            existing = self._row(scope, binding) is not None
            if not existing:
                self.db.execute(
                    "INSERT INTO uploads(operation,scope,workspace,phase) VALUES (?,?,?,'allocating')",
                    (scope.operation_id, binding, scope.workspace_id),
                )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        if existing:
            return self.lookup(scope, intent)
        # Only the invocation which committed the reservation advances. A process
        # death even before the first request conservatively consumes the attempt.
        allocated = client.allocate(scope, intent)
        self._record_delay(scope, "allocate", allocated)
        if allocated.state != "parsed" or type(allocated.facts) is not Ticket:
            return self._unknown(scope, binding)
        ticket = allocated.facts
        # Validate and authorize before persisting any provider-derived identity.
        self.sanitizer.require_clean([ticket.file_id, ticket.upload_url])
        request = upload_request(ticket, intent)
        if not allowed(request):
            return self._unknown(scope, binding)
        self.db.execute(
            "UPDATE uploads SET file_id=?,phase='uploading' WHERE operation=?",
            (ticket.file_id, scope.operation_id),
        )
        uploaded = client.upload(ticket, intent)
        self._record_delay(scope, "upload", uploaded)
        if uploaded.state != "upload_response":
            return self._unknown(scope, binding)
        if not allowed(complete_request(ticket, intent)):
            return self._unknown(scope, binding)
        self.db.execute(
            "UPDATE uploads SET phase='completing' WHERE operation=?",
            (scope.operation_id,),
        )
        completed = client.complete(ticket, intent)
        self._record_delay(scope, "complete", completed)
        # Completion acknowledgement is not delivery, including a parsed success.
        # An uncertain completion is reconciled, never completed a second time.
        return self.lookup(scope, intent)

    def _unknown(self, scope: Scope, binding: bytes) -> UploadObservation:
        row = self._row(scope, binding)
        if row is None:
            return UploadObservation()
        return UploadObservation(
            file_id=row[2], retry_action=row[5], retry_after=row[6]
        )

    def lookup(self, scope: Scope, intent: FileIntent) -> UploadObservation:
        binding = self._context(scope, intent)
        client, allowed = self._bound_client(scope, intent, binding)
        row = self._row(scope, binding)
        # Bytes at the provider cannot establish that this operation reached
        # completion intent. Earlier phases can retain only an unknown attempt.
        if row is None or row[1] != "completing" or row[2] is None or row[4]:
            return self._unknown(scope, binding)
        file = FileBinding(scope, row[2])
        self.sanitizer.require_clean(file.file_id)
        result = client.readback(file, intent, sanitizer=self.sanitizer)
        self._record_delay(scope, "readback", result)
        if not (
            (result.state == "content_match" and type(result.facts) is ContentFacts)
            or (
                result.state == "content_conflict"
                and type(result.facts) is ContentConflict
            )
        ):
            return self._unknown(scope, binding)
        facts = result.facts
        # Both branches contain independently compared bytes and exact shares.
        # Missing/incomplete/malformed responses never become conflict evidence.
        messages: tuple[MessageFacts, ...]
        if type(facts) is ContentFacts:
            messages = (facts.message,)
        elif type(facts) is ContentConflict:
            messages = facts.messages
        else:
            return self._unknown(scope, binding)
        self.sanitizer.require_clean(
            [
                [
                    [message.message_ts, message.thread_ts, message.text]
                    for message in messages
                ],
                facts.file.file_id,
                facts.file.filename,
                facts.file.download_url,
                facts.downloaded_sha256,
            ]
        )
        # No network under a SQLite lock. Recheck authority after observation and
        # after waiting for the lock before retaining a successful observation.
        check = info_request(file)
        if not allowed(check):
            return self._unknown(scope, binding)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self._row(scope, binding)
            if row is None or not allowed(check):
                self.db.rollback()
                return self._unknown(scope, binding)
            conflict = (
                bool(row[4])
                or type(facts) is ContentConflict
                or row[3] not in (None, messages[0].message_ts)
            )
            self.db.execute(
                "UPDATE uploads SET observed=?,conflict=? WHERE operation=?",
                (
                    row[3] if conflict else messages[0].message_ts,
                    int(conflict),
                    scope.operation_id,
                ),
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        if conflict:
            return self._unknown(scope, binding)
        return UploadObservation("content_match", file.file_id, messages[0].message_ts)
