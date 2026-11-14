"""Bounded, process-local synthetic Slack transport for contract tests only.

No credentials, network, persistence, automatic retry or core outbox ownership.
All receipts are synthetic and cannot qualify real provider compatibility.
"""

import hashlib
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum

from tether.admission import canonical, identifier


@dataclass(frozen=True)
class Destination:
    workspace_id: str
    channel_id: str
    thread_id: str

    def validate(self) -> None:
        for value in (self.workspace_id, self.channel_id, self.thread_id):
            identifier(value)


@dataclass(frozen=True)
class Attachment:
    attachment_id: str
    filename: str
    content: bytes


@dataclass(frozen=True)
class Payload:
    text: str
    attachments: tuple[Attachment, ...] = ()

    def validate(self) -> None:
        if type(self.text) is not str or type(self.attachments) is not tuple:
            raise ValueError("invalid synthetic payload")
        if len(self.attachments) > 8:
            raise ValueError("attachment limit")
        ids: set[str] = set()
        size = len(self.text.encode("utf-8"))
        for attachment in self.attachments:
            if type(attachment) is not Attachment:
                raise ValueError("invalid attachment")
            identifier(attachment.attachment_id)
            if (
                type(attachment.filename) is not str
                or not attachment.filename
                or len(attachment.filename.encode("utf-8")) > 256
                or type(attachment.content) is not bytes
                or attachment.attachment_id in ids
            ):
                raise ValueError("invalid attachment metadata or bytes")
            ids.add(attachment.attachment_id)
            size += len(attachment.content)
        if size > 1048576:
            raise ValueError("payload limit")

    def digest(self) -> str:
        self.validate()
        return hashlib.sha256(
            canonical(
                {
                    "text": self.text,
                    "attachments": [
                        {
                            "id": a.attachment_id,
                            "filename": a.filename,
                            "sha256": hashlib.sha256(a.content).hexdigest(),
                            "bytes": len(a.content),
                        }
                        for a in self.attachments
                    ],
                }
            )
        ).hexdigest()


class Fault(Enum):
    RATE_LIMIT = "rate_limit"
    BEFORE_EFFECT = "before_effect"
    LOST_ACK = "lost_ack"
    PARTIAL_ATTACHMENTS = "partial_attachments"
    MALFORMED = "malformed"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    WRONG_THREAD = "wrong_thread"


@dataclass(frozen=True)
class Reply:
    state: str
    message_id: str | None = None
    retry_at: int | None = None
    evidence_class: str = "synthetic"


@dataclass(frozen=True)
class Record:
    destination: Destination
    operation_id: str
    message_id: str
    payload: Payload | None
    deleted: bool
    evidence_class: str = "synthetic"


@dataclass(frozen=True)
class Request:
    action: str
    destination: Destination
    operation_id: str
    message_id: str | None
    payload_digest: str | None
    at: int


class FakeSlack:
    """A bounded destination store, deliberately not an idempotent outbox.

    Repeating send can create another message: caller reconciliation must prevent
    retries after uncertain effects. Only the configured destination is accepted.
    """

    def __init__(
        self,
        destination: Destination,
        clock: Callable[[], int],
        new_id: Callable[[], str],
        limit: int = 100,
    ) -> None:
        destination.validate()
        if type(limit) is not int or limit < 1:
            raise ValueError("invalid capacity")
        self.destination = destination
        self.clock = clock
        self.new_id = new_id
        self.limit = limit
        self.requests: list[Request] = []
        self.records: dict[str, Record] = {}
        self.faults: dict[str, deque[Fault]] = {}

    def inject(self, action: str, fault: Fault) -> None:
        allowed = {
            "send": {
                Fault.RATE_LIMIT,
                Fault.BEFORE_EFFECT,
                Fault.LOST_ACK,
                Fault.PARTIAL_ATTACHMENTS,
                Fault.MALFORMED,
            },
            "update": {
                Fault.RATE_LIMIT,
                Fault.BEFORE_EFFECT,
                Fault.LOST_ACK,
                Fault.PARTIAL_ATTACHMENTS,
                Fault.MALFORMED,
            },
            "delete": {
                Fault.RATE_LIMIT,
                Fault.BEFORE_EFFECT,
                Fault.LOST_ACK,
                Fault.MALFORMED,
            },
            "readback": {
                Fault.MISSING,
                Fault.AMBIGUOUS,
                Fault.WRONG_THREAD,
                Fault.MALFORMED,
            },
        }
        if action not in allowed or fault not in allowed[action]:
            raise ValueError("unsupported fault")
        queue = self.faults.setdefault(action, deque())
        if len(queue) >= self.limit:
            raise ValueError("fault queue full")
        queue.append(fault)

    def _request(
        self,
        action: str,
        destination: Destination,
        operation_id: str,
        message_id: str | None,
        payload: Payload | None,
    ) -> Fault | None:
        destination.validate()
        identifier(operation_id)
        if message_id is not None:
            identifier(message_id)
        digest = payload.digest() if payload is not None else None
        now = self.clock()
        if type(now) is not int or now < 0:
            raise ValueError("invalid virtual clock")
        if len(self.requests) >= self.limit:
            raise ValueError("request history full")
        self.requests.append(
            Request(action, destination, operation_id, message_id, digest, now)
        )
        if destination != self.destination:
            raise ValueError("wrong destination")
        queue = self.faults.get(action)
        return queue.popleft() if queue else None

    def _write(
        self,
        action: str,
        destination: Destination,
        operation_id: str,
        payload: Payload | None,
        message_id: str | None = None,
    ) -> Reply:
        if action != "delete" and type(payload) is not Payload:
            raise ValueError("invalid synthetic payload")
        fault = self._request(action, destination, operation_id, message_id, payload)
        if fault == Fault.RATE_LIMIT:
            return Reply("rate_limited", retry_at=self.requests[-1].at + 3)
        if fault == Fault.BEFORE_EFFECT:
            return Reply("failed")
        if fault == Fault.PARTIAL_ATTACHMENTS and (
            payload is None or not payload.attachments
        ):
            raise ValueError("partial attachment fault requires an attachment")
        if action == "send":
            if len(self.records) >= self.limit:
                raise ValueError("destination store full")
            message_id = self.new_id()
            identifier(message_id)
            if message_id in self.records:
                raise ValueError("message identity collision")
        elif message_id not in self.records or self.records[message_id].deleted:
            return Reply("failed")
        if message_id is None:
            raise ValueError("missing message identity")
        actual = payload
        if fault == Fault.PARTIAL_ATTACHMENTS and payload is not None:
            actual = replace(payload, attachments=payload.attachments[:-1])
        self.records[message_id] = Record(
            destination, operation_id, message_id, actual, action == "delete"
        )
        # An applied effect with absent/malformed acknowledgement is never failed.
        if fault in (Fault.LOST_ACK, Fault.MALFORMED):
            return Reply("unknown")
        return Reply("accepted", message_id)

    def send(
        self, destination: Destination, operation_id: str, payload: Payload
    ) -> Reply:
        return self._write("send", destination, operation_id, payload)

    def update(
        self,
        destination: Destination,
        operation_id: str,
        message_id: str,
        payload: Payload,
    ) -> Reply:
        return self._write("update", destination, operation_id, payload, message_id)

    def delete(
        self, destination: Destination, operation_id: str, message_id: str
    ) -> Reply:
        return self._write("delete", destination, operation_id, None, message_id)

    def readback(self, destination: Destination, operation_id: str) -> object:
        fault = self._request("readback", destination, operation_id, None, None)
        rows = tuple(r for r in self.records.values() if r.operation_id == operation_id)
        if fault == Fault.MALFORMED:
            return {"unexpected": "synthetic-malformed-reply"}
        if fault == Fault.MISSING:
            return ()
        if fault == Fault.AMBIGUOUS:
            return rows + rows
        if fault == Fault.WRONG_THREAD:
            wrong_thread = (
                "wrong-thread-2"
                if destination.thread_id == "wrong-thread"
                else "wrong-thread"
            )
            return tuple(
                replace(r, destination=replace(destination, thread_id=wrong_thread))
                for r in rows
            )
        return rows


def confirm_readback(
    rows: object,
    destination: Destination,
    operation_id: str,
    payload: Payload | None,
    message_id: str | None = None,
) -> Reply:
    """Compare independent readback, never promote mere transport acceptance."""
    destination.validate()
    identifier(operation_id)
    if message_id is not None:
        identifier(message_id)
    if payload is not None:
        payload.validate()
    if type(rows) is not tuple or len(rows) != 1 or type(rows[0]) is not Record:
        return Reply("unknown")
    row = rows[0]
    if (
        type(row.deleted) is not bool
        or row.evidence_class != "synthetic"
        or row.destination != destination
        or row.operation_id != operation_id
        or row.payload != payload
        or row.deleted != (payload is None)
        or (message_id is not None and row.message_id != message_id)
    ):
        return Reply("unknown")
    try:
        identifier(row.message_id)
    except ValueError:
        return Reply("unknown")
    return Reply("destination_confirmed", row.message_id)
