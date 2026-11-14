"""Durable provider-attempt fencing beneath (not replacing) core's outbox.

Only synthetic transport qualification exists. Missing trusted core authorization,
route resolution or retained admission denies all provider calls. No worker runs.
"""

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from tether.admission import Admission, Rejected, canonical, counter, identifier, pairs
from tether.sanitization import Sanitizer
from tether.testing import Destination, Payload, Record, Reply, confirm_readback


class Provider(Protocol):
    def send(
        self, destination: Destination, operation_id: str, payload: Payload
    ) -> Reply: ...
    def readback(self, destination: Destination, operation_id: str) -> object: ...


@dataclass(frozen=True)
class Observation:
    state: str
    message_id: str | None = None
    retry_at: int | None = None
    evidence_class: str = "synthetic_adapter"


def delivery(raw: bytes) -> dict[str, Any]:
    """Strict delivery_request subset of root runspindle.envelope.v1."""
    if type(raw) is not bytes or len(raw) > 1048576:
        raise Rejected("envelope size/encoding")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        if type(value) is not dict or set(value) != {
            "version",
            "message_type",
            "message_id",
            "binding",
            "payload",
        }:
            raise Rejected("envelope fields")
        if (
            value["version"] != "runspindle.envelope.v1"
            or value["message_type"] != "delivery_request"
        ):
            raise Rejected("envelope version/type")
        identifier(value["message_id"])
        binding = value["binding"]
        if type(binding) is not dict or set(binding) != {
            "task_id",
            "revision",
            "operation_id",
            "policy_revision",
            "host_id",
            "workspace_id",
            "lease_epoch",
        }:
            raise Rejected("binding fields")
        for key, item in binding.items():
            if key in ("revision", "lease_epoch"):
                counter(item)
            else:
                identifier(item)
        payload = value["payload"]
        if type(payload) is not dict or set(payload) != {
            "artifact_id",
            "artifact_revision",
            "sha256",
            "validator_revision",
            "account_id",
            "destination_id",
            "delivery_operation_id",
        }:
            raise Rejected("payload fields")
        for key, item in payload.items():
            if key == "artifact_revision":
                counter(item)
            elif key == "sha256":
                if type(item) is not str or not re.fullmatch("[0-9a-f]{64}", item):
                    raise Rejected("artifact digest")
            else:
                identifier(item)
        if (
            payload["delivery_operation_id"] == binding["operation_id"]
            or canonical(value) != raw
        ):
            raise Rejected("operation or canonical encoding")
        return cast(dict[str, Any], value)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise Rejected("invalid delivery envelope") from exc


class ProviderJournal:
    def __init__(
        self,
        path: str,
        admission: Admission | None = None,
        authorize: Callable[[bytes, str], bool] | None = None,
        resolve: Callable[[str, str], Destination | None] | None = None,
        sanitizer: Sanitizer | None = None,
    ) -> None:
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.admission = admission
        self.authorize = authorize
        self.resolve = resolve
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS provider_attempts (
                operation TEXT PRIMARY KEY, envelope BLOB NOT NULL,
                payload_digest TEXT NOT NULL, destination TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('attempted','accepted','unknown','rate_limited','failed')),
                acknowledgement TEXT, observed TEXT, retry_at INTEGER,
                conflict INTEGER NOT NULL DEFAULT 0 CHECK(conflict IN (0,1)));
            CREATE TRIGGER IF NOT EXISTS provider_binding_immutable
                BEFORE UPDATE OF operation,envelope,payload_digest,destination ON provider_attempts
                BEGIN SELECT RAISE(ABORT,'immutable provider binding'); END;
            CREATE TRIGGER IF NOT EXISTS provider_attempt_retained
                BEFORE DELETE ON provider_attempts
                BEGIN SELECT RAISE(ABORT,'retain uncertain provider attempt'); END;
        """)

    def close(self) -> None:
        self.db.close()

    def _artifact(self, raw: bytes, payload: Payload) -> tuple[dict[str, Any], str]:
        envelope = delivery(raw)
        self.sanitizer.require_clean(envelope)
        if type(payload) is not Payload:
            raise Rejected("payload type")
        self.sanitizer.require_payload(payload)
        digest = payload.digest()
        p = envelope["payload"]
        if (
            len(payload.attachments) != 1
            or payload.attachments[0].attachment_id != p["artifact_id"]
            or hashlib.sha256(payload.attachments[0].content).hexdigest() != p["sha256"]
        ):
            raise Rejected("exact accepted artifact required")
        return envelope, digest

    def _context(self, raw: bytes, payload: Payload) -> tuple[str, Destination, str]:
        envelope, digest = self._artifact(raw, payload)
        p, b = envelope["payload"], envelope["binding"]
        if self.admission is None or self.authorize is None or self.resolve is None:
            raise Rejected("trusted integration unavailable")
        # Core still owns accepted artifact validation and delivery authority. The
        # callback must verify both exact envelope and normalized outbound content.
        try:
            if self.authorize(raw, digest) is not True:
                raise Rejected("core delivery authorization denied")
            destination = self.resolve(p["account_id"], p["destination_id"])
        except Exception as exc:
            raise Rejected("trusted integration unavailable") from exc
        if type(destination) is not Destination:
            raise Rejected("destination unavailable")
        destination.validate()
        self.sanitizer.require_clean(
            [destination.workspace_id, destination.channel_id, destination.thread_id]
        )
        if destination.workspace_id != b["workspace_id"]:
            raise Rejected("workspace mismatch")
        admitted = any(e["binding"] == b for e in self.admission.envelopes())
        head = self.admission.db.execute(
            "SELECT revision,deleted FROM heads WHERE task=?", (b["task_id"],)
        ).fetchone()
        if not admitted or head != (str(b["revision"]), 0):
            raise Rejected("missing, superseded or deleted admission")
        return p["delivery_operation_id"], destination, digest

    def retained_target(
        self, raw: bytes, payload: Payload, message_id: str
    ) -> dict[str, Any]:
        """Historical independent readback only; no provider calls or Core acceptance.

        The immutable artifact bytes must still match the retained journal record.
        This does not check current destination existence or current task authority.
        """
        identifier(message_id)
        self.sanitizer.require_clean(message_id)
        envelope, digest = self._artifact(raw, payload)
        p, b = envelope["payload"], envelope["binding"]
        row = self.db.execute(
            "SELECT envelope,payload_digest,destination,observed,conflict FROM provider_attempts WHERE operation=?",
            (p["delivery_operation_id"],),
        ).fetchone()
        if (
            row is None
            or row[0] != raw
            or row[1] != digest
            or row[3] != message_id
            or row[4] != 0
        ):
            raise Rejected("retained target unavailable or conflicted")
        route = json.loads(row[2], object_pairs_hook=pairs)
        if type(route) is not list or len(route) != 3:
            raise Rejected("retained target route")
        for item in route:
            identifier(item)
        if route[0] != b["workspace_id"]:
            raise Rejected("retained workspace mismatch")
        target = {
            "task_id": b["task_id"],
            "task_revision": b["revision"],
            "artifact_id": p["artifact_id"],
            "artifact_revision": p["artifact_revision"],
            "artifact_sha256": p["sha256"],
            "delivery_operation_id": p["delivery_operation_id"],
            "message_id": message_id,
            "payload_sha256": digest,
            "workspace_id": route[0],
            "channel_id": route[1],
            "thread_id": route[2],
        }
        self.sanitizer.require_clean(target)
        return target

    @staticmethod
    def _route(destination: Destination) -> str:
        encoded: str = canonical(
            [destination.workspace_id, destination.channel_id, destination.thread_id]
        ).decode()
        return encoded

    def _row(
        self, operation: str, raw: bytes, digest: str, route: str
    ) -> tuple[Any, ...] | None:
        row = self.db.execute(
            "SELECT envelope,payload_digest,destination,state,acknowledgement,observed,retry_at,conflict FROM provider_attempts WHERE operation=?",
            (operation,),
        ).fetchone()
        if row is not None and row[:3] != (raw, digest, route):
            raise Rejected("provider operation binding conflict")
        return cast(tuple[Any, ...] | None, row)

    def send(self, raw: bytes, payload: Payload, provider: Provider) -> Observation:
        operation, destination, digest = self._context(raw, payload)
        route = self._route(destination)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self._row(operation, raw, digest, route)
            if old is not None:
                self.db.execute("ROLLBACK")
                # Existing reservations only reconcile; never retry a provider send.
                return self.lookup(raw, payload, provider)
            self.db.execute(
                "INSERT INTO provider_attempts(operation,envelope,payload_digest,destination,state) VALUES (?,?,?,?,'attempted')",
                (operation, raw, digest, route),
            )
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        # A crash/cancellation after COMMIT retains the send fence. Recheck current
        # admission/core authority immediately before the only provider-send path.
        if self._context(raw, payload) != (operation, destination, digest):
            raise Rejected("trusted context changed")
        try:
            reply = provider.send(destination, operation, payload)
        except Exception:
            reply = Reply("unknown")
        if type(reply) is not Reply or reply.evidence_class != "synthetic":
            reply = Reply("unknown")
        state, ack, retry_at = "unknown", None, None
        if reply.state == "accepted" and reply.message_id is not None:
            try:
                identifier(reply.message_id)
                self.sanitizer.require_clean(reply.message_id)
                state, ack = "accepted", reply.message_id
            except ValueError:
                pass
        elif (
            reply.state == "rate_limited"
            and type(reply.retry_at) is int
            and 0 <= reply.retry_at <= 2**63 - 1
        ):
            state, retry_at = "rate_limited", reply.retry_at
        elif reply.state == "failed":
            state = "failed"
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self._row(operation, raw, digest, route)
            if row is None:
                raise Rejected("missing durable attempt")
            conflict = bool(row[7]) or (
                ack is not None and row[5] is not None and ack != row[5]
            )
            self.db.execute(
                "UPDATE provider_attempts SET state=?,acknowledgement=?,retry_at=?,conflict=? WHERE operation=?",
                (state, ack, retry_at, conflict, operation),
            )
            self.db.execute("COMMIT")
            return Observation(
                "unknown" if conflict else state,
                ack if not conflict else None,
                retry_at,
            )
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def lookup(self, raw: bytes, payload: Payload, provider: Provider) -> Observation:
        operation, destination, digest = self._context(raw, payload)
        route = self._route(destination)
        row = self._row(operation, raw, digest, route)
        if row is None:
            raise Rejected("no core-owned provider attempt")
        if row[7]:
            return Observation("unknown")
        try:
            rows = provider.readback(destination, operation)
        except Exception:
            return Observation("unknown")
        if self._context(raw, payload) != (operation, destination, digest):
            raise Rejected("trusted context changed during readback")
        if type(rows) is tuple:
            try:
                for candidate in rows:
                    if type(candidate) is Record:
                        self.sanitizer.require_clean(candidate.message_id)
            except ValueError:
                return Observation("unknown")
        observation = confirm_readback(rows, destination, operation, payload)
        # Only exact-content/binding rows can contradict previously observed IDs.
        valid = []
        if type(rows) is tuple:
            for candidate in rows:
                if (
                    type(candidate) is Record
                    and confirm_readback(
                        (candidate,), destination, operation, payload
                    ).state
                    == "destination_confirmed"
                ):
                    valid.append(candidate.message_id)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            # Acquiring the write lock can wait. Do not publish an observation
            # using authority checked before that potentially blocking boundary.
            if self._context(raw, payload) != (operation, destination, digest):
                raise Rejected("trusted context changed while awaiting journal lock")
            current = self._row(operation, raw, digest, route)
            if current is None:
                raise Rejected("missing durable attempt")
            ids = set(valid + [x for x in (current[4], current[5]) if x is not None])
            conflict = bool(current[7]) or len(ids) > 1
            observed = current[5]
            if not conflict and observation.state == "destination_confirmed":
                observed = observation.message_id
            self.db.execute(
                "UPDATE provider_attempts SET observed=?,conflict=? WHERE operation=?",
                (observed, conflict, operation),
            )
            self.db.execute("COMMIT")
            return (
                Observation("destination_confirmed", observed)
                if not conflict and observation.state == "destination_confirmed"
                else Observation("unknown")
            )
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
