"""Bounded OFFLINE campaign fixture, not a relay, Core outbox or retry authority.

Only FakeSlack's classified no-effect 429 may retry. All interrupted dispatches
are readback-only. The real ProviderJournal remains unchanged and never retries.
"""

import base64
import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from tether.admission import identifier
from tether.native_testing import Binding, Event
from tether.sanitization import Sanitizer
from tether.schema import open_store
from tether.testing import Attachment, FakeSlack, Payload, Reply, confirm_readback


COUNTERS = (
    "origin_observation",
    "origin_event",
    "queued",
    "rejected",
    "sent",
    "destination_confirmed",
    "dispatch_reserved",
)
SCHEMA = """
CREATE TABLE campaign_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE campaign_counts (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE campaign_operations (
 event_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL UNIQUE,
 action TEXT NOT NULL, payload TEXT NOT NULL, target TEXT,
 state TEXT NOT NULL, attempts INTEGER NOT NULL, due INTEGER NOT NULL,
 acknowledgement TEXT, receipt TEXT, terminal INTEGER NOT NULL);
"""


def validate_metadata(db: sqlite3.Connection, config: str) -> None:
    meta = [tuple(row) for row in db.execute("SELECT key,value FROM campaign_meta")]
    counts = [
        tuple(row) for row in db.execute("SELECT name,value FROM campaign_counts")
    ]
    if (
        meta != [("config", config)]
        or set(name for name, _ in counts) != set(COUNTERS)
        or len(counts) != len(COUNTERS)
        or any(type(value) is not int or value < 0 for _, value in counts)
    ):
        raise ValueError("campaign metadata rejected")


class OfflineCampaign:
    """Disposable SQLite campaign; trusted test callbacks only, no network API."""

    def __init__(
        self,
        path: Path,
        binding: Binding,
        sanitizer: Sanitizer,
        clock: Callable[[], int],
        *,
        capacity: int = 32,
        retries: int = 2,
        checkpoint: Callable[[str], None] = lambda _: None,
    ) -> None:
        binding.validate()
        sanitizer.require_clean(asdict(binding))
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError("invalid campaign capacity")
        if type(retries) is not int or not 0 <= retries <= 8:
            raise ValueError("invalid retry bound")
        self.binding, self.sanitizer, self.clock = binding, sanitizer, clock
        self.capacity, self.retries, self.checkpoint = capacity, retries, checkpoint
        self._busy = False
        config = json.dumps(
            {
                "family": "offline_campaign_v1",
                "binding": asdict(binding),
                "capacity": capacity,
                "retries": retries,
            },
            sort_keys=True,
        )
        new_file = not path.exists()
        if not new_file:
            probe = sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)
            try:
                if (
                    probe.execute("PRAGMA user_version").fetchone()[0] != 1
                    or probe.execute("PRAGMA application_id").fetchone()[0]
                    != 1413694257
                ):
                    raise ValueError("campaign family rejected")
                validate_metadata(probe, config)
            finally:
                probe.close()
        self.db = open_store(str(path), SCHEMA, 1413694257)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT key,value FROM campaign_meta").fetchall()
            if new_file and not existing:
                self.db.execute(
                    "INSERT INTO campaign_meta VALUES ('config',?)", (config,)
                )
                self.db.executemany(
                    "INSERT INTO campaign_counts VALUES (?,0)",
                    [(name,) for name in COUNTERS],
                )
            validate_metadata(self.db, config)
            self.db.commit()
            self.db.row_factory = sqlite3.Row
        except BaseException:
            self.db.rollback()
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def _now(self) -> int:
        now = self.clock()
        if type(now) is not int or not 0 <= now <= 9223372036854775807:
            raise ValueError("invalid virtual clock")
        return now

    def _count(self, name: str) -> None:
        self.db.execute(
            "UPDATE campaign_counts SET value=value+1 WHERE name=?", (name,)
        )

    def counters(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT name,value FROM campaign_counts"))

    def state(self, event_id: str) -> str | None:
        row = self.db.execute(
            "SELECT state FROM campaign_operations WHERE event_id=?", (event_id,)
        ).fetchone()
        return row[0] if row else None

    def receipt(self, event_id: str) -> str | None:
        row = self.db.execute(
            "SELECT receipt FROM campaign_operations WHERE event_id=?", (event_id,)
        ).fetchone()
        return row[0] if row else None

    def enqueue(
        self,
        event: Event,
        projection: object,
        action: str = "send",
        target: str | None = None,
    ) -> str:
        """Persist only a sanitized allowlisted projection and clean attachment bytes.

        Source capability admission happens in existing NativeSource before this
        sink. This boundary independently enforces exact identity and durable order.
        Rejected inputs are counted but their contents are never retained.
        """
        outcome = "rejected"
        encoded = ""
        try:
            if type(event) is not Event or event.binding != self.binding:
                raise ValueError("wrong binding")
            identifier(event.event_id)
            self.sanitizer.require_clean(event.event_id)
            if type(event.sequence) is not int or event.sequence < 1:
                raise ValueError("invalid sequence")
            if action not in {"send", "update", "delete"}:
                raise ValueError("unsupported action")
            if (action == "send") != (target is None):
                raise ValueError("wrong target shape")
            if target is not None:
                identifier(target)
                self.sanitizer.require_clean(target)
            clean = self.sanitizer.project(projection)
            if clean["kind"] != event.kind:
                raise ValueError("projection kind mismatch")
            payload = Payload(self.sanitizer.render(clean), event.payload.attachments)
            self.sanitizer.require_payload(payload)
            encoded = json.dumps(
                {
                    "text": payload.text,
                    "attachments": [
                        {
                            "id": a.attachment_id,
                            "filename": a.filename,
                            "content": base64.b64encode(a.content).decode("ascii"),
                        }
                        for a in payload.attachments
                    ],
                },
                sort_keys=True,
            )
            outcome = "queued"
        except (ValueError, TypeError, KeyError, AttributeError):
            pass
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._count("origin_observation")
            if outcome == "queued":
                count, sequence = self.db.execute(
                    "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM campaign_operations"
                ).fetchone()
                duplicate = self.db.execute(
                    "SELECT 1 FROM campaign_operations WHERE event_id=?",
                    (event.event_id,),
                ).fetchone()
                terminal = self.db.execute(
                    "SELECT 1 FROM campaign_operations WHERE terminal=1"
                ).fetchone()
                if (
                    terminal
                    or duplicate
                    or event.sequence != sequence + 1
                    or count >= self.capacity
                ):
                    outcome = "rejected"
            if outcome == "queued":
                self.db.execute(
                    "INSERT INTO campaign_operations VALUES (?,?,?,?,?,'queued',0,?,NULL,NULL,?)",
                    (
                        event.event_id,
                        event.sequence,
                        action,
                        encoded,
                        target,
                        self._now(),
                        int(event.kind == "final" or action == "delete"),
                    ),
                )
                self._count("origin_event")
            self._count(outcome)
            self.checkpoint("before_persist")
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self.checkpoint("after_persist")
        return outcome

    @staticmethod
    def _payload(row: sqlite3.Row) -> Payload | None:
        if row["action"] == "delete":
            return None
        value = json.loads(row["payload"])
        return Payload(
            value["text"],
            tuple(
                Attachment(
                    a["id"],
                    a["filename"],
                    base64.b64decode(a["content"], validate=True),
                )
                for a in value["attachments"]
            ),
        )

    def tick(self, provider: FakeSlack) -> str:
        if self._busy:
            raise ValueError("reentrant campaign tick")
        self._busy = True
        try:
            return self._tick(provider)
        finally:
            if self.db.in_transaction:
                self.db.rollback()
            self._busy = False

    def _tick(self, provider: FakeSlack) -> str:
        """One bounded synchronous step; unknown outcomes never return to send.

        Ordering blocks successors until exact destination confirmation or a
        proven no-effect terminal failure. Ambiguous outcomes cannot be skipped.
        """
        if (
            not isinstance(provider, FakeSlack)
            or provider.destination != self.binding.destination
        ):
            raise ValueError("offline exact-route FakeSlack required")
        now = self._now()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT * FROM campaign_operations WHERE state NOT IN ('confirmed','failed','exhausted') ORDER BY sequence LIMIT 1"
            ).fetchone()
            if row is None:
                self.db.commit()
                return "idle"
            dispatch = row["state"] in {"queued", "retry"}
            if dispatch and now < row["due"]:
                self.db.commit()
                return "waiting"
            if dispatch:
                self.db.execute(
                    "UPDATE campaign_operations SET state='unknown',attempts=attempts+1 WHERE event_id=?",
                    (row["event_id"],),
                )
                self._count("dispatch_reserved")
                self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        payload = self._payload(row)
        operation = row["event_id"]
        if not dispatch:
            try:
                reply = confirm_readback(
                    provider.readback(self.binding.destination, operation),
                    self.binding.destination,
                    operation,
                    payload,
                    row["acknowledgement"] or row["target"],
                )
            except Exception:
                return "unknown"
            if reply.state != "destination_confirmed":
                return "unknown"
            try:
                self.sanitizer.require_clean(reply.message_id)
            except ValueError:
                return "unknown"
            self.checkpoint("before_receipt")
            try:
                changed = self.db.execute(
                    "UPDATE campaign_operations SET state='confirmed',receipt=? WHERE event_id=? AND state='unknown'",
                    (reply.message_id, operation),
                ).rowcount
                if changed:
                    self._count("destination_confirmed")
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            self.checkpoint("after_receipt")
            return "confirmed"
        self.checkpoint("before_send")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            try:
                if row["action"] == "send":
                    if payload is None:
                        raise ValueError("missing payload")
                    reply = provider.send(self.binding.destination, operation, payload)
                elif row["action"] == "update":
                    if payload is None:
                        raise ValueError("missing payload")
                    reply = provider.update(
                        self.binding.destination, operation, row["target"], payload
                    )
                else:
                    reply = provider.delete(
                        self.binding.destination, operation, row["target"]
                    )
            except Exception:
                self.db.rollback()
                return "unknown"
            self.checkpoint("after_send")
            state, due = "unknown", now
            if type(reply) is not Reply or reply.evidence_class != "synthetic":
                self.db.rollback()
                return "unknown"
            valid_shape = (
                (
                    reply.state == "accepted"
                    and reply.message_id is not None
                    and reply.retry_at is None
                )
                or (
                    reply.state in {"unknown", "failed"}
                    and reply.message_id is None
                    and reply.retry_at is None
                )
                or (
                    reply.state == "rate_limited"
                    and reply.message_id is None
                    and type(reply.retry_at) is int
                    and now < reply.retry_at <= 9223372036854775807
                )
            )
            if not valid_shape:
                self.db.rollback()
                return "unknown"
            if type(reply) is Reply and reply.message_id is not None:
                try:
                    identifier(reply.message_id)
                    self.sanitizer.require_clean(reply.message_id)
                except ValueError:
                    self.db.rollback()
                    return "unknown"
            if type(reply) is Reply and reply.evidence_class == "synthetic":
                if (
                    reply.state == "rate_limited"
                    and type(reply.retry_at) is int
                    and now < reply.retry_at <= 9223372036854775807
                ):
                    state = "retry" if row["attempts"] < self.retries else "exhausted"
                    due = reply.retry_at
                elif reply.state == "failed":
                    state = "failed"
            try:
                # Writer lock spans the bounded fake call and acknowledgement.
                self.db.execute(
                    "UPDATE campaign_operations SET state=?,due=?,acknowledgement=? WHERE event_id=? AND state='unknown'",
                    (
                        state,
                        due,
                        reply.message_id if type(reply) is Reply else None,
                        operation,
                    ),
                )
                if type(reply) is Reply and reply.state == "accepted":
                    self._count("sent")
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            return state
        except BaseException:
            self.db.rollback()
            raise
