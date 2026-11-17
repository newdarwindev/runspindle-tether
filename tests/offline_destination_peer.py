"""Independent disposable SQLite backing for the EXISTING FakeSlack contract.

No protocol implementation/network: effects and request history are snapshots of
FakeSlack's real outputs, committed before returning a reply to the campaign.
"""

import base64
import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from tether.testing import (
    Attachment,
    Destination,
    FakeSlack,
    Payload,
    Record,
    Reply,
    Request,
)


class StoredFakeSlack(FakeSlack):
    def __init__(
        self, path: Path, destination: Destination, clock: Callable[[], int]
    ) -> None:
        super().__init__(destination, clock, lambda: f"message-{len(self.records) + 1}")
        self.store = sqlite3.connect(path, isolation_level=None, timeout=5)
        self.store.execute(
            "CREATE TABLE IF NOT EXISTS peer (id INTEGER PRIMARY KEY, snapshot TEXT NOT NULL)"
        )
        self.store.execute(
            "INSERT OR IGNORE INTO peer VALUES (1,?)",
            (
                json.dumps(
                    {"destination": asdict(destination), "records": [], "requests": []}
                ),
            ),
        )
        self._load()

    def close(self) -> None:
        self.store.close()

    def _load(self) -> None:
        value = json.loads(
            self.store.execute("SELECT snapshot FROM peer WHERE id=1").fetchone()[0]
        )
        if value["destination"] != asdict(self.destination):
            raise ValueError("peer route mismatch")
        self.records = {}
        for row in value["records"]:
            payload = row["payload"]
            if payload is not None:
                payload = Payload(
                    payload["text"],
                    tuple(
                        Attachment(
                            a["attachment_id"],
                            a["filename"],
                            base64.b64decode(a["content"], validate=True),
                        )
                        for a in payload["attachments"]
                    ),
                )
            record = Record(
                Destination(**row["destination"]),
                row["operation_id"],
                row["message_id"],
                payload,
                row["deleted"],
                row["evidence_class"],
            )
            self.records[record.message_id] = record
        self.requests = [
            Request(**{**row, "destination": Destination(**row["destination"])})
            for row in value["requests"]
        ]

    def _save(self) -> None:
        rows = []
        for record in self.records.values():
            row = asdict(record)
            if record.payload is not None:
                for a in row["payload"]["attachments"]:
                    a["content"] = base64.b64encode(a["content"]).decode("ascii")
            rows.append(row)
        self.store.execute(
            "UPDATE peer SET snapshot=? WHERE id=1",
            (
                json.dumps(
                    {
                        "destination": asdict(self.destination),
                        "records": rows,
                        "requests": [asdict(r) for r in self.requests],
                    },
                    sort_keys=True,
                ),
            ),
        )

    def _write(
        self,
        action: str,
        destination: Destination,
        operation_id: str,
        payload: Payload | None,
        message_id: str | None = None,
    ) -> Reply:
        self.store.execute("BEGIN IMMEDIATE")
        try:
            self._load()
            reply = super()._write(
                action, destination, operation_id, payload, message_id
            )
            self._save()
            self.store.commit()
            return reply
        except BaseException:
            self.store.rollback()
            raise

    def readback(self, destination: Destination, operation_id: str) -> object:
        self.store.execute("BEGIN IMMEDIATE")
        try:
            self._load()
            rows = super().readback(destination, operation_id)
            self._save()
            self.store.commit()
            return rows
        except BaseException:
            self.store.rollback()
            raise
