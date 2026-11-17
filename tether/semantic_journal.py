"""Version-isolated, atomic semantic candidate journal; never sends or grants.

No legacy store adoption. A trusted issuer must separately authorize the latest
full intent before a complete chain is submitted to Core's atomic batch lane.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from tether.admission import (
    SCHEMA,
    Admission,
    Grant,
    Identity,
    Rejected,
    canonical,
    identifier,
)
from tether.intent import build_intent, decode_intent, digest
from tether.sanitization import Sanitizer
from tether.schema import open_store

FAMILY = 1413545987
BATCH_VERSION = "runspindle.intent-batch.v1"
MAX_EXECUTABLE_REVISIONS = 64
JOURNAL_SCHEMA = (
    SCHEMA
    + """
CREATE TABLE intent_config (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), app_id TEXT NOT NULL, account_id TEXT NOT NULL);
CREATE TABLE intent_candidates (
    task TEXT NOT NULL, revision TEXT NOT NULL, wire TEXT NOT NULL, wire_sha256 TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
    PRIMARY KEY(task,revision));
CREATE TABLE intent_observations (
    task TEXT NOT NULL, revision TEXT NOT NULL, batch_sha256 TEXT NOT NULL,
    workflow_id TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(task,revision));
"""
)


@dataclass(frozen=True)
class IntentReferences:
    """Explicit new references, NOT an assertion, signing key or authorization."""

    grant_ref: str
    delivery_operation_id: str


def encode_batch(wires: list[bytes]) -> bytes:
    """Validate a complete chain for atomic latest-only Core admission."""
    if not 1 <= len(wires) <= MAX_EXECUTABLE_REVISIONS + 1:
        raise Rejected("semantic chain capacity")
    intents = [decode_intent(wire) for wire in wires]
    source = intents[0]["event"]["source"]
    operations: set[str] = set()
    events: set[str] = set()
    for index, value in enumerate(intents):
        event = value["event"]
        request = value["scoped"]["request"]
        if event["source"] != source or event["revision"] != index + 1:
            raise Rejected("semantic chain source or order")
        if event["kind"] == "delete" and index != len(intents) - 1:
            raise Rejected("semantic chain tombstone")
        if index == MAX_EXECUTABLE_REVISIONS and event["kind"] != "delete":
            raise Rejected("semantic delete reserve")
        operation = request["binding"]["operation_id"]
        if operation in operations:
            raise Rejected("semantic operation reuse")
        operations.add(operation)
        if event["event_id"] in events:
            raise Rejected("semantic event reuse")
        events.add(event["event_id"])
        if index and event["previous"] != {
            "request": intents[index - 1]["scoped"]["request"],
            "wire_sha256": digest(wires[index - 1]),
        }:
            raise Rejected("semantic chain predecessor")
    wire: bytes = canonical({"version": BATCH_VERSION, "intents": intents})
    if len(wire) > 1_048_576:
        raise Rejected("semantic batch size")
    return wire


class SemanticAdmission(Admission):
    """New store family retaining ingress and semantic candidates atomically.

    ``references`` is trusted application configuration and must supply explicit
    fresh-v3 references, not reinterpret the ingress grant. No issuer is invoked.
    Raw Slack edit/delete identity support is NOT supplied by this class.
    """

    STORE_SCHEMA = JOURNAL_SCHEMA
    STORE_FAMILY = FAMILY

    def __init__(
        self,
        path: str,
        *,
        app_id: str,
        account_id: str,
        references: Callable[[dict[str, Any]], IntentReferences | None] | None = None,
        authenticate: Callable[[bytes, object], Identity | None] | None = None,
        authorize: Callable[[Identity, str], Grant | None] | None = None,
        sanitizer: Sanitizer | None = None,
    ) -> None:
        identifier(app_id)
        identifier(account_id)
        self.sanitizer = sanitizer if sanitizer is not None else Sanitizer()
        self.sanitizer.require_clean([app_id, account_id])
        self.authenticate = authenticate
        self.authorize = authorize
        self.references = references
        self.app_id, self.account_id = app_id, account_id
        self.db = open_store(path, self.STORE_SCHEMA, self.STORE_FAMILY)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            rows = self.db.execute(
                "SELECT singleton,app_id,account_id FROM intent_config"
            ).fetchall()
            if not rows:
                # Initialization only: never bind an already populated store.
                if self.db.execute("SELECT 1 FROM revisions LIMIT 1").fetchone():
                    raise Rejected("missing semantic store configuration")
                self.db.execute(
                    "INSERT INTO intent_config VALUES (1,?,?)", (app_id, account_id)
                )
            elif rows != [(1, app_id, account_id)]:
                raise Rejected("semantic store configuration mismatch")
            self.db.commit()
        except BaseException:
            self.db.rollback()
            self.db.close()
            raise

    def _require_event_owner(
        self, namespace: str, event_id: str, raw_digest: str
    ) -> None:
        # This store is bound to exactly one app/account. Provider event identity
        # is global inside that scope, not partitioned by a grant's namespace.
        rows = self.db.execute(
            "SELECT namespace,digest FROM deliveries WHERE event=?", (event_id,)
        ).fetchall()
        if rows != [(namespace, raw_digest)]:
            raise Rejected("semantic global event conflict")

    def _retained_extension(
        self, raw: bytes, envelope: dict[str, Any], duplicate: bool
    ) -> None:
        if self.db.execute(
            "SELECT singleton,app_id,account_id FROM intent_config"
        ).fetchall() != [(1, self.app_id, self.account_id)]:
            raise Rejected("semantic configuration changed")
        self._require_event_owner(
            envelope["payload"]["delivery_namespace"],
            envelope["payload"]["delivery_id"],
            digest(raw),
        )
        binding = envelope["binding"]
        task, revision = binding["task_id"], binding["revision"]
        prior_rows = self.db.execute(
            "SELECT revision,wire,wire_sha256,raw_sha256 FROM intent_candidates WHERE task=? ORDER BY length(revision),revision",
            (task,),
        ).fetchall()
        if duplicate:
            # Recheck the exact immutable candidate; never replace its references.
            matches = [row for row in prior_rows if row[0] == str(revision)]
            if len(matches) != 1:
                raise Rejected("missing semantic duplicate")
            existing = decode_intent(matches[0][1].encode())
            previous = None if revision == 1 else prior_rows[revision - 2][1].encode()
            expected = build_intent(
                raw,
                app_id=self.app_id,
                account_id=self.account_id,
                binding=binding,
                delivery_namespace=envelope["payload"]["delivery_namespace"],
                grant_ref=existing["scoped"]["request"]["payload"]["grant_ref"],
                delivery_operation_id=existing["scoped"]["destination"][
                    "delivery_operation_id"
                ],
                previous_wire=previous,
            )
            if (
                expected != matches[0][1].encode()
                or digest(expected) != matches[0][2]
                or digest(raw) != matches[0][3]
            ):
                raise Rejected("semantic duplicate mismatch")
            encode_batch([row[1].encode() for row in prior_rows])
            return
        if self.references is None:
            raise Rejected("semantic references unavailable")
        refs = None
        failed = False
        try:
            refs = self.references(json.loads(canonical(envelope)))
        except Exception:
            failed = True
        if failed or type(refs) is not IntentReferences:
            raise Rejected("semantic references unavailable")
        if refs.grant_ref == envelope["payload"]["grant_ref"]:
            raise Rejected("legacy grant reuse")
        if len(prior_rows) != revision - 1:
            raise Rejected("semantic journal gap")
        previous = prior_rows[-1][1].encode() if prior_rows else None
        wire = build_intent(
            raw,
            app_id=self.app_id,
            account_id=self.account_id,
            binding=binding,
            delivery_namespace=envelope["payload"]["delivery_namespace"],
            delivery_operation_id=refs.delivery_operation_id,
            grant_ref=refs.grant_ref,
            previous_wire=previous,
        )
        chain = [row[1].encode() for row in prior_rows] + [wire]
        encode_batch(chain)
        self.sanitizer.require_clean(json.loads(wire))
        self.db.execute(
            "INSERT INTO intent_candidates VALUES (?,?,?,?,?)",
            (task, str(revision), wire.decode(), digest(wire), digest(raw)),
        )

    def snapshot_batch(self, task_id: str) -> bytes:
        """Read complete immutable history through current head, no dispatch.

        Submit ONLY to Core's atomic batch consumer, never loop over intents as
        executable individual admissions. Only the latest current grant is used.
        """
        identifier(task_id)
        if self.db.in_transaction:
            raise Rejected("semantic snapshot transaction")
        self.db.execute("BEGIN")
        try:
            if self.db.execute(
                "SELECT singleton,app_id,account_id FROM intent_config"
            ).fetchall() != [(1, self.app_id, self.account_id)]:
                raise Rejected("semantic configuration changed")
            rows = self.db.execute(
                "SELECT revision,wire,wire_sha256,raw_sha256 FROM intent_candidates WHERE task=? ORDER BY length(revision),revision",
                (task_id,),
            ).fetchall()
            wires = [row[1].encode() for row in rows]
            batch = encode_batch(wires)
            for index, (revision, wire, sha, original_digest) in enumerate(rows):
                obj = decode_intent(wire.encode())
                self.sanitizer.require_clean(obj)
                request = obj["scoped"]["request"]
                if (
                    revision != str(index + 1)
                    or sha != digest(wire.encode())
                    or request["binding"]["task_id"] != task_id
                ):
                    raise Rejected("semantic journal integrity")
                retained = self.db.execute(
                    "SELECT scope,kind,digest,envelope FROM revisions WHERE task=? AND revision=?",
                    (task_id, revision),
                ).fetchall()
                if len(retained) != 1:
                    raise Rejected("semantic retained gap")
                scope, kind, raw_digest, old_wire = retained[0]
                if raw_digest != original_digest:
                    raise Rejected("semantic retained digest")
                source = obj["event"]["source"]
                source_scope = canonical(
                    [
                        source[k]
                        for k in (
                            "workspace_id",
                            "channel_id",
                            "thread_id",
                            "message_id",
                        )
                    ]
                ).decode()
                expected_scope = canonical(
                    [
                        source[k]
                        for k in (
                            "workspace_id",
                            "channel_id",
                            "thread_id",
                            "message_id",
                            "actor_id",
                        )
                    ]
                ).decode()
                if scope != expected_scope or kind != obj["event"]["kind"]:
                    raise Rejected("semantic retained scope")
                old = json.loads(old_wire)
                expected = json.loads(canonical(request))
                expected["payload"]["normalized_digest"] = raw_digest
                expected["payload"]["grant_ref"] = old["payload"]["grant_ref"]
                if canonical(expected).decode() != old_wire:
                    raise Rejected("semantic retained envelope")
                namespace, event_id = (
                    request["payload"]["delivery_namespace"],
                    obj["event"]["event_id"],
                )
                self._require_event_owner(namespace, event_id, raw_digest)
                if self.db.execute(
                    "SELECT digest FROM deliveries WHERE namespace=? AND event=?",
                    (namespace, event_id),
                ).fetchall() != [(raw_digest,)]:
                    raise Rejected("semantic delivery mismatch")
                if self.db.execute(
                    "SELECT task FROM sources WHERE scope=?", (source_scope,)
                ).fetchall() != [(task_id,)]:
                    raise Rejected("semantic source mismatch")
                if self.db.execute(
                    "SELECT scope FROM mirrors WHERE scope=?", (source_scope,)
                ).fetchall():
                    raise Rejected("semantic mirrored source")
            latest = decode_intent(wires[-1])
            latest_source = latest["event"]["source"]
            scope = canonical(
                [
                    latest_source[k]
                    for k in (
                        "workspace_id",
                        "channel_id",
                        "thread_id",
                        "message_id",
                        "actor_id",
                    )
                ]
            ).decode()
            if self.db.execute(
                "SELECT revision,scope,deleted FROM heads WHERE task=?", (task_id,)
            ).fetchall() != [
                (str(len(rows)), scope, int(latest["event"]["kind"] == "delete"))
            ]:
                raise Rejected("semantic current head")
            return batch
        finally:
            self.db.rollback()

    def pending_batch(self, task_id: str) -> bytes | None:
        """Return captured complete batch until its exact retention is observed.

        None describes this snapshot only, not a global drained-state promise;
        concurrent/new ingestion requires another poll.
        """
        batch = self.snapshot_batch(task_id)
        intents = json.loads(batch)["intents"]
        revision = len(intents)
        source = intents[-1]["event"]["source"]
        workflow = "intent-" + digest(
            canonical(
                [
                    source["app_id"],
                    source["account_id"],
                    source["workspace_id"],
                    task_id,
                ]
            )
        )
        expected = {
            "status": "retained",
            "workflow_id": workflow,
            "revision": revision,
            "batch_sha256": digest(batch),
        }
        rows = self.db.execute(
            "SELECT batch_sha256,workflow_id,receipt FROM intent_observations WHERE task=? AND revision=?",
            (task_id, str(revision)),
        ).fetchall()
        if rows == [(digest(batch), workflow, canonical(expected).decode())]:
            return None
        if rows:
            raise Rejected("semantic observation conflict")
        return batch

    def reconcile_retention(
        self,
        batch: bytes,
        readback: Callable[[bytes], dict[str, Any] | None] | None = None,
    ) -> str:
        """Record trusted exact Core readback; never submit or infer execution.

        Lost submit responses remain pending until this read-only callback returns
        exact prefix retention. Late receipts acknowledge only their own revision.
        """
        if type(batch) is not bytes or len(batch) > 1_048_576 or readback is None:
            raise Rejected("semantic readback unavailable")
        try:
            value = json.loads(batch)
            if (
                type(value) is not dict
                or set(value) != {"version", "intents"}
                or value["version"] != BATCH_VERSION
            ):
                raise Rejected("semantic batch fields")
            supplied = encode_batch([canonical(item) for item in value["intents"]])
        except (ValueError, TypeError, KeyError, RecursionError):
            supplied = b""
        if supplied != batch:
            raise Rejected("invalid semantic batch")
        intents = json.loads(batch)["intents"]
        latest = intents[-1]
        task = latest["scoped"]["request"]["binding"]["task_id"]
        source = latest["event"]["source"]
        workflow = "intent-" + digest(
            canonical(
                [source["app_id"], source["account_id"], source["workspace_id"], task]
            )
        )
        revision = latest["event"]["revision"]
        expected = {
            "status": "retained",
            "workflow_id": workflow,
            "revision": revision,
            "batch_sha256": digest(batch),
        }
        # Establish local prefix before invoking even the trusted readback helper.
        current = json.loads(self.snapshot_batch(task))["intents"]
        if encode_batch([canonical(item) for item in current[:revision]]) != batch:
            raise Rejected("semantic readback prefix")
        observed = None
        unavailable = False
        try:
            observed = readback(batch)
        except Exception:
            unavailable = True
        if (
            unavailable
            or type(observed) is not dict
            or canonical(observed) != canonical(expected)
        ):
            raise Rejected("semantic readback mismatch")
        if self.db.in_transaction:
            raise Rejected("semantic readback transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self.db.execute(
                "SELECT revision,wire,wire_sha256 FROM intent_candidates WHERE task=? ORDER BY length(revision),revision",
                (task,),
            ).fetchall()[:revision]
            if len(rows) != revision or any(
                row[0] != str(i + 1) or digest(row[1].encode()) != row[2]
                for i, row in enumerate(rows)
            ):
                raise Rejected("semantic readback journal")
            if encode_batch([row[1].encode() for row in rows]) != batch:
                raise Rejected("semantic readback changed prefix")
            receipt = canonical(expected).decode()
            old = self.db.execute(
                "SELECT batch_sha256,workflow_id,receipt FROM intent_observations WHERE task=? AND revision=?",
                (task, str(revision)),
            ).fetchall()
            if old:
                if old != [(digest(batch), workflow, receipt)]:
                    raise Rejected("semantic receipt conflict")
                self.db.rollback()
                return "duplicate"
            self.db.execute(
                "INSERT INTO intent_observations VALUES (?,?,?,?,?)",
                (task, str(revision), digest(batch), workflow, receipt),
            )
            self.db.commit()
            return "retained"
        except BaseException:
            self.db.rollback()
            raise
