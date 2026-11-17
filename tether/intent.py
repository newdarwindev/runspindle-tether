"""Pure semantic Core v3 admission producer; encoding never grants authority.

Only trusted application wiring may connect these bytes to a fresh v3 issuer.
This codec does not authenticate Slack requests or change the v1 ingress path.
"""

import hashlib
import json
from copy import deepcopy
from typing import Any, cast

from tether.admission import (
    Admission,
    Rejected,
    canonical,
    counter,
    decode,
    identifier,
    pairs,
)

VERSION = "runspindle.intent-admission.v1"
SOURCE = {
    "app_id",
    "account_id",
    "actor_id",
    "workspace_id",
    "channel_id",
    "thread_id",
    "message_id",
}
BINDING = {
    "task_id",
    "revision",
    "operation_id",
    "policy_revision",
    "host_id",
    "workspace_id",
    "lease_epoch",
}
PAYLOAD = {
    "delivery_namespace",
    "delivery_id",
    "predecessor_revision",
    "normalized_digest",
    "grant_ref",
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fields(value: Any, expected: set[str]) -> None:
    if type(value) is not dict or set(value) != expected:
        raise Rejected("intent fields")


def _hash(value: Any) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise Rejected("intent digest")


def _binding(value: Any) -> None:
    _fields(value, BINDING)
    for key, item in value.items():
        (counter if key in ("revision", "lease_epoch") else identifier)(item)


def _request(value: Any) -> None:
    _fields(value, {"version", "message_type", "message_id", "binding", "payload"})
    if (
        value["version"] != "runspindle.envelope.v1"
        or value["message_type"] != "admission_request"
    ):
        raise Rejected("intent request version")
    identifier(value["message_id"])
    _binding(value["binding"])
    payload = value["payload"]
    _fields(payload, PAYLOAD)
    for key in ("delivery_namespace", "delivery_id", "grant_ref"):
        identifier(payload[key])
    _hash(payload["normalized_digest"])
    revision = value["binding"]["revision"]
    predecessor = payload["predecessor_revision"]
    if revision == 1:
        if predecessor is not None:
            raise Rejected("intent predecessor")
    elif type(predecessor) is not int or predecessor != revision - 1:
        raise Rejected("intent predecessor")


def destination_id(source: dict[str, str]) -> str:
    """Versioned exact app/account/workspace/channel/thread destination."""
    _fields(source, SOURCE)
    for item in source.values():
        identifier(item)
    return "tether:" + digest(
        canonical(
            [
                source[key]
                for key in (
                    "app_id",
                    "account_id",
                    "workspace_id",
                    "channel_id",
                    "thread_id",
                )
            ]
        )
    )


def expected_task_id(source: dict[str, str]) -> str:
    """Stable source ownership across actors; never derive execution permission."""
    _fields(source, SOURCE)
    for item in source.values():
        identifier(item)
    return "tether-task:" + digest(
        canonical(
            [
                source[key]
                for key in (
                    "app_id",
                    "account_id",
                    "workspace_id",
                    "channel_id",
                    "thread_id",
                    "message_id",
                )
            ]
        )
    )


def _validate(value: Any) -> None:
    _fields(value, {"version", "scoped", "event"})
    if value["version"] != VERSION:
        raise Rejected("intent version")
    scoped, event = value["scoped"], value["event"]
    _fields(scoped, {"version", "request", "destination"})
    if scoped["version"] != "runspindle.scoped-admission.v1":
        raise Rejected("intent scoped version")
    request, destination = scoped["request"], scoped["destination"]
    _request(request)
    _fields(destination, {"account_id", "destination_id", "delivery_operation_id"})
    for item in destination.values():
        identifier(item)
    _fields(
        event, {"event_id", "source", "revision", "kind", "content_sha256", "previous"}
    )
    source = event["source"]
    target = destination_id(source)
    identifier(event["event_id"])
    counter(event["revision"])
    _hash(event["content_sha256"])
    binding, payload = request["binding"], request["payload"]
    if (
        destination["account_id"] != source["account_id"]
        or destination["destination_id"] != target
        or destination["delivery_operation_id"] == binding["operation_id"]
        or binding["workspace_id"] != source["workspace_id"]
        or binding["task_id"] != expected_task_id(source)
        or event["revision"] != binding["revision"]
        or event["event_id"] != request["message_id"]
        or event["event_id"] != payload["delivery_id"]
        or payload["normalized_digest"] != digest(canonical(event))
    ):
        raise Rejected("intent binding")
    prior = event["previous"]
    if event["kind"] == "create":
        if event["revision"] != 1 or prior is not None:
            raise Rejected("intent create")
    elif event["kind"] in ("edit", "delete"):
        _fields(prior, {"request", "wire_sha256"})
        _hash(prior["wire_sha256"])
        _request(prior["request"])
        old = prior["request"]["binding"]
        if (
            old["revision"] + 1 != event["revision"]
            or old["task_id"] != binding["task_id"]
            or old["workspace_id"] != binding["workspace_id"]
            or old["operation_id"] == binding["operation_id"]
        ):
            raise Rejected("intent prior binding")
        if event["kind"] == "delete" and event["content_sha256"] != digest(b""):
            raise Rejected("intent delete content")
    else:
        raise Rejected("intent kind")


def decode_intent(raw: bytes) -> dict[str, Any]:
    """Validate canonical wire shape, not signature, freshness or durable ownership."""
    if type(raw) is not bytes or not 0 < len(raw) <= 1_048_576:
        raise Rejected("intent size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
        _validate(value)
        if canonical(value) == raw:
            return cast(dict[str, Any], value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    raise Rejected("invalid intent")


def build_intent(
    raw: bytes,
    *,
    app_id: str,
    account_id: str,
    binding: dict[str, Any],
    delivery_namespace: str,
    delivery_operation_id: str,
    grant_ref: str,
    previous_wire: bytes | None = None,
) -> bytes:
    """Project a normalized ingress event without carrying its raw text.

    ``grant_ref`` is only a reference for a NEW v3 grant over the returned bytes;
    a legacy Admission Grant never authenticates this projection. Caller-supplied
    normalized events are not proof of Slack identity. No callbacks or I/O occur.
    """
    event = decode(raw)
    if event["mirrored"]:
        raise Rejected("mirrored output")
    _binding(binding)
    source = {key: event[key] for key in SOURCE - {"app_id", "account_id"}}
    source.update(app_id=app_id, account_id=account_id)
    target = destination_id(source)
    previous = None
    if previous_wire is not None:
        prior = decode_intent(previous_wire)
        if prior["event"]["source"] != source or prior["event"]["kind"] == "delete":
            raise Rejected("intent source or tombstone")
        previous = {
            "request": prior["scoped"]["request"],
            "wire_sha256": digest(previous_wire),
        }
    semantic = {
        "event_id": event["event_id"],
        "source": source,
        "revision": event["revision"],
        "kind": event["kind"],
        "content_sha256": digest(event["text"].encode("utf-8")),
        "previous": previous,
    }
    request = {
        "version": "runspindle.envelope.v1",
        "message_type": "admission_request",
        "message_id": event["event_id"],
        "binding": deepcopy(binding),
        "payload": {
            "delivery_namespace": delivery_namespace,
            "delivery_id": event["event_id"],
            "predecessor_revision": None
            if event["revision"] == 1
            else event["revision"] - 1,
            "normalized_digest": digest(canonical(semantic)),
            "grant_ref": grant_ref,
        },
    }
    value = {
        "version": VERSION,
        "event": semantic,
        "scoped": {
            "version": "runspindle.scoped-admission.v1",
            "request": request,
            "destination": {
                "account_id": account_id,
                "destination_id": target,
                "delivery_operation_id": delivery_operation_id,
            },
        },
    }
    wire: bytes = canonical(value)
    decode_intent(wire)
    return wire


def export_retained_intent(
    admission: Admission,
    raw: bytes,
    *,
    app_id: str,
    account_id: str,
    binding: dict[str, Any],
    delivery_namespace: str,
    delivery_operation_id: str,
    grant_ref: str,
    previous_wire: bytes | None = None,
) -> bytes:
    """Export only the exact current retained revision, never submit or authorize.

    The legacy grant reference is checked as retained data, not copied as v3
    authority. Caller owns a fresh v3 issuer. A snapshot cannot fence later effects.
    """
    if type(admission) is not Admission or admission.db.in_transaction:
        raise Rejected("retained admission transaction")
    wire = build_intent(
        raw,
        app_id=app_id,
        account_id=account_id,
        binding=binding,
        delivery_namespace=delivery_namespace,
        delivery_operation_id=delivery_operation_id,
        grant_ref=grant_ref,
        previous_wire=previous_wire,
    )
    event = decode(raw)
    scope, source_scope = Admission.scope(event), Admission.scope(event, False)
    task, revision = binding["task_id"], str(binding["revision"])
    raw_digest = digest(raw)
    db = admission.db
    db.execute("BEGIN")
    try:
        rows = db.execute(
            "SELECT scope,kind,digest,envelope FROM revisions WHERE task=? AND revision=?",
            (task, revision),
        ).fetchall()
        if len(rows) != 1 or rows[0][:3] != (scope, event["kind"], raw_digest):
            raise Rejected("retained revision mismatch")
        owner = db.execute(
            "SELECT task FROM sources WHERE scope=?", (source_scope,)
        ).fetchall()
        delivery = db.execute(
            "SELECT digest FROM deliveries WHERE namespace=? AND event=?",
            (delivery_namespace, event["event_id"]),
        ).fetchall()
        head = db.execute(
            "SELECT revision,scope,deleted FROM heads WHERE task=?", (task,)
        ).fetchall()
        mirrors = db.execute(
            "SELECT scope FROM mirrors WHERE scope=?", (source_scope,)
        ).fetchall()
        if (
            owner != [(task,)]
            or delivery != [(raw_digest,)]
            or head != [(revision, scope, int(event["kind"] == "delete"))]
            or mirrors
        ):
            raise Rejected("retained source delivery or head mismatch")
        try:
            retained = json.loads(rows[0][3], object_pairs_hook=pairs)
            _request(retained)
            expected = deepcopy(decode_intent(wire)["scoped"]["request"])
            expected["payload"]["normalized_digest"] = raw_digest
            expected["payload"]["grant_ref"] = retained["payload"]["grant_ref"]
            valid = retained == expected and canonical(retained).decode() == rows[0][3]
        except (ValueError, TypeError, UnicodeError, RecursionError):
            valid = False
        if not valid:
            raise Rejected("retained envelope mismatch")
        # Apply existing metadata sanitization without altering identity or bytes.
        admission.sanitizer.require_clean(decode_intent(wire))
        return wire
    finally:
        db.execute("ROLLBACK")
