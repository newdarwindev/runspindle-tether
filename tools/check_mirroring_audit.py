#!/usr/bin/env python3
"""Bounded SRC-014 artifact coverage checks, never runtime acceptance."""

import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tether.native_testing import KINDS, Availability, Mode, capabilities  # noqa: E402

EXPECTED_ITEMS = {
    "S1.introduction",
    "S1.row1",
    "S1.row2",
    "S1.row3",
    "S1.row4",
    "S1.method",
    "S2.row1",
    "S2.row2",
    "S2.row3",
    "S2.row4",
    "S2.testing",
    "S3.introduction",
    "S3.requirement1",
    "S3.requirement2",
    "S3.requirement3",
    "S3.requirement4",
    "S3.requirement5",
    "S4.procedure",
    "S4.conclusion",
}
HISTORICAL = {"guarded_cli", "final_output_router", "exposed_sdk", "status_snapshot"}
FAILURES = {
    "route_and_session",
    "capabilities",
    "ordering_and_reconnect",
    "duplicate_and_restart",
    "unknown_and_conflict",
    "partial_artifact",
    "rate_limit",
    "edit_delete_loop",
    "authority_and_interruption",
    "sanitization",
    "mutations",
}
SLOTS = {
    "authorization_and_bounded_scope",
    "source_revision_and_installed_runtime",
    "host_and_native_session_identity",
    "exact_workspace_channel_thread_binding",
    "supported_and_unavailable_events",
    "sanitized_emitted_event_manifest",
    "operation_attempt_sequence_provenance",
    "journal_state",
    "independent_destination_receipts",
    "origin_event_count",
    "queued_count",
    "rejected_count",
    "sent_count",
    "destination_confirmed_count",
    "normal_delivery",
    "reconnect_and_replay",
    "duplicate_suppression",
    "uncertain_send_reconciliation",
    "tool_lifecycle_progress_failure_final",
    "sanitization_and_secret_reference_review",
    "passive_visibility_separate_from_control",
    "inspection_denials_and_unavailable_tools",
}
NOTICE_SHA256 = "6633fb2316603acd45898cbcd7497f18e045449547eddf137b1919358b57fe2e"
ORIGINAL_EVIDENCE_SHA256 = (
    "04e7580b6a685a77d1f92736e9fe847b12605f93c1905a1dead2cf8a1487315f"
)
PUBLIC_FILES = (
    "docs/MIRRORING_ACCEPTANCE.md",
    "docs/MIRRORING_COVERAGE.md",
    "docs/mirroring-coverage.json",
    "docs/mirroring-audit-evidence.json",
    "docs/evidence-artifacts.json",
    "provenance.json",
    "STATUS.json",
    "docs/mirroring-audit-original-evidence.json",
)
EVIDENCE_FILES = {
    "docs/MIRRORING_ACCEPTANCE.md",
    "docs/MIRRORING_COVERAGE.md",
    "docs/mirroring-coverage.json",
    "docs/LICENSE-SRC-014.txt",
    "docs/THIRD_PARTY_NOTICES.md",
    "STATUS.json",
    "provenance.json",
    "specs/README.md",
    "tools/check_mirroring_audit.py",
    "tools/validate.py",
    "tests/test_mirroring_audit.py",
    "tests/test_native_source.py",
    "tests/test_fake_transport.py",
    "tests/test_provider_journal.py",
    "tests/test_sanitization.py",
    "tests/test_slack_wire.py",
    "tether/native_testing.py",
    "tether/testing.py",
    "tether/journal.py",
    "tether/sanitization.py",
    "tether/slack_wire.py",
    "specs/slack-wire-v1.md",
    "docs/slack-wire-evidence.json",
    "docs/mirroring-audit-original-evidence.json",
    "hygiene.json",
    "validation-partitions.json",
    "tools/quality-baseline.json",
    "requirements-quality.txt",
}
ARTIFACT_FILES = {
    "docs/MIRRORING_ACCEPTANCE.md",
    "docs/MIRRORING_COVERAGE.md",
    "docs/mirroring-coverage.json",
    "docs/LICENSE-SRC-014.txt",
    "docs/THIRD_PARTY_NOTICES.md",
    "docs/mirroring-audit-evidence.json",
    "docs/mirroring-audit-original-evidence.json",
}


def require(condition: object, category: str) -> None:
    if not condition:
        raise ValueError("mirroring audit: " + category)


def unique(rows: list[dict[str, Any]], key: str) -> set[str]:
    require(isinstance(rows, list), "row collection")
    keys = [row[key] for row in rows]
    require(len(keys) == len(set(keys)), "duplicate " + key)
    return set(keys)


def reference(root: Path, value: str) -> None:
    require(isinstance(value, str) and value and ":" not in value, "local reference")
    name, _, fragment = value.partition("#")
    require(
        not Path(name).is_absolute() and ".." not in Path(name).parts,
        "relative reference",
    )
    path = (root / name).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), "reference target")
    if fragment and path.suffix == ".py":
        nodes = ast.walk(ast.parse(path.read_text()))
        require(
            any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == fragment
                for n in nodes
            ),
            "test reference",
        )
    elif fragment and path.suffix == ".json":
        require(fragment in json.loads(path.read_text()), "json reference")
    elif fragment and path.suffix == ".md":
        headings = re.findall(r"^#{1,6} (.+)$", path.read_text(), re.MULTILINE)
        anchors = {
            re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in headings
        }
        require(fragment in anchors, "markdown reference")
    elif fragment:
        require(False, "unsupported reference anchor")


def privacy(text: str) -> None:
    # Intentionally bounded. Private source review is still required; do not add
    # actual private identifiers or secret values to this public checker.
    patterns = (
        r"(?:file|ssh)://",
        r"/(?:home|Users|workspace|tmp)/",
        r"\b[A-Z]:\\",
        r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"https?://[^\s/]+:[^\s/]+@",
        r"audit-private-device\.invalid",
    )
    require(
        not any(re.search(p, text, re.IGNORECASE) for p in patterns),
        "unsafe publication form",
    )


def validate(root: Path = ROOT) -> dict[str, Any]:
    root = Path(root)
    data = json.loads((root / "docs/mirroring-coverage.json").read_text())
    require(
        data["schema_version"] == 1 and data["source_id"] == "SRC-014",
        "source identity",
    )
    require(data["artifact_scope"] == "complete", "artifact scope")
    require(
        data["historical_source"] == "private_reference_not_runtime_evidence",
        "historical evidence",
    )
    require(
        unique(data["source_sections"], "section_id") == {"S1", "S2", "S3", "S4"},
        "sections",
    )
    require(
        unique(data["dispositions"], "source_item") == EXPECTED_ITEMS,
        "disposition completeness",
    )
    for row in data["dispositions"]:
        expected_disposition = (
            "excluded_private_snapshot"
            if row["source_item"] in {"S1.row1", "S1.row2", "S1.row3", "S1.row4"}
            else None
        )
        require(
            row["disposition"]
            in {"adapted", "adapted_with_exclusion", "excluded_private_snapshot"},
            "disposition",
        )
        require(
            expected_disposition is None or row["disposition"] == expected_disposition,
            "snapshot exclusion",
        )
        require(row["review"] and row["destinations"], "review decision")
        for ref in row["destinations"] + row["evidence"]:
            reference(root, ref)
    columns = set(KINDS) | {"snapshot", "hidden_reasoning"}
    require(
        set(data["event_columns"]) == columns
        and len(data["event_columns"]) == len(columns),
        "event columns",
    )
    expected_adapters = {"synthetic." + mode.value for mode in Mode} | {
        "historical." + p for p in HISTORICAL
    }
    require(
        unique(data["adapter_matrix"], "adapter_id") == expected_adapters,
        "adapter completeness",
    )
    for row in data["adapter_matrix"]:
        require(
            row["control"] is False and row["live_coverage"] == "not_run",
            "adapter authority/live status",
        )
        require(set(row["events"]) == columns, "adapter event completeness")
        require(row["events"]["hidden_reasoning"] == "forbidden", "hidden reasoning")
        if row["adapter_id"].startswith("synthetic."):
            mode = Mode(row["mode"])
            require(row["adapter_id"] == "synthetic." + mode.value, "mode identity")
            require(
                row["classification"] == "synthetic_fixture"
                and row["historical_profile"] is None,
                "fixture class",
            )
            expected = {
                k: "synthetic_supported"
                if k in capabilities(mode)
                else "forbidden"
                if k == "hidden_reasoning"
                else "unsupported"
                for k in columns
            }
            require(row["events"] == expected, "actual capability mismatch")
            require(
                set(row["availability"]) == {a.value for a in Availability},
                "availability",
            )
            require(
                row["implementation"] == "tether/native_testing.py" and row["evidence"],
                "fixture evidence",
            )
        else:
            require(
                row["classification"]
                == "historical_reference_current_adapter_unavailable",
                "historical class",
            )
            require(
                row["implementation"] is None
                and row["mode"] is None
                and row["evidence"] == [],
                "historical executable claim",
            )
            require(
                row["historical_profile"] and row["availability"] == ["unverified"],
                "historical profile",
            )
            require(
                all(
                    v
                    == (
                        "forbidden"
                        if k == "hidden_reasoning"
                        else "unverified_unavailable"
                    )
                    for k, v in row["events"].items()
                ),
                "historical capability claim",
            )
        for ref in (
            [row["specification"]]
            + row["evidence"]
            + ([row["implementation"]] if row["implementation"] else [])
        ):
            reference(root, ref)
    components = data["component_matrix"]
    require(
        unique(components, "component_id")
        == {
            "fake_transport",
            "provider_journal",
            "sanitizer",
            "slack_wire",
            "live_slack_provider",
        },
        "component completeness",
    )
    for row in components:
        require(
            row["event_source"] is False and row["live_receipts"] == "not_run",
            "component status",
        )
        for ref in [row["specification"], row["implementation"]] + row["evidence"]:
            if ref is not None:
                reference(root, ref)
    by_id = {row["component_id"]: row for row in components}
    component_contracts = {
        "fake_transport": (
            "process_local_synthetic",
            "specs/synthetic-transport-v1.md",
            "tether/testing.py",
            "accepted_synthetic_only",
            "exact_synthetic_destination_comparison",
            "not_implemented",
        ),
        "provider_journal": (
            "sqlite_component_synthetic_provider",
            "specs/provider-journal-v1.md",
            "tether/journal.py",
            "accepted_synthetic_only",
            "exact_synthetic_destination_comparison",
            "local_attempt_fence_tested",
        ),
        "sanitizer": (
            "bounded_configured_secret_component",
            "specs/sanitization-v1.md",
            "tether/sanitization.py",
            "not_applicable",
            "not_applicable",
            "sanitized_projection_sqlite_tested",
        ),
    }
    for component_id, contract in component_contracts.items():
        require(
            tuple(
                by_id[component_id][key]
                for key in (
                    "classification",
                    "specification",
                    "implementation",
                    "acknowledgement",
                    "readback",
                    "durability",
                )
            )
            == contract
            and by_id[component_id]["evidence"],
            "component source evidence",
        )
    require(
        by_id["provider_journal"]["acknowledgement"] == "accepted_synthetic_only",
        "journal evidence class",
    )
    require(
        by_id["live_slack_provider"]["implementation"] is None
        and by_id["live_slack_provider"]["classification"] == "unavailable",
        "live provider claim",
    )
    require(
        by_id["slack_wire"]["acknowledgement"] == "unqualified_wire_observation_only"
        and by_id["slack_wire"]["readback"] == "unqualified_wire_observation_only"
        and by_id["slack_wire"]["durability"] == "not_implemented",
        "wire evidence promotion",
    )
    require(
        by_id["slack_wire"]["classification"]
        == "bounded_protocol_component_synthetic_http_only"
        and by_id["slack_wire"]["implementation"] == "tether/slack_wire.py"
        and by_id["slack_wire"]["specification"] == "specs/slack-wire-v1.md"
        and "tests/test_slack_wire.py#test_real_provider_types_are_not_journal_receipts"
        in by_id["slack_wire"]["evidence"],
        "wire source evidence",
    )
    require(
        unique(data["failure_matrix"], "failure_id") == FAILURES, "failure completeness"
    )
    for row in data["failure_matrix"]:
        require(row["evidence"] and row["verification"], "failure verification")
        for ref in row["evidence"]:
            reference(root, ref)
    template = data["live_evidence_template"]
    require(
        template["status"] == "not_run" and set(template["values"]) == SLOTS,
        "live evidence slots",
    )
    require(
        all(v is None for v in template["values"].values()), "fabricated live evidence"
    )
    require(
        data["runtime_issues_remaining_open"] == [1, 3, 8, 9, 10]
        and data["product_gate"] == "F01_not_run",
        "closure scope",
    )
    status = json.loads((root / "STATUS.json").read_text())
    require(
        status["live_acceptance"] == "not_run"
        and status["implementation"] == "not_implemented"
        and status["selected_source_migration"] == "partial",
        "product status",
    )
    require(
        status["src014_artifact_lift"]["status"] == "artifact_scope_complete",
        "artifact status",
    )
    require(
        status["src014_artifact_lift"]["runtime_completion"] is False
        and status["src014_artifact_lift"]["live_receipts"] == "not_run",
        "artifact runtime promotion",
    )
    require(
        status["slack_wire_protocol"]["status"] == by_id["slack_wire"]["classification"]
        and status["slack_wire_protocol"]["provider_acceptance"] == "not_run"
        and status["slack_wire_protocol"]["live_transport"] == "not_implemented",
        "wire source status",
    )
    provenance = json.loads((root / "provenance.json").read_text())
    sources = [s for s in provenance["sources"] if s["source_id"] == "SRC-014"]
    require(
        len(sources) == 1
        and sources[0]["status"] == "adapted_spec"
        and sources[0]["artifact_scope"] == "complete"
        and sources[0]["executable_implementation"] == "none_imported"
        and sources[0]["live_verification"] == "not_run"
        and sources[0]["historical_reference"] == "private_original_snapshot_excluded"
        and sources[0]["verified_behavior"] == "existing_local_synthetic_suites_only",
        "provenance classification",
    )
    require(
        hashlib.sha256((root / "docs/LICENSE-SRC-014.txt").read_bytes()).hexdigest()
        == NOTICE_SHA256,
        "notice integrity",
    )
    evidence = json.loads((root / "docs/mirroring-audit-evidence.json").read_text())
    historical = evidence["historical_validation"]
    require(
        historical["path"] == "docs/mirroring-audit-original-evidence.json"
        and historical["sha256"] == ORIGINAL_EVIDENCE_SHA256
        and historical["source_commit"] == "9c89f59867d760cec2f128ca95392526a2cf721e"
        and historical["merge_commit"] == "7130373187ff70e59c4593ce56f37d8417900738",
        "historical validation identity",
    )
    require(
        hashlib.sha256((root / historical["path"]).read_bytes()).hexdigest()
        == ORIGINAL_EVIDENCE_SHA256,
        "historical validation integrity",
    )
    require(
        evidence["evidence_class"] == "artifact_review_and_local_synthetic_validation"
        and evidence["live_receipts"] == "not_run",
        "review evidence class",
    )
    require(set(evidence["sha256"]) == EVIDENCE_FILES, "evidence hash inventory")
    for name, digest in evidence["sha256"].items():
        reference(root, name)
        require(
            hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
            "current evidence hash",
        )
    manifest = json.loads((root / "docs/evidence-artifacts.json").read_text())
    require(
        manifest["migration_status"] == "partial" and manifest["schema_version"] == 1,
        "manifest scope",
    )
    require(
        unique(manifest["artifacts"], "path") == ARTIFACT_FILES, "manifest inventory"
    )
    for row in manifest["artifacts"]:
        if row["path"] == "docs/mirroring-audit-original-evidence.json":
            require(
                row.get("historical_original") is True
                and row["kind"] == "retained_historical_validation_record",
                "historical manifest classification",
            )
        require(
            row["source_ids"] == ["SRC-014"]
            and row["implementation_evidence"] is False,
            "manifest evidence class",
        )
        require(
            hashlib.sha256((root / row["path"]).read_bytes()).hexdigest()
            == row["sha256"],
            "manifest artifact hash",
        )
    for name in PUBLIC_FILES:
        privacy((root / name).read_text())
    return {
        "status": "passed",
        "source_id": "SRC-014",
        "disposition_units": len(EXPECTED_ITEMS),
        "adapter_rows": len(expected_adapters),
        "evidence_class": "artifact_coverage_integrity",
        "live_acceptance": "not_run",
    }


if __name__ == "__main__":
    print(json.dumps(validate(), sort_keys=True))
