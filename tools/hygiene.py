#!/usr/bin/env python3
"""Manifest-driven, offline verification with bounded, sanitized receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def contained(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError("paths must be nonempty repository-relative strings")
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("path escapes repository")
    return path


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL, text=True
    ).strip()


def validate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported manifest schema")
    checks = value.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("checks must be a nonempty explicit inventory")
    ids: set[str] = set()
    for entry in checks:
        validate_entry(entry)
        if entry["id"] in ids:
            raise ValueError("duplicate check id")
        ids.add(entry["id"])
    for field in ("lockfiles", "artifact_paths", "limitations"):
        if not isinstance(value.get(field, []), list) or not all(
            isinstance(item, str) for item in value.get(field, [])
        ):
            raise ValueError("manifest lists must contain strings")
    profiling = value.get("profiling", {})
    if not isinstance(profiling, dict):
        raise ValueError("profiling must be explicit")
    if "not_applicable" in profiling:
        if (
            not isinstance(profiling["not_applicable"], str)
            or not profiling["not_applicable"].strip()
        ):
            raise ValueError("profiling N/A needs a reason")
    elif profiling.get("workloads"):
        for workload in profiling["workloads"]:
            validate_entry(workload)
            if workload.get("kind") not in ("offline_runtime", "validation"):
                raise ValueError(
                    "profiling kind must distinguish runtime from validation"
                )
    else:
        raise ValueError("profiling needs workloads or an explicit N/A")
    return value


def validate_entry(entry: Any) -> None:
    if (
        not isinstance(entry, dict)
        or not isinstance(entry.get("id"), str)
        or not SAFE_ID.fullmatch(entry["id"])
    ):
        raise ValueError("invalid check id")
    if "not_applicable" in entry:
        if (
            "command" in entry
            or not isinstance(entry["not_applicable"], str)
            or not entry["not_applicable"].strip()
        ):
            raise ValueError("N/A needs a reason and cannot contain a command")
        return
    command = entry.get("command")
    if (
        not isinstance(command, list)
        or not command
        or not all(
            isinstance(arg, str) and arg and "\x00" not in arg for arg in command
        )
    ):
        raise ValueError("command must be a nonempty argv list")
    timeout = entry.get("timeout_seconds", 300)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0 < timeout <= 3600
    ):
        raise ValueError("timeout must be bounded to 1 hour")
    if not isinstance(entry.get("required_files", []), list) or not all(
        isinstance(path, str) for path in entry.get("required_files", [])
    ):
        raise ValueError("required_files must be a list of paths")


def run_entry(root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    receipt: dict[str, Any] = {"id": entry["id"]}
    if "not_applicable" in entry:
        return {
            **receipt,
            "status": "not_applicable",
            "reason": entry["not_applicable"],
        }
    # Only a fingerprint is retained: arguments and subprocess output may contain secrets.
    receipt["command_sha256"] = hashlib.sha256(
        json.dumps(entry["command"]).encode()
    ).hexdigest()
    try:
        if any(
            not contained(root, path).exists()
            for path in entry.get("required_files", [])
        ):
            return {**receipt, "status": "failed", "reason": "required_file_missing"}
    except ValueError:
        return {**receipt, "status": "failed", "reason": "unsafe_required_path"}
    executable = entry["command"][0]
    if "/" in executable:
        try:
            available = contained(root, executable).is_file() and os.access(
                contained(root, executable), os.X_OK
            )
        except ValueError:
            available = False
    else:
        available = shutil.which(executable) is not None
    if not available:
        return {**receipt, "status": "failed", "reason": "required_tool_missing"}
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        process = subprocess.Popen(
            entry["command"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        # Drain without persisting logs or allowing unbounded captured output.
        tail = bytearray()

        def drain() -> None:
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(8192)
                if not chunk:
                    break
                tail.extend(chunk)
                if len(tail) > 65536:
                    del tail[:-65536]

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=entry.get("timeout_seconds", 300))
            receipt.update(status="passed" if code == 0 else "failed", exit_code=code)
        except subprocess.TimeoutExpired:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            receipt.update(status="failed", reason="timeout")
        reader.join(timeout=2)
        if reader.is_alive():
            import signal

            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            reader.join(timeout=2)
        output = bytes(tail).decode("utf-8", errors="replace")
        if "unittest" in entry["command"]:
            counts = re.findall(r"(?m)^Ran (\d+) tests? in [0-9.]+s$", output)
            summaries = re.findall(r"(?m)^(?:OK|FAILED)(?: \(([^\n]*)\))?$", output)
            if counts and summaries:
                receipt["tests_run"] = int(counts[-1])
                skipped = re.search(r"(?:^|, )skipped=(\d+)(?:,|$)", summaries[-1])
                receipt["tests_skipped"] = int(skipped.group(1)) if skipped else 0
                receipt["test_summary"] = "unittest_trailing_summary"
            else:
                receipt["test_summary"] = "unavailable"
        if Path(entry["command"][0]).name in ("node", "npm"):
            counts = re.findall(r"(?m)^(?:ℹ|#) tests (\d+)\r?$", output)
            node_skipped = re.findall(r"(?m)^(?:ℹ|#) skipped (\d+)\r?$", output)
            if counts and node_skipped:
                receipt["tests_run"] = int(counts[-1])
                receipt["tests_skipped"] = int(node_skipped[-1])
                receipt["test_summary"] = "node_trailing_summary"
            else:
                receipt["test_summary"] = "unavailable"
        tail.clear()
        del output
        if process.stdout is not None:
            process.stdout.close()
    except OSError:
        receipt.update(status="failed", reason="process_start_failed")
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    receipt.update(
        wall_seconds=round(time.monotonic() - started, 6),
        child_cpu_seconds=round(
            after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime, 6
        ),
        child_maxrss_high_water=after.ru_maxrss,
        maxrss_scope="process-wide child high-water, not per-workload peak",
        maxrss_unit="bytes" if platform.system() == "Darwin" else "KiB",
    )
    return receipt


def preflight(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    problems: list[str] = []
    locks: dict[str, str] = {}
    for name in manifest.get("lockfiles", []):
        try:
            path = contained(root, name)
            if not path.is_file():
                problems.append("required_lockfile_missing")
                continue
            git(root, "ls-files", "--error-unmatch", "--", name)
            if git(root, "diff", "--", name):
                problems.append("lockfile_drift")
            locks[name] = digest(path)
        except (ValueError, subprocess.CalledProcessError):
            problems.append("lockfile_untracked_or_unsafe")
    # Reject floating remote actions and container actions; local actions retain local review.
    for path in (root / ".github/workflows").glob("*.y*ml"):
        for match in re.finditer(
            r"(?m)^\s*(?:-\s*)?uses:\s*[\"']?([^\s\"'#]+)", path.read_text()
        ):
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            if reference.startswith("docker://"):
                valid = bool(re.search(r"@sha256:[0-9a-f]{64}$", reference))
            else:
                valid = bool(re.search(r"@[0-9a-f]{40}$", reference))
            if not valid:
                problems.append("workflow_action_not_pinned")
    component = root / "component.json"
    if component.exists() and os.environ.get("CI", "").lower() == "true":
        if json.loads(component.read_text()).get("component") == "platform":
            prepared = Path(
                os.environ.get(
                    "RUNSPINDLE_TEMPORAL_PREPARED", "/opt/runspindle-temporal"
                )
            )
            if not prepared.is_dir():
                problems.append("prepared_temporal_missing")
    pins: dict[str, str] = {}
    lock = root / "composition.lock.json"
    if lock.exists():
        try:
            components = json.loads(lock.read_text())["components"]
            for component in components:
                name, expected = component["path"], component["commit"]
                contained(root, name)
                if not SHA.fullmatch(expected):
                    raise ValueError("invalid commit")
                entries = git(root, "ls-files", "--stage", "--", name).splitlines()
                if len(entries) != 1:
                    raise ValueError("missing gitlink")
                mode, actual, stage = entries[0].split("\t", 1)[0].split()
                if mode != "160000" or stage != "0" or actual != expected:
                    problems.append("composition_gitlink_mismatch")
                pins[name] = expected
        except (KeyError, TypeError, ValueError, subprocess.CalledProcessError):
            problems.append("composition_lock_invalid")
    return {
        "id": "reproducible-inputs",
        "status": "failed" if problems else "passed",
        "problems": sorted(set(problems)),
        "lock_sha256": locks,
        "component_pins": pins,
    }


def evidence(
    root: Path, manifest: dict[str, Any], *, preflight_only: bool = False
) -> dict[str, Any]:
    try:
        sha = git(root, "rev-parse", "HEAD")
        dirty = bool(git(root, "status", "--porcelain", "--untracked-files=no"))
        untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z")
        untracked_count = len([name for name in untracked.split("\0") if name])
    except subprocess.CalledProcessError:
        sha, dirty, untracked_count = "unknown", True, -1
    try:
        base_sha = git(root, "merge-base", "HEAD", "origin/main")
    except subprocess.CalledProcessError:
        base_sha = "unknown"
    result: dict[str, Any] = {
        "schema_version": 1,
        "source_sha": sha,
        "base_sha": base_sha,
        "tracked_worktree_dirty": dirty,
        "source_worktree_dirty": dirty or untracked_count != 0,
        "untracked_file_count": untracked_count,
        "source_identity": "commit_only_when_clean; dirty worktree is not an exact-source receipt",
        "manifest_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode()
        ).hexdigest(),
        "hardware": {
            "system": platform.system(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "checks": [preflight(root, manifest)],
        "profiles": [],
        "artifact_sha256": {},
        "limitations": manifest.get("limitations", [])
        + [
            "Command output and argv are deliberately omitted; fingerprints identify manifest commands.",
            "Profiles are report-only single samples, not regression thresholds or provider benchmarks.",
        ],
    }
    runner_image = Path("/etc/runspindle-image.json")
    result["runner_image_sha256"] = (
        digest(runner_image) if runner_image.is_file() else "unavailable"
    )
    for entry in manifest["checks"]:
        result["checks"].append(
            {"id": entry["id"], "status": "not_run", "reason": "preflight_only"}
            if preflight_only
            else run_entry(root, entry)
        )
    profiling = manifest["profiling"]
    if "not_applicable" in profiling:
        result["profiles"] = [
            {"status": "not_applicable", "reason": profiling["not_applicable"]}
        ]
    elif not preflight_only:
        for entry in profiling["workloads"]:
            result["profiles"].append(
                {
                    **run_entry(root, entry),
                    "kind": entry["kind"],
                    "enforcement": "report_only",
                }
            )
    else:
        result["profiles"] = [{"status": "not_run", "reason": "preflight_only"}]
    for name in manifest.get("artifact_paths", []):
        try:
            path = contained(root, name)
            if path.is_file():
                result["artifact_sha256"][name] = digest(path)
            else:
                result["checks"].append(
                    {
                        "id": "artifact-presence",
                        "status": "failed",
                        "reason": "declared_artifact_missing",
                    }
                )
        except ValueError:
            result["checks"].append(
                {
                    "id": "artifact-path",
                    "status": "failed",
                    "reason": "unsafe_artifact_path",
                }
            )
    for name, expected in result["checks"][0].get("lock_sha256", {}).items():
        path = contained(root, name)
        if not path.is_file() or digest(path) != expected:
            result["checks"].append(
                {
                    "id": "lockfile-stability",
                    "status": "failed",
                    "reason": "lockfile_changed_during_verification",
                }
            )
    result["status"] = (
        "failed"
        if any(item["status"] == "failed" for item in result["checks"])
        else "partial"
        if preflight_only
        else "passed"
    )
    return result


def write_reports(output: Path, result: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "evidence.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    lines = [
        "# Verification evidence",
        "",
        f"Status: **{result['status']}**",
        "",
        f"Source: `{result.get('source_sha', 'unknown')}`",
        "",
        "| Check | Result | Tests run | Skipped | Seconds | Reason |",
        "|---|---|---|---|---|---|",
    ]
    for entry in result.get("checks", []):
        reason = str(entry.get("reason", "")).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {entry['id']} | {entry['status']} | {entry.get('tests_run', 'n/a')} | {entry.get('tests_skipped', 'unknown')} | {entry.get('wall_seconds', 'n/a')} | {reason} |"
        )
    lines.extend(
        [
            "",
            "## Report-only profiling",
            "",
            "| Workload | Kind | Result | Wall seconds |",
            "|---|---|---|---|",
        ]
    )
    for profile in result.get("profiles", []):
        lines.append(
            f"| {profile.get('id', 'none')} | {profile.get('kind', 'n/a')} | {profile['status']} | {profile.get('wall_seconds', 'n/a')} |"
        )
    lines.extend(
        [
            "",
            "See evidence.json for hardware, pins, artifact hashes and limitations.",
            "",
            "Command output is deliberately omitted. No performance thresholds are enforced.",
        ]
    )
    (output / "report.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="hygiene.json")
    parser.add_argument("--output", default=".verification")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = contained(root, args.output)
    try:
        manifest = validate_manifest(
            json.loads(contained(root, args.manifest).read_text())
        )
        result = evidence(root, manifest, preflight_only=args.preflight_only)
    except (ValueError, KeyError, OSError):
        result = {
            "schema_version": 1,
            "status": "failed",
            "checks": [
                {
                    "id": "manifest",
                    "status": "failed",
                    "reason": "invalid_or_missing_manifest",
                }
            ],
        }
    write_reports(output, result)
    print("hygiene: " + result["status"] + " (sanitized reports written)")
    return int(result["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
