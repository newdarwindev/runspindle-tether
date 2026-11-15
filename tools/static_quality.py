#!/usr/bin/env python3
"""Pinned static checks; existing diagnostics are explicit reviewed debt.

Provision requirements-quality.txt and tools/quality-node/package-lock.json before
running. This command never installs tools. --write-baseline is an explicit review
operation, not part of validation; commit and review any resulting debt changes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "ruff": "0.14.5",
    "mypy": "1.18.2",
    "yamllint": "1.37.1",
    "shellcheck-py": "0.11.0.1",
    "mypy_extensions": "1.2.0",
    "pathspec": "1.1.1",
    "typing_extensions": "4.16.0",
    "PyYAML": "6.0.3",
}
NODE_PINS = {
    "eslint": "9.39.1",
    "typescript": "5.9.3",
    "prettier": "3.6.2",
    "@types/node": "22.19.1",
}


def command(argv: list[str], allowed: tuple[int, ...] = (0, 1)) -> str:
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=180)
    if result.returncode not in allowed or (
        result.returncode and not result.stdout.strip()
    ):
        raise RuntimeError(f"checker failed: {argv[0]} (exit {result.returncode})")
    return result.stdout


def inputs() -> list[str]:
    tracked = command(["git", "ls-files", "-z"], (0,)).split("\0")
    new = command(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], (0,)
    ).split("\0")
    return sorted(
        {
            p
            for p in tracked + new
            if p
            and (ROOT / p).is_file()
            and not p.startswith(("tools/quality-node/node_modules/", "components/"))
        }
    )


def fingerprint(tool: str, path: str, code: str, line: int, message: str) -> str:
    lines = (ROOT / path).read_text().splitlines()
    source = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    digest = hashlib.sha256(source.encode()).hexdigest()[:16]
    return json.dumps([tool, path, code, digest, message], ensure_ascii=True)


def collect(files: list[str]) -> tuple[list[str], dict[str, Any]]:
    diagnostics: list[str] = []
    summary: dict[str, Any] = {
        "python_runtime": sys.version.split()[0],
        "runtime_pin": "runner-image qualification is separate from package pins",
    }
    for name, expected in PINS.items():
        actual = metadata.version(name)
        if actual != expected:
            raise RuntimeError(f"{name} version mismatch: require {expected}")
    python = [p for p in files if p.endswith(".py")]
    yaml = [p for p in files if p.endswith((".yml", ".yaml"))]
    shell = [p for p in files if p.endswith(".sh")]
    javascript = [p for p in files if p.endswith((".js", ".mjs", ".cjs"))]
    if python:
        findings = json.loads(
            command(
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "check",
                    "--isolated",
                    "--select",
                    "E4,E7,E9,F,I",
                    "--output-format",
                    "json",
                    *python,
                ]
            )
        )
        for item in findings:
            path = str(Path(item["filename"]).relative_to(ROOT))
            diagnostics.append(
                fingerprint(
                    "ruff", path, item["code"], item["location"]["row"], item["message"]
                )
            )
        output = command(
            [
                sys.executable,
                "-m",
                "mypy",
                "--strict",
                "--follow-imports=skip",
                "--explicit-package-bases",
                "--no-incremental",
                "--show-error-codes",
                "--no-error-summary",
                "--no-pretty",
                *python,
            ],
            (0, 1),
        )
        for line in output.splitlines():
            match = re.match(r"(.+?):(\d+): error: (.+)  \[([^]]+)\]$", line)
            if match:
                diagnostics.append(
                    fingerprint("mypy", match[1], match[4], int(match[2]), match[3])
                )
            elif ": error:" in line:
                raise RuntimeError("unparsed mypy diagnostic")
        for path in python:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "format",
                    "--isolated",
                    "--stdin-filename",
                    path,
                    "-",
                ],
                input=(ROOT / path).read_text(),
                text=True,
                capture_output=True,
                cwd=ROOT,
                timeout=30,
            )
            if result.returncode:
                raise RuntimeError("ruff formatter failed")
            if result.stdout != (ROOT / path).read_text():
                diagnostics.append(
                    json.dumps(
                        [
                            "ruff-format",
                            path,
                            hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                        ]
                    )
                )
        summary["python"] = {
            "files": len(python),
            "lint": "ruff E4/E7/E9/F/I",
            "types": "mypy strict; imported modules separately enumerated",
            "format": "ruff",
        }
    if yaml:
        output = command(
            [
                sys.executable,
                "-m",
                "yamllint",
                "-f",
                "parsable",
                "-d",
                "{extends: default, rules: {line-length: disable, truthy: disable}}",
                *yaml,
            ]
        )
        for line in output.splitlines():
            match = re.match(
                r"(.+?):(\d+):\d+: \[(?:warning|error)\] (.+) \(([^)]+)\)$", line
            )
            if not match:
                raise RuntimeError("unparsed yamllint diagnostic")
            diagnostics.append(
                fingerprint("yamllint", match[1], match[4], int(match[2]), match[3])
            )
    summary["yaml"] = {
        "files": len(yaml),
        "tool": "yamllint",
        "not_applicable": not yaml,
    }
    if shell:
        if "version: 0.11.0" not in command(["shellcheck", "--version"], (0,)):
            raise RuntimeError("shellcheck executable version mismatch: require 0.11.0")
        for item in json.loads(command(["shellcheck", "--format=json", *shell])):
            diagnostics.append(
                fingerprint(
                    "shellcheck",
                    item["file"],
                    str(item["code"]),
                    item["line"],
                    item["message"],
                )
            )
    summary["shell"] = {
        "files": len(shell),
        "tool": "shellcheck",
        "not_applicable": not shell,
    }
    for path in [p for p in files if p.endswith(".json")]:
        try:
            json.loads((ROOT / path).read_text())
        except (ValueError, UnicodeError):
            raise RuntimeError(f"invalid JSON: {path}") from None
    if javascript:
        summary["node_runtime"] = command(["node", "--version"], (0,)).strip()
        modules = ROOT / "tools/quality-node/node_modules"
        for name, expected in NODE_PINS.items():
            if (
                json.loads((modules / name / "package.json").read_text())["version"]
                != expected
            ):
                raise RuntimeError(f"{name} version mismatch: require {expected}")
        eslint = command(
            [
                "node",
                str(modules / "eslint/bin/eslint.js"),
                "--config",
                "tools/quality-node/eslint.config.mjs",
                "--format=json",
                *javascript,
            ]
        )
        for item in json.loads(eslint):
            path = str(Path(item["filePath"]).relative_to(ROOT))
            for finding in item["messages"]:
                diagnostics.append(
                    fingerprint(
                        "eslint",
                        path,
                        finding["ruleId"] or "parse",
                        finding["line"],
                        finding["message"],
                    )
                )
        output = command(
            [
                "node",
                str(modules / "typescript/bin/tsc"),
                "--noEmit",
                "--allowJs",
                "--checkJs",
                "--strict",
                "--target",
                "es2022",
                "--module",
                "nodenext",
                "--moduleResolution",
                "nodenext",
                "--typeRoots",
                str(modules / "@types"),
                "--skipLibCheck",
                "--pretty",
                "false",
                *javascript,
            ],
            (0, 2),
        )
        for line in output.splitlines():
            match = re.match(r"(.+?)\((\d+),\d+\): error (TS\d+): (.+)", line)
            if match:
                diagnostics.append(
                    fingerprint("tsc", match[1], match[3], int(match[2]), match[4])
                )
            elif line and not line.startswith(" "):
                raise RuntimeError("unparsed TypeScript diagnostic")
        for path in javascript:
            formatted = command(
                ["node", str(modules / "prettier/bin/prettier.cjs"), path], (0,)
            )
            if formatted != (ROOT / path).read_text():
                diagnostics.append(
                    json.dumps(
                        [
                            "prettier",
                            path,
                            hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                        ]
                    )
                )
    summary["javascript"] = {
        "files": len(javascript),
        "tools": list(NODE_PINS),
        "not_applicable": not javascript,
    }
    return diagnostics, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="explicit reviewed debt capture; never used in CI",
    )
    args = parser.parse_args()
    os.chdir(ROOT)
    baseline_path = ROOT / "tools/quality-baseline.json"
    try:
        diagnostics, summary = collect(inputs())
        current = Counter(diagnostics)
        if args.write_baseline:
            baseline_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "reason": "Existing debt at initial D03 adoption; additions require review, not automatic refresh.",
                        "diagnostics": dict(sorted(current.items())),
                    },
                    indent=2,
                )
                + "\n"
            )
        baseline = json.loads(baseline_path.read_text())
        if baseline.get("schema_version") != 1 or not isinstance(
            baseline.get("diagnostics"), dict
        ):
            raise RuntimeError("invalid quality baseline")
        added = current - Counter(baseline["diagnostics"])
        print(
            json.dumps(
                {
                    "status": "failed" if added else "passed",
                    "new_diagnostics": sum(added.values()),
                    "existing_debt": sum(
                        (current & Counter(baseline["diagnostics"])).values()
                    ),
                    "checks": summary,
                },
                sort_keys=True,
            )
        )
        for diagnostic, count in sorted(added.items()):
            print(f"NEW ({count}) {diagnostic}")
        return bool(added)
    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
        metadata.PackageNotFoundError,
    ) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
