#!/usr/bin/env python3
"""Run implemented component validation; product acceptance stays separate."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)


def run(argv):
    started = time.monotonic()
    result = subprocess.run(argv, check=False)
    print(json.dumps({"command": argv, "exit_code": result.returncode,
                      "seconds": round(time.monotonic() - started, 3)}), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def main():
    identity = Path("/etc/runspindle-image.json")
    image_manifest = json.loads(identity.read_text()) if identity.exists() else {}
    instance = Path("/etc/runspindle-instance.json")
    print(json.dumps({"evidence_class": "implemented_validation",
        "sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "python": sys.version, "machine": platform.machine(),
        "image": {"identity": image_manifest.get("identity", "local-unattested"), "versions": image_manifest.get("versions", {}),
                  "instance": json.loads(instance.read_text()) if instance.exists() else None},
        "product_acceptance": "not_run"}), flush=True)
    for tool in ("git", "rustc", "cargo", "node"):
        import shutil
        if shutil.which(tool):
            run([tool, "--version"])
    run([sys.executable, "tools/check_scaffold.py"])
    # Each implemented repository checker runs as a real process. Acceptance
    # gates are deliberately excluded and retain their own failing workflows.
    for name in ("check_artifacts.py", "check_references.py", "check_shared_fixtures.py",
                 "check_model_mutations.py", "check_projection_mutations.py", "check_temporal_mutations.py"):
        if (ROOT / "tools" / name).exists():
            run([sys.executable, "tools/" + name])
    if (ROOT / "tests").exists():
        run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    if (ROOT / "Cargo.toml").exists():
        run(["cargo", "fmt", "--all", "--", "--check"])
        if not (ROOT / "Cargo.lock").exists():
            run(["cargo", "generate-lockfile", "--offline"])
        run(["cargo", "test", "--offline", "--locked"])
        run(["cargo", "clippy", "--offline", "--locked", "--all-targets", "--", "-D", "warnings"])
    if (ROOT / "package.json").exists():
        package = json.loads((ROOT / "package.json").read_text())
        for script in ("test", "build"):
            if script in package.get("scripts", {}):
                run(["npm", "run", script])
    artifacts = {}
    for folder in ("dist", "build", "target/release"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file():
                artifacts[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps({"status": "passed", "artifact_sha256": artifacts,
        "build": "checksums_recorded" if artifacts else "no_distributable_build_implemented",
        "remaining_gates": json.loads((ROOT / "STATUS.json").read_text())}), flush=True)


if __name__ == "__main__":
    main()
