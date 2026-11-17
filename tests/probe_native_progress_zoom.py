"""Bounded actual SIGTERM cleanup probe for the additive native-browser harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def process_start(pid: int) -> str | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return text.rsplit(")", 1)[1].split()[19]
    except FileNotFoundError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", required=True)
    parser.add_argument("--playwright", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        raise ValueError("new report required")
    with tempfile.TemporaryDirectory(prefix="native-zoom-cancel-probe-") as directory:
        root = Path(directory)
        with (root / "log").open("w") as log:
            process = subprocess.Popen(
                [
                    "node",
                    str(ROOT / "tools/check_native_progress_zoom.cjs"),
                    "--browser",
                    args.browser,
                    "--playwright",
                    args.playwright,
                    "--output",
                    str(root / "actual"),
                ],
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            owned = None
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(
                            "harness exited before actual browser checkpoint"
                        )
                    for line in subprocess.check_output(
                        ["ps", "-eo", "pid=,ppid=,args="], text=True
                    ).splitlines():
                        fields = line.strip().split(None, 2)
                        if len(fields) != 3 or int(fields[1]) != process.pid:
                            continue
                        match = re.search(r"--user-data-dir=(/[^\s]+)", fields[2])
                        if match:
                            profile = Path(match.group(1))
                            if not profile.name.startswith("tether-native-zoom-"):
                                raise RuntimeError("unexpected owned profile")
                            owned = (
                                int(fields[0]),
                                process_start(int(fields[0])),
                                profile,
                            )
                            break
                    if owned:
                        break
                    time.sleep(0.05)
                if not owned:
                    raise RuntimeError("actual browser checkpoint deadline")
                # Signal only the still-unreaped process we created, never a guessed PID.
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=30)
                receipt = json.loads((root / "actual/evidence.json").read_text())
                if code == 0 or receipt["status"] != "failed":
                    raise AssertionError("cancelled native qualification must not pass")
                if owned[1] is not None and process_start(owned[0]) == owned[1]:
                    raise AssertionError("owned browser survived cancellation")
                if owned[2].exists():
                    raise AssertionError(
                        "owned synthetic profile survived cancellation"
                    )
                args.report.write_text(
                    json.dumps(
                        {
                            "status": "passed",
                            "probe": "actual_browser_started_then_SIGTERM",
                            "harness_exit": code,
                            "owned_browser_absent": True,
                            "owned_profile_absent": True,
                            "qualifier_report_status": receipt["status"],
                            "log_sha256": hashlib.sha256(
                                (root / "log").read_bytes()
                            ).hexdigest(),
                            "scope": "actual_process_cleanup_not_live_provider_or_visual_approval",
                        },
                        indent=2,
                    )
                    + "\n"
                )
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=30)


if __name__ == "__main__":
    main()
