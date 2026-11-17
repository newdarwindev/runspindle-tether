"""Opt-in real renderer cleanup; disposable synthetic files and process owners."""

import os
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("RUNSPINDLE_VISUAL_BROWSER"), "explicit pinned renderer required"
)
class VisualCancellationTests(unittest.TestCase):
    def test_sigterm_after_first_frame_reaps_owned_children_and_publishes_nothing(self):
        with tempfile.TemporaryDirectory(prefix="tether-render-cancel-") as temporary:
            root = Path(temporary)
            output = root / "candidates"
            process = subprocess.Popen(
                [
                    sys.executable,
                    "tools/render_progress_fixtures.py",
                    "--browser",
                    os.environ["RUNSPINDLE_VISUAL_BROWSER"],
                    "--expected-browser-version",
                    os.environ["RUNSPINDLE_VISUAL_BROWSER_VERSION"],
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": str(ROOT), "TMPDIR": temporary},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            handles = {}
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and process.poll() is None:
                    if list(root.glob("**/progress-320.png")):
                        break
                    time.sleep(0.05)
                self.assertTrue(
                    list(root.glob("**/progress-320.png")),
                    "first owned frame not generated",
                )
                rows = [
                    line.split(None, 2)
                    for line in subprocess.check_output(
                        ["ps", "-eo", "pid=,ppid=,comm="], text=True
                    ).splitlines()
                ]
                descendants = {process.pid}
                for _ in range(16):
                    descendants.update(
                        int(pid) for pid, ppid, _ in rows if int(ppid) in descendants
                    )
                for pid in descendants - {process.pid}:
                    try:
                        handles[pid] = os.pidfd_open(pid)
                    except ProcessLookupError:
                        pass
                self.assertTrue(handles, "owned browser processes not observed")
                process.terminate()
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 143, (stdout, stderr))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    active = [
                        pid
                        for pid, fd in handles.items()
                        if not select.select([fd], [], [], 0)[0]
                    ]
                    if not active:
                        break
                    time.sleep(0.05)
                self.assertFalse(active, "owned process survived cancellation")
                self.assertFalse(output.exists(), "partial candidates published")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=5)
                for fd in handles.values():
                    if not select.select([fd], [], [], 0)[0]:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    os.close(fd)
