"""Synthetic ownership/order tests; no actual processes or signal operations."""

from __future__ import annotations

import importlib.util
import json
import signal
import subprocess
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "hygiene_lifetime", Path(__file__).resolve().parents[1] / "tools/hygiene.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("hygiene module unavailable")
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)
ROOT = Path(__file__).resolve().parents[1]


class OwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 0.0
        self.events: list[str] = []
        self.exit_code: int | None = 0
        self.wait_error: BaseException | None = None
        self.kill_error: OSError | None = None
        self.reads: list[bytes | BaseException] = [b""]
        self.process: Any = Mock(pid=424242, returncode=None)
        self.process.stdout.fileno.return_value = 42
        self.process.poll.side_effect = self.poll
        self.process.wait.side_effect = self.wait
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.select.side_effect = self.select
        patches = [
            patch.object(hygiene.subprocess, "Popen", return_value=self.process),
            patch.object(hygiene.shutil, "which", return_value="synthetic-tool"),
            patch.object(hygiene.signal, "getsignal", return_value=signal.SIG_DFL),
            patch.object(hygiene.selectors, "DefaultSelector", return_value=selector),
            patch.object(hygiene.os, "set_blocking"),
            patch.object(hygiene.os, "read", side_effect=self.read),
            patch.object(hygiene.os, "killpg", side_effect=self.kill),
            patch.object(hygiene.time, "monotonic", side_effect=lambda: self.now),
            patch.object(hygiene.time, "sleep", side_effect=self.advance),
        ]
        self.mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)

    def advance(self, delay: float) -> None:
        self.now += delay

    def select(self, delay: float) -> list[bool]:
        self.advance(delay)
        return [True]

    def poll(self) -> int | None:
        self.events.append("poll")
        if self.process.returncode is None:
            self.process.returncode = self.exit_code
        return self.process.returncode  # type: ignore[no-any-return]

    def wait(self, *, timeout: float) -> int:
        self.events.append("wait")
        self.assertEqual(timeout, hygiene.PROCESS_CLEANUP_SECONDS)
        if self.wait_error is not None:
            raise self.wait_error
        self.process.returncode = -signal.SIGKILL
        return -signal.SIGKILL

    def kill(self, pid: int, sig: int) -> None:
        self.events.append("kill")
        self.assertEqual((pid, sig), (424242, signal.SIGKILL))
        self.assertIsNone(self.process.returncode, "signal after leader was reaped")
        if self.kill_error is not None:
            raise self.kill_error

    def read(self, fd: int, size: int) -> bytes:
        self.assertEqual((fd, size), (42, 8192))
        item = self.reads.pop(0) if self.reads else BlockingIOError()
        if isinstance(item, BaseException):
            raise item
        return item

    def run_entry(self) -> dict[str, Any]:
        result: dict[str, Any] = hygiene.run_entry(
            ROOT, {"id": "owned", "command": ["synthetic-tool"], "timeout_seconds": 0.1}
        )
        return result

    def test_leader_exit_open_pipe_never_signals_or_passes(self) -> None:
        self.reads = []
        receipt = self.run_entry()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["reason"], "output_incomplete")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertFalse(receipt["output_complete"])
        self.assertNotIn("kill", self.events)
        self.assertNotIn("wait", self.events)
        self.process.stdout.close.assert_called_once()
        self.assertLessEqual(self.now, 2.1)
        self.assertIn(
            "reason=output_incomplete",
            hygiene.failure_summary({"checks": [receipt]})[0],
        )

    def test_original_failure_and_sanitized_diagnostic_survive_open_pipe(self) -> None:
        self.exit_code = 7
        self.reads = [b"AssertionError: PRIVATE_CANARY\n"]
        receipt = self.run_entry()
        self.assertEqual(receipt["exit_code"], 7)
        self.assertEqual(
            receipt["reported_diagnostic"]["category"], "assertion_failure"
        )
        self.assertNotIn("PRIVATE_CANARY", json.dumps(receipt))
        self.assertNotIn("kill", self.events)

    def test_timeout_signals_once_before_bounded_wait(self) -> None:
        self.exit_code = None
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "timeout")
        self.assertEqual(receipt["status"], "failed")
        self.assertNotIn("exit_code", receipt)
        self.assertTrue(receipt["output_complete"])
        self.assertEqual(self.events.count("kill"), 1)
        self.assertLess(self.events.index("kill"), self.events.index("wait"))
        self.assertNotIn("cleanup", receipt)
        self.assertEqual(self.mocks[0].call_args.kwargs["bufsize"], 0)

    def test_unreaped_timeout_is_unknown_and_never_retried(self) -> None:
        self.exit_code = None
        self.wait_error = subprocess.TimeoutExpired("synthetic", 2)
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "timeout")
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertEqual(self.events.count("kill"), 1)
        self.assertEqual(self.events.count("wait"), 1)

    def test_missing_group_preserves_timeout_not_start_failure(self) -> None:
        self.exit_code = None
        self.kill_error = ProcessLookupError()
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "timeout")
        self.assertEqual(receipt["signal_error"], "not_found")
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertEqual(self.events.count("kill"), 1)
        self.assertEqual(self.events.count("wait"), 1)

    def test_signal_failure_preserves_timeout_and_unknown_cleanup(self) -> None:
        self.exit_code = None
        self.kill_error = PermissionError("PRIVATE_CANARY")
        self.wait_error = subprocess.TimeoutExpired("synthetic", 2)
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "timeout")
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertNotIn("PRIVATE_CANARY", json.dumps(receipt))
        self.assertEqual(receipt["signal_error"], "permission_denied")
        self.assertEqual(receipt["reap_error"], "timeout")

    def test_read_failure_after_reap_never_signals(self) -> None:
        self.exit_code = 7
        self.reads = [OSError("PRIVATE_CANARY")]
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "output_read_failed")
        self.assertEqual(receipt["exit_code"], 7)
        self.assertNotIn("kill", self.events)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(receipt))

    def test_read_failure_before_reap_stops_owned_process(self) -> None:
        self.exit_code = None
        self.reads = [OSError()]
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "output_read_failed")
        self.assertEqual(self.events.count("kill"), 1)
        self.process.stdout.close.assert_called_once()

    def test_close_failure_does_not_overwrite_timeout(self) -> None:
        self.exit_code = None
        self.process.stdout.close.side_effect = OSError()
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "timeout")
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertEqual(self.events.count("kill"), 1)

    def test_cancellation_preserved_after_bounded_owned_cleanup(self) -> None:
        self.exit_code = None
        self.reads = [KeyboardInterrupt()]
        with self.assertRaises(KeyboardInterrupt):
            self.run_entry()
        self.assertEqual(self.events.count("kill"), 1)
        self.assertEqual(self.events.count("wait"), 1)
        self.process.stdout.close.assert_called_once()

    def test_cleanup_interruption_preserves_original_cancellation_and_closes(
        self,
    ) -> None:
        self.exit_code = None
        original = KeyboardInterrupt("primary cancellation")
        self.reads = [original]
        self.wait_error = KeyboardInterrupt("cleanup cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_entry()
        self.assertIs(caught.exception, original)
        self.process.stdout.close.assert_called_once()
        self.assertEqual(self.events.count("kill"), 1)
        self.assertEqual(self.events.count("wait"), 1)

    def test_first_interruption_during_timeout_cleanup_propagates_and_closes(
        self,
    ) -> None:
        self.exit_code = None
        original = KeyboardInterrupt("cleanup cancellation")
        self.wait_error = original
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_entry()
        self.assertIs(caught.exception, original)
        self.process.stdout.close.assert_called_once()
        self.assertEqual(self.events.count("kill"), 1)

    def test_first_close_cancellation_inside_handled_caller_error_propagates(
        self,
    ) -> None:
        cancellation = KeyboardInterrupt("first close cancellation")
        self.process.stdout.close.side_effect = cancellation
        try:
            raise ValueError("already handled outside the collector")
        except ValueError:
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_entry()
        self.assertIs(caught.exception, cancellation)
        self.assertNotIn("kill", self.events)
        self.process.stdout.close.assert_called_once()

    def test_first_cleanup_cancellation_after_read_error_propagates(self) -> None:
        self.exit_code = None
        self.reads = [OSError("handled read error")]
        cancellation = KeyboardInterrupt("first cleanup cancellation")
        self.wait_error = cancellation
        try:
            raise ValueError("already handled outside the collector")
        except ValueError:
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_entry()
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.events.count("kill"), 1)
        self.process.stdout.close.assert_called_once()

    def test_cancellation_after_reap_never_signals(self) -> None:
        self.reads = [KeyboardInterrupt()]
        with self.assertRaises(KeyboardInterrupt):
            self.run_entry()
        self.assertNotIn("kill", self.events)
        self.process.stdout.close.assert_called_once()

    def test_continuous_output_does_not_starve_timeout_or_drain_deadline(self) -> None:
        self.exit_code = None
        self.reads = [b"x" * 8192] * 100
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "timeout")
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertFalse(receipt["output_complete"])
        self.assertEqual(self.events.count("kill"), 1)
        self.assertLessEqual(self.now, 2.2)

    def test_synthetic_output_tail_is_bounded(self) -> None:
        self.reads = [b"x" * 8192] * 10 + [b"FINAL_MARKER", b""]
        receipt, output = hygiene.collect_process(self.process, 0.1)
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["output_complete"])
        self.assertEqual(len(output.encode()), 65536)
        self.assertTrue(output.endswith("FINAL_MARKER"))
        self.assertNotIn("kill", self.events)

    def test_nondefault_sigchld_prevents_spawn(self) -> None:
        self.mocks[2].return_value = signal.SIG_IGN
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "process_ownership_unavailable")
        self.mocks[0].assert_not_called()
        self.assertNotIn("kill", self.events)

    def test_changed_sigchld_never_signals_or_reports_success(self) -> None:
        self.mocks[2].side_effect = [signal.SIG_DFL, signal.SIG_IGN, signal.SIG_IGN]
        receipt = self.run_entry()
        self.assertEqual(receipt["reason"], "process_ownership_unavailable")
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cleanup"], "unknown")
        self.assertNotIn("kill", self.events)
        self.assertNotIn("wait", self.events)

    def test_stop_of_already_reaped_leader_is_noop(self) -> None:
        self.process.returncode = 0
        self.assertEqual(hygiene.stop_owned_process(self.process), {})
        self.assertEqual(self.events, [])



if __name__ == "__main__":
    unittest.main()
