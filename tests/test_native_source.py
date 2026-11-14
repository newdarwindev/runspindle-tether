"""Finite native-event fixture tests: no actual sessions or network."""

import importlib.util
import itertools
import socket
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from tether.native_testing import (
    KINDS,
    Availability,
    Binding,
    Event,
    Mode,
    NativeSource,
)
from tether.testing import Destination, FakeSlack, Payload

BINDING = Binding("task-1", "host-1", "session-1", Destination("w-1", "c-1", "t-1"))
PAYLOAD = Payload("Invented public fixture")


def event(sequence: int = 1, kind: str = "final") -> Event:
    return Event(BINDING, f"event-{sequence}", sequence, 100, kind, PAYLOAD)


class NativeSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 100
        self.source = NativeSource(BINDING, Mode.EVENTS, lambda: self.now)
        ids = itertools.count(1)
        self.slack = FakeSlack(
            BINDING.destination, lambda: self.now, lambda: f"message-{next(ids)}"
        )
        self.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("network forbidden")
        )
        self.connect = self.network.start()
        self.addCleanup(self.network.stop)

    def tearDown(self) -> None:
        self.connect.assert_not_called()

    def send(self, item: Event) -> object:
        return self.slack.send(item.binding.destination, item.event_id, item.payload)

    def test_all_public_kinds_preserve_identity_and_actual_effects(self) -> None:
        seen: list[Event] = []

        def sink(item: Event) -> object:
            seen.append(item)
            return self.send(item)

        for sequence, kind in enumerate(sorted(KINDS), 1):
            item = event(sequence, kind)
            result = self.source.emit(item, sink)
            self.assertEqual(result.outcome, "submitted")
            self.assertEqual(result.evidence_class, "synthetic")
            self.assertEqual(seen[-1], item)
        self.assertEqual(len(self.slack.requests), len(KINDS))
        self.assertEqual(len(self.slack.records), len(KINDS))
        self.assertTrue(
            all(
                row.destination == BINDING.destination
                for row in self.slack.records.values()
            )
        )
        self.assertNotIn("confirmed", repr(self.source.observations))

    def test_each_unavailable_state_has_zero_transport_calls(self) -> None:
        for state in (
            Availability.UNBOUND,
            Availability.STALE,
            Availability.DISCONNECTED,
        ):
            self.source.set_availability(state)
            self.assertEqual(self.source.emit(event(), self.send).outcome, state.value)
        self.assertEqual(len(self.slack.requests), 0)
        self.assertEqual(len(self.slack.records), 0)

    def test_wrong_task_host_session_and_each_destination_field(self) -> None:
        bindings = [
            replace(BINDING, task_id="other"),
            replace(BINDING, host_id="other"),
            replace(BINDING, session_id="other"),
        ]
        bindings += [
            replace(BINDING, destination=replace(BINDING.destination, **{key: "other"}))
            for key in ("workspace_id", "channel_id", "thread_id")
        ]
        for binding in bindings:
            self.assertEqual(
                self.source.emit(replace(event(), binding=binding), self.send).outcome,
                "wrong_binding",
            )
        self.assertEqual(len(self.slack.requests), 0)

    def test_capability_modes_never_invent_event_coverage(self) -> None:
        for mode, allowed in [
            (Mode.EVENTS, KINDS),
            (Mode.FINAL_ONLY, {"final"}),
            (Mode.SNAPSHOT_ONLY, {"snapshot"}),
            (Mode.UNSUPPORTED, set()),
        ]:
            with self.subTest(mode=mode):
                source = NativeSource(BINDING, mode, lambda: 100)
                sink = Mock()
                for kind in KINDS | {"snapshot", "hidden_reasoning", "unknown"}:
                    result = source.emit(event(1, kind), sink)
                    if kind not in allowed:
                        self.assertEqual(result.outcome, "unsupported")
                self.assertEqual(source.matrix()["supported"], sorted(allowed))
                self.assertFalse(source.matrix()["control"])
                self.assertEqual(source.matrix()["live_coverage"], "not_run")
                self.assertEqual(sink.call_count, min(1, len(allowed)))
        snapshot = NativeSource(BINDING, Mode.SNAPSHOT_ONLY, lambda: 100)
        seen: list[Event] = []
        snapshot.emit(event(kind="snapshot"), seen.append)
        self.assertEqual(seen[0].kind, "snapshot")

    def test_gap_duplicate_replay_and_reconnect_do_not_repeat_effects(self) -> None:
        self.assertEqual(self.source.emit(event(2), self.send).outcome, "gap")
        self.source.emit(event(), self.send)
        self.source.set_availability(Availability.DISCONNECTED)
        self.source.emit(event(2), self.send)
        self.source.set_availability(Availability.BOUND)
        self.assertEqual(self.source.emit(event(), self.send).outcome, "duplicate")
        self.assertEqual(self.source.emit(event(2), self.send).outcome, "submitted")
        self.assertEqual(len(self.slack.records), 2)
        self.assertEqual(len(self.slack.requests), 2)

    def test_old_future_and_invalid_clock_are_no_effect(self) -> None:
        for timestamp in (69, 101):
            self.assertEqual(
                self.source.emit(
                    replace(event(), observed_at=timestamp), self.send
                ).outcome,
                "stale",
            )
        self.now = -1
        with self.assertRaises(ValueError):
            self.source.emit(event(), self.send)
        self.assertEqual(len(self.slack.requests), 0)

    def test_callback_unknown_is_consumed_and_error_text_not_recorded(self) -> None:
        def lost(item: Event) -> None:
            self.send(item)
            raise RuntimeError("SYNTHETIC_SECRET_CANARY")

        self.assertEqual(self.source.emit(event(), lost).outcome, "unknown")
        self.assertEqual(self.source.emit(event(), lost).outcome, "duplicate")
        self.assertEqual(len(self.slack.records), 1)
        self.assertNotIn("SYNTHETIC_SECRET_CANARY", repr(self.source.observations))

    def test_cancellation_is_unknown_and_reentrant_emit_is_refused(self) -> None:
        def cancelled(item: Event) -> None:
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.source.emit(event(), cancelled)
        self.assertEqual(self.source.observations[0].outcome, "unknown")
        self.assertEqual(self.source.emit(event(), self.send).outcome, "duplicate")

        def recursive(item: Event) -> None:
            with self.assertRaises(ValueError):
                self.source.emit(event(3), self.send)

        self.source.emit(event(2), recursive)
        self.assertEqual(len(self.slack.requests), 0)

    def test_capacity_is_bounded_and_observations_are_immutable(self) -> None:
        source = NativeSource(BINDING, Mode.UNSUPPORTED, lambda: 100, capacity=1)
        source.emit(event(), self.send)
        snapshot = source.observations
        with self.assertRaises(ValueError):
            source.emit(event(2), self.send)
        self.assertEqual(source.observations, snapshot)
        self.assertEqual(len(self.slack.requests), 0)

    def test_invalid_events_and_configuration_never_call_sink(self) -> None:
        for changes in ({"sequence": True}, {"observed_at": True}, {"event_id": ""}):
            with self.assertRaises(ValueError):
                self.source.emit(replace(event(), **changes), self.send)
        for kwargs in ({"capacity": True}, {"capacity": 4097}, {"freshness": -1}):
            with self.assertRaises(ValueError):
                NativeSource(BINDING, Mode.EVENTS, lambda: 100, **kwargs)
        self.assertEqual(len(self.slack.requests), 0)

    def test_removed_availability_guard_causes_independently_observed_forbidden_effect(
        self,
    ) -> None:
        original = Path(__file__).resolve().parents[1] / "tether/native_testing.py"
        source = original.read_text()
        anchor = "if self._availability is not Availability.BOUND:"
        self.assertEqual(source.count(anchor), 1)
        with tempfile.TemporaryDirectory() as directory:
            mutant = Path(directory) / "mutant.py"
            mutant.write_text(source.replace(anchor, "if False:"))
            spec = importlib.util.spec_from_file_location(
                "native_source_mutant", mutant
            )
            self.assertIsNotNone(spec)
            if spec is None or spec.loader is None:
                raise AssertionError("missing mutant loader")
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            try:
                spec.loader.exec_module(module)
                binding = module.Binding(
                    "task-1", "host-1", "session-1", BINDING.destination
                )
                fixture = module.NativeSource(binding, module.Mode.EVENTS, lambda: 100)
                fixture.set_availability(module.Availability.DISCONNECTED)
                item = module.Event(binding, "event-1", 1, 100, "final", PAYLOAD)
                fixture.emit(item, self.send)
                # This is the forbidden-effect oracle, independent of fixture receipts.
                self.assertEqual(len(self.slack.requests), 1)
                self.assertEqual(len(self.slack.records), 1)
                with self.assertRaises(AssertionError):
                    self.assertEqual(len(self.slack.records), 0)
            finally:
                sys.modules.pop(spec.name, None)


if __name__ == "__main__":
    unittest.main()
