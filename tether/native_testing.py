"""Synthetic exposed-event source; not a native adapter or permission boundary."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from tether.admission import identifier
from tether.testing import Destination, Payload


class Mode(Enum):
    EVENTS = "events"
    FINAL_ONLY = "final_only"
    SNAPSHOT_ONLY = "snapshot_only"
    UNSUPPORTED = "unsupported"


class Availability(Enum):
    BOUND = "bound"
    UNBOUND = "unbound"
    STALE = "stale"
    DISCONNECTED = "disconnected"


KINDS = frozenset(
    {
        "lifecycle",
        "public_summary",
        "tool_start",
        "tool_update",
        "tool_complete",
        "result",
        "error",
        "final",
        "usage",
    }
)


def capabilities(mode: Mode) -> frozenset[str]:
    if type(mode) is not Mode:
        raise ValueError("invalid synthetic mode")
    if mode is Mode.EVENTS:
        return KINDS
    if mode is Mode.FINAL_ONLY:
        return frozenset({"final"})
    if mode is Mode.SNAPSHOT_ONLY:
        return frozenset({"snapshot"})
    return frozenset()


@dataclass(frozen=True)
class Binding:
    task_id: str
    host_id: str
    session_id: str
    destination: Destination

    def validate(self) -> None:
        for value in (self.task_id, self.host_id, self.session_id):
            identifier(value)
        if type(self.destination) is not Destination:
            raise ValueError("invalid synthetic destination")
        self.destination.validate()


@dataclass(frozen=True)
class Event:
    binding: Binding
    event_id: str
    sequence: int
    observed_at: int
    kind: str
    payload: Payload


@dataclass(frozen=True)
class Observation:
    sequence: int
    outcome: str
    evidence_class: str = "synthetic"


class NativeSource:
    """Finite synchronous fixture. Accepted attempts are consumed before callbacks.

    The caller provides invented, already sanitized payloads and a fake sink.
    No automatic retry, authentication, production sanitization or persistence.
    """

    def __init__(
        self,
        binding: Binding,
        mode: Mode,
        clock: Callable[[], int],
        *,
        freshness: int = 30,
        capacity: int = 128,
    ) -> None:
        if type(binding) is not Binding:
            raise ValueError("invalid synthetic binding")
        binding.validate()
        capabilities(mode)
        if type(freshness) is not int or not 0 <= freshness <= 3600:
            raise ValueError("invalid freshness")
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ValueError("invalid capacity")
        self._binding = binding
        self._mode = mode
        self._clock = clock
        self._freshness = freshness
        self._capacity = capacity
        self._availability = Availability.BOUND
        self._sequence = 0
        self._ids: set[str] = set()
        self._observations: list[Observation] = []
        self._busy = False

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(self._observations)

    def set_availability(self, availability: Availability) -> None:
        if type(availability) is not Availability:
            raise ValueError("invalid availability")
        self._availability = availability

    def matrix(self) -> dict[str, object]:
        return {
            "mode": self._mode.value,
            "availability": self._availability.value,
            "supported": sorted(capabilities(self._mode)),
            "evidence_class": "synthetic",
            "control": False,
            "live_coverage": "not_run",
        }

    def emit(self, event: Event, sink: Callable[[Event], object]) -> Observation:
        if self._busy:
            raise ValueError("reentrant emission")
        if len(self._observations) >= self._capacity:
            raise ValueError("synthetic observation capacity")
        if type(event) is not Event or type(event.binding) is not Binding:
            raise ValueError("invalid synthetic event")
        event.binding.validate()
        identifier(event.event_id)
        if type(event.sequence) is not int or event.sequence <= 0:
            raise ValueError("invalid sequence")
        if type(event.observed_at) is not int or event.observed_at < 0:
            raise ValueError("invalid observation time")
        if type(event.kind) is not str or type(event.payload) is not Payload:
            raise ValueError("invalid event content")
        event.payload.validate()
        now = self._clock()
        if type(now) is not int or now < 0:
            raise ValueError("invalid synthetic clock")
        outcome = "accepted"
        if self._availability is not Availability.BOUND:
            outcome = self._availability.value
        elif event.binding != self._binding:
            outcome = "wrong_binding"
        elif event.kind not in capabilities(self._mode):
            outcome = "unsupported"
        elif not 0 <= now - event.observed_at <= self._freshness:
            outcome = "stale"
        elif event.event_id in self._ids or event.sequence <= self._sequence:
            outcome = "duplicate"
        elif event.sequence != self._sequence + 1:
            outcome = "gap"
        if outcome != "accepted":
            result = Observation(event.sequence, outcome)
            self._observations.append(result)
            return result
        self._sequence = event.sequence
        self._ids.add(event.event_id)
        # Never infer destination confirmation from a callback return value.
        result = Observation(event.sequence, "unknown")
        self._observations.append(result)
        index = len(self._observations) - 1
        self._busy = True
        try:
            sink(event)
            result = Observation(event.sequence, "submitted")
            self._observations[index] = result
        except Exception:
            pass  # Fixed outcome only; never expose callback messages/canaries.
        finally:
            self._busy = False
        return result
