"""Append-only execution provenance graph and replay reconstruction utilities."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Iterable
import math
import threading

from Virus_Scan.runtime.provenance import stable_digest
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name

_PROVENANCE_GRAPH_TEXT_UNAVAILABLE = "provenance_graph_text_unavailable"
_EMPTY_PROVENANCE_GRAPH_TEXT = "provenance_graph_text_empty"


def _graph_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return no_hook_type_name(value)


def _graph_join(left: str, right: object) -> str:
    return str.__str__(left) + str.__str__(right)


def _graph_indexed(base: str, index: int) -> str:
    return str.__str__(base) + "#" + int.__str__(index)


def _unavailable_text(value: object, reason: str | None = None) -> str:
    suffix = str.__str__(reason) if type(reason) is str else no_hook_type_name(value)
    return _graph_join(_PROVENANCE_GRAPH_TEXT_UNAVAILABLE + ":", suffix)


def _exact_text(value: object) -> str | None:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bytes:
        return bytes.decode(value, "utf-8", "replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", "replace")
    return None


def _text(value: object, *, default: str | None = None, allow_empty: bool = False) -> str:
    if value is None:
        return default if default is not None else _unavailable_text(value, "none")
    exact = _exact_text(value)
    if exact is None:
        if type(value) is bool:
            exact = "true" if value else "false"
        elif type(value) is int:
            exact = int.__repr__(value)
        elif type(value) is float:
            exact = float.__repr__(value) if math.isfinite(value) else _unavailable_text(value, "nonfinite_float")
        else:
            exact = _unavailable_text(value)
    if exact == "" and not allow_empty:
        return default if default is not None else _EMPTY_PROVENANCE_GRAPH_TEXT
    return exact


def _unique_key(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    index = 2
    while _graph_indexed(base, index) in used:
        index += 1
    key = _graph_indexed(base, index)
    used.add(key)
    return key


def _sort_key(value: object) -> tuple[str, str]:
    return (_text(value), no_hook_type_name(value))


def _mapping_payload(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return {"provenance_graph_payload_unavailable": _unavailable_text(value, "unsupported_mapping")}
    return value


def _parent_values(parent_ids: object) -> tuple[object, ...]:
    if parent_ids is None:
        return ()
    if type(parent_ids) in (tuple, list):
        return tuple(parent_ids)
    if type(parent_ids) in (set, frozenset):
        return tuple(sorted(parent_ids, key=_sort_key))
    if type(parent_ids) is str:
        return (parent_ids,)
    return (_unavailable_text(parent_ids, "unsupported_parent_iterable"),)


def _safe_mapping_projection(
    items: tuple[tuple[object, object], ...],
) -> dict[str, object]:
    out: dict[str, object] = {}
    used: set[str] = set()
    for key, item in sorted(items, key=lambda entry: _sort_key(entry[0])):
        projected = _unique_key(_text(key), used)
        out[projected] = _safe(item)
    return out


def _safe_container_projection(value: object) -> list[object]:
    if type(value) in (set, frozenset):
        items = sorted(value, key=_sort_key)
    else:
        items = value
    return [_safe(item) for item in items]


def _safe_scalar_projection(value: object) -> object:
    if type(value) is str:
        projected: object = _text(value, allow_empty=True)
    elif type(value) is bool or value is None or type(value) is int:
        projected = value
    elif type(value) is float:
        projected = (
            value
            if math.isfinite(value)
            else _unavailable_text(value, "nonfinite_float")
        )
    else:
        projected = _unavailable_text(value)
    return projected


def _safe_nonmapping_projection(value: object) -> object:
    if isinstance(value, Mapping):
        projected = _unavailable_text(value, "unsupported_mapping")
    elif type(value) in (set, frozenset, list, tuple):
        projected = _safe_container_projection(value)
    else:
        projected = _safe_scalar_projection(value)
    return projected


def _safe(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        return _safe_mapping_projection(items)
    return _safe_nonmapping_projection(value)


@dataclass(frozen=True)
class ProvenanceGraphEvent:
    event_id: str
    event_type: str
    subsystem: str
    parent_ids: tuple[str, ...] = ()
    payload: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not ProvenanceGraphEvent:
            exception_message = "provenance graph event owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "event_id", _text(self.event_id, default="provenance_graph_event_id_unavailable"))
        object.__setattr__(self, "event_type", _text(self.event_type, default="event"))
        object.__setattr__(self, "subsystem", _text(self.subsystem, default="runtime"))
        object.__setattr__(self, "payload", freeze_runtime_value(_safe(_mapping_payload(self.payload) if self.payload is not None else {})))
        object.__setattr__(self, "parent_ids", tuple(
            _text(parent, default="provenance_graph_parent_unavailable")
            for parent in _parent_values(self.parent_ids)
        ))

    @classmethod
    def build(cls, *, event_type: str, subsystem: str, payload: Mapping[str, object] | None = None, parent_ids: Iterable[str] = ()) -> "ProvenanceGraphEvent":
        parents = tuple(
            _text(parent, default="provenance_graph_parent_unavailable")
            for parent in _parent_values(parent_ids)
        )
        canonical = {
            "event_type": _text(event_type, default="event"),
            "subsystem": _text(subsystem, default="runtime"),
            "parents": parents,
            "payload": _safe(_mapping_payload(payload) if payload is not None else {}),
        }
        event_id = stable_digest("provenance_graph_event", canonical)
        return cls(
            event_id=event_id,
            event_type=canonical["event_type"],
            subsystem=canonical["subsystem"],
            parent_ids=parents,
            payload=canonical["payload"],
        )

    def canonical(self) -> dict[str, object]:
        return {
            "event_id": _text(self.event_id, default="provenance_graph_event_id_unavailable"),
            "event_type": _text(self.event_type, default="event"),
            "subsystem": _text(self.subsystem, default="runtime"),
            "parent_ids": list(self.parent_ids),
            "payload": _safe(materialize_runtime_value(self.payload)),
        }


class ProvenanceGraphStore:
    """Thread-safe append-only graph with deterministic canonical snapshots."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: list[ProvenanceGraphEvent] = []

    def append(self, event: ProvenanceGraphEvent | Mapping[str, object]) -> ProvenanceGraphEvent:
        if not isinstance(event, ProvenanceGraphEvent):
            items = no_hook_mapping_items(event)
            if items is None:
                event_map = {
                    "event_type": _unavailable_text(event, "unsupported_event_mapping"),
                    "subsystem": "runtime",
                    "payload": {"provenance_graph_event_unavailable": _unavailable_text(event, "unsupported_mapping")},
                    "parent_ids": (),
                }
            else:
                event_map = dict(items)
            raw_payload = dict.get(event_map, "payload")
            payload_items = no_hook_mapping_items(raw_payload)
            payload: Mapping[str, object] = (
                dict(payload_items) if payload_items is not None else event_map
            )
            parent_source = dict.get(event_map, "parent_ids")
            if parent_source is None:
                parent_source = dict.get(event_map, "parent_chain", ())
            event = ProvenanceGraphEvent.build(
                event_type=_text(dict.get(event_map, "event_type", "event"), default="event"),
                subsystem=_text(
                    dict.get(event_map, "subsystem", dict.get(event_map, "origin_subsystem", "runtime")),
                    default="runtime",
                ),
                payload=payload,
                parent_ids=tuple(_text(parent, default="provenance_graph_parent_unavailable") for parent in _parent_values(parent_source)),
            )
        with self._lock:
            # Append-only means repeated identical events remain observable.
            # Earlier de-duplication collapsed retry/cancellation/replay repeats and
            # could hide lineage multiplicity under stress.
            self._events.append(event)
        return event

    def canonical_snapshot(self) -> dict[str, object]:
        with self._lock:
            source_events = tuple(self._events)
        events = []
        for index, event in enumerate(source_events):
            item = event.canonical()
            item["append_index"] = index
            item["append_record_id"] = stable_digest("provenance_graph_append", index, item)
            events.append(item)
        ids = {e["event_id"] for e in events}
        missing_parents = [
            {"event_id": e["event_id"], "missing_parent": parent}
            for e in events
            for parent in e.get("parent_ids", [])
            if parent not in ids
        ]
        return {"events": events, "missing_parents": missing_parents, "graph_digest": stable_digest("provenance_graph", events)}

    def validate(self) -> dict[str, object]:
        snap = self.canonical_snapshot()
        return {"ok": not snap["missing_parents"], "event_count": len(snap["events"]), "missing_parents": snap["missing_parents"], "graph_digest": snap["graph_digest"]}


__all__ = ("ProvenanceGraphEvent", "ProvenanceGraphStore")
