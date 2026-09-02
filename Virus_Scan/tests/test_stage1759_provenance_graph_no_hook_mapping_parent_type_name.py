from __future__ import annotations

from collections.abc import Iterable, Mapping
import inspect

from Virus_Scan.runtime import provenance_graph
from Virus_Scan.runtime.provenance_graph import ProvenanceGraphEvent, ProvenanceGraphStore


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            type.__setattr__(cls, "touched", type.__getattribute__(cls, "touched") + 1)
            raise RuntimeError("do not read class name through metaclass hook")
        return type.__getattribute__(cls, name)


class HostilePayloadValue(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not stringify payload value")

    def __repr__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not repr payload value")

    def __format__(self, spec):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not format payload value")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not iterate mapping")

    def __len__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not len mapping")

    def __getitem__(self, key):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not index mapping")

    def keys(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not call keys")

    def items(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not call items")

    def get(self, key, default=None):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not call get")


class HostileParentIterable(Iterable):
    touched = 0

    def __iter__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not iterate parent ids")

    def __bool__(self):
        type.__setattr__(type(self), "touched", type.__getattribute__(type(self), "touched") + 1)
        raise RuntimeError("do not truth-test parent ids")


def _reset() -> None:
    type.__setattr__(HostileNameMeta, "touched", 0)
    type.__setattr__(HostilePayloadValue, "touched", 0)
    type.__setattr__(HostileMapping, "touched", 0)
    type.__setattr__(HostileParentIterable, "touched", 0)


def _touch_count() -> int:
    return (
        type.__getattribute__(HostileNameMeta, "touched")
        + type.__getattribute__(HostilePayloadValue, "touched")
        + type.__getattribute__(HostileMapping, "touched")
        + type.__getattribute__(HostileParentIterable, "touched")
    )


def test_provenance_graph_rejects_hostile_mapping_parent_iterable_and_type_name_without_hooks() -> None:
    _reset()
    row = ProvenanceGraphEvent.build(
        event_type=HostilePayloadValue(),
        subsystem=HostilePayloadValue(),
        parent_ids=HostileParentIterable(),
        payload=HostileMapping(),
    ).canonical()

    assert row["event_type"].startswith("provenance_graph_text_unavailable:")
    assert row["subsystem"].startswith("provenance_graph_text_unavailable:")
    assert row["parent_ids"] == ["provenance_graph_text_unavailable:unsupported_parent_iterable"]
    assert row["payload"]["provenance_graph_payload_unavailable"].startswith(
        "provenance_graph_text_unavailable:"
    )
    assert _touch_count() == 0


def test_provenance_store_append_rejects_hostile_mapping_without_dict_or_mapping_hooks() -> None:
    _reset()
    store = ProvenanceGraphStore()

    event = store.append(HostileMapping())
    snapshot = store.canonical_snapshot()

    assert event.event_type == "provenance_graph_text_unavailable:unsupported_event_mapping"
    assert snapshot["events"][0]["payload"]["provenance_graph_event_unavailable"].startswith(
        "provenance_graph_text_unavailable:"
    )
    assert _touch_count() == 0


def test_provenance_graph_set_sorting_uses_no_hook_type_name() -> None:
    _reset()
    value = HostilePayloadValue()

    row = ProvenanceGraphEvent.build(
        event_type="set-sort",
        subsystem="runtime",
        payload={"tags": {"safe", value}},
    ).canonical()

    assert any(item.startswith("provenance_graph_text_unavailable:") for item in row["payload"]["tags"])
    assert _touch_count() == 0


def test_provenance_graph_source_removed_private_reachable_hook_paths() -> None:
    source = inspect.getsource(provenance_graph)

    assert "no_hook_type_name(value)" in source
    assert "no_hook_mapping_items" in source
    assert "type(value).__name__" not in source
    assert "type(key).__name__" not in source
    assert ".keys()" not in source
    assert "dict(event)" not in source
