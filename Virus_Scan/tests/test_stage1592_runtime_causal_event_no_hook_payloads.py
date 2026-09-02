from __future__ import annotations

from Virus_Scan.runtime.causal_event_stream import CausalEvent, EventBus


class HostilePayload(dict):
    items_touched = 0
    keys_touched = 0
    get_touched = 0
    iter_touched = 0
    bool_touched = 0
    str_touched = 0

    def items(self):  # pragma: no cover - must never be called
        type(self).items_touched += 1
        raise AssertionError("payload items hook executed")

    def keys(self):  # pragma: no cover - must never be called
        type(self).keys_touched += 1
        raise AssertionError("payload keys hook executed")

    def get(self, key, default=None):  # pragma: no cover - must never be called
        type(self).get_touched += 1
        raise AssertionError("payload get hook executed")

    def __iter__(self):  # pragma: no cover - must never be called
        type(self).iter_touched += 1
        raise AssertionError("payload iter hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).bool_touched += 1
        raise AssertionError("payload truthiness hook executed")

    def __str__(self):  # pragma: no cover - must never be called
        type(self).str_touched += 1
        raise AssertionError("payload str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).str_touched += 1
        raise AssertionError("payload repr hook executed")


class HostileKey:
    touched = 0

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("key str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("key repr hook executed")

    def __format__(self, spec):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("key format hook executed")


class HostileValue:
    touched = 0

    def __str__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("value str hook executed")

    def __repr__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("value repr hook executed")


class HostileCost:
    touched = 0

    def __float__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("cost float hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("cost truthiness hook executed")


class HostileParent:
    touched = 0

    def __int__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("parent int hook executed")

    def __bool__(self):  # pragma: no cover - must never be called
        type(self).touched += 1
        raise AssertionError("parent truthiness hook executed")


def _reset() -> None:
    HostilePayload.items_touched = 0
    HostilePayload.keys_touched = 0
    HostilePayload.get_touched = 0
    HostilePayload.iter_touched = 0
    HostilePayload.bool_touched = 0
    HostilePayload.str_touched = 0
    HostileKey.touched = 0
    HostileValue.touched = 0
    HostileCost.touched = 0
    HostileParent.touched = 0


def test_stage1592_causal_event_rejects_hostile_mapping_payload_without_mapping_hooks() -> None:
    _reset()
    hostile = HostilePayload({"stable": "value"})

    event = CausalEvent(1, "lineage", "runtime", "unit", hostile)
    row = event.as_dict()

    assert row["payload"]["unavailable_reason"] == "non_materializable_causal_mapping"
    assert HostilePayload.items_touched == 0
    assert HostilePayload.keys_touched == 0
    assert HostilePayload.get_touched == 0
    assert HostilePayload.iter_touched == 0
    assert HostilePayload.bool_touched == 0
    assert HostilePayload.str_touched == 0


def test_stage1592_event_bus_emit_rejects_hostile_payload_and_numeric_hooks() -> None:
    _reset()
    bus = EventBus()
    hostile = HostilePayload({"count": 7})

    event = bus.emit(
        "runtime",
        "exports_registered",
        hostile,
        cost=HostileCost(),
        parent_seq=HostileParent(),
    )
    row = event.as_dict()

    assert row["payload"]["payload_unavailable"]["unavailable_reason"] == "non_materializable_causal_payload_mapping"
    assert row["payload"]["contract_violation"] == "missing_fields:count"
    assert HostilePayload.items_touched == 0
    assert HostilePayload.keys_touched == 0
    assert HostilePayload.get_touched == 0
    assert HostilePayload.iter_touched == 0
    assert HostilePayload.bool_touched == 0
    assert HostilePayload.str_touched == 0
    assert HostileCost.touched == 0
    assert HostileParent.touched == 0


def test_stage1592_event_bus_preserves_exact_dict_payload_and_rejects_hostile_keys_without_text_hooks() -> None:
    _reset()
    bus = EventBus()

    event = bus.emit("runtime", "unit", {HostileKey(): HostileValue(), "stable": ["a"]})
    row = event.as_dict()

    assert row["payload"]["stable"] == ["a"]
    assert any(key.startswith("causal_text_unavailable:") for key in row["payload"])
    assert HostileKey.touched == 0
    assert HostileValue.touched == 0
