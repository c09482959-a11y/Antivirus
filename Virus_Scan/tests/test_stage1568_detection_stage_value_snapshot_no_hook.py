"""Stage1568 Phase 2 detection stage-value snapshot no-hook hardening."""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.detection.models.stage_value_utils import (
    detection_unavailable_value,
    freeze_detection_value,
    frozen_tuple,
    thaw_detection_value,
)


class HostileMapping(Mapping):
    def __init__(self) -> None:
        self.keys_calls = 0
        self.items_calls = 0
        self.iter_calls = 0
        self.getitem_calls = 0
        self.values_calls = 0

    def __iter__(self):  # pragma: no cover - failure proves caller-owned iteration was used
        self.iter_calls += 1
        raise AssertionError("caller-owned mapping __iter__ was invoked")

    def __len__(self) -> int:
        return 1

    def __getitem__(self, key):  # pragma: no cover - failure proves caller-owned lookup was used
        self.getitem_calls += 1
        raise AssertionError("caller-owned mapping __getitem__ was invoked")

    def keys(self):  # pragma: no cover - failure proves caller-owned keys was used
        self.keys_calls += 1
        raise AssertionError("caller-owned mapping keys was invoked")

    def items(self):  # pragma: no cover - failure proves caller-owned items was used
        self.items_calls += 1
        raise AssertionError("caller-owned mapping items was invoked")

    def values(self):  # pragma: no cover - failure proves caller-owned values was used
        self.values_calls += 1
        raise AssertionError("caller-owned mapping values was invoked")


class HostileIterable:
    def __init__(self) -> None:
        self.iter_calls = 0

    def __iter__(self):  # pragma: no cover - failure proves unknown iterables were traversed
        self.iter_calls += 1
        raise AssertionError("caller-owned iterable __iter__ was invoked")


class HostileScalar:
    def __init__(self) -> None:
        self.repr_calls = 0
        self.str_calls = 0
        self.float_calls = 0

    def __repr__(self):  # pragma: no cover - failure proves raw repr was used
        self.repr_calls += 1
        raise AssertionError("caller-owned __repr__ was invoked")

    def __str__(self):  # pragma: no cover - failure proves raw str was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def __float__(self):  # pragma: no cover - failure proves raw float was used
        self.float_calls += 1
        raise AssertionError("caller-owned __float__ was invoked")


class HostileTypeMeta(type):
    type_name_reads = 0

    def __getattribute__(cls, name):  # pragma: no cover - failure proves metaclass hook was used
        if name == "__name__":
            cls.type_name_reads += 1
            raise AssertionError("caller-owned metaclass __name__ lookup was invoked")
        return super().__getattribute__(name)


class HostileTypeName(metaclass=HostileTypeMeta):
    pass


def test_stage1568_detection_freezer_rejects_unknown_mapping_without_hooks() -> None:
    mapping = HostileMapping()

    frozen = freeze_detection_value(mapping)
    thawed = thaw_detection_value(frozen)

    assert thawed["degraded"] is True
    assert thawed["unavailable_reason"] == "detection_mapping_keys_unavailable"
    assert thawed["final_json_must_record"] is True
    assert thawed["replay_record_required"] is True
    assert mapping.keys_calls == 0
    assert mapping.items_calls == 0
    assert mapping.values_calls == 0
    assert mapping.iter_calls == 0
    assert mapping.getitem_calls == 0


def test_stage1568_detection_freezer_rejects_unknown_iterable_and_scalar_without_hooks() -> None:
    iterable = HostileIterable()
    scalar = HostileScalar()

    frozen_iterable = frozen_tuple(iterable)
    frozen_scalar = freeze_detection_value(scalar)
    thawed_scalar = thaw_detection_value(frozen_scalar)

    assert thaw_detection_value(frozen_iterable[0])["unavailable_reason"] == "detection_iterable_unavailable"
    assert thawed_scalar["unavailable_reason"] == "detection_scalar_unavailable"
    assert iterable.iter_calls == 0
    assert scalar.repr_calls == 0
    assert scalar.str_calls == 0
    assert scalar.float_calls == 0


def test_stage1568_detection_unavailable_evidence_uses_no_hook_type_name() -> None:
    value = HostileTypeName()

    evidence = detection_unavailable_value("bad", value)
    thawed = thaw_detection_value(evidence)

    assert thawed["value_type"] == "HostileTypeName"
    assert HostileTypeMeta.type_name_reads == 0
