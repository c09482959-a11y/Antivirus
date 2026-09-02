from __future__ import annotations
from Virus_Scan.detection.models.failure_state import DetectionRecoverableFailureRequest
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.detection.models.failure_state import DetectionFailureState, failure_state_records


class HostileNameMeta(type):
    name_touches = 0

    def __getattribute__(cls, name):  # pragma: no cover - fails if production touches it
        if name == "__name__":
            HostileNameMeta.name_touches += 1
            raise RuntimeError("caller-owned metaclass __name__ executed")
        return super().__getattribute__(name)


class HostileException(Exception, metaclass=HostileNameMeta):
    pass


class HostileFailureValue(metaclass=HostileNameMeta):
    str_touches = 0
    repr_touches = 0
    format_touches = 0
    iter_touches = 0

    def __str__(self):  # pragma: no cover - fails if production touches it
        type(self).str_touches += 1
        raise RuntimeError("caller-owned __str__ executed")

    def __repr__(self):  # pragma: no cover - fails if production touches it
        type(self).repr_touches += 1
        raise RuntimeError("caller-owned __repr__ executed")

    def __format__(self, spec):  # pragma: no cover - fails if production touches it
        type(self).format_touches += 1
        raise RuntimeError("caller-owned __format__ executed")

    def __iter__(self):  # pragma: no cover - fails if production touches it
        type(self).iter_touches += 1
        raise RuntimeError("caller-owned __iter__ executed")


class HostileFailureInt(int, metaclass=HostileNameMeta):
    eq_touches = 0

    def __eq__(self, other):  # pragma: no cover - fails if production touches it
        type(self).eq_touches += 1
        raise RuntimeError("caller-owned __eq__ executed")


class HostileMappingLike(metaclass=HostileNameMeta):
    iter_touches = 0
    str_touches = 0
    repr_touches = 0

    def __iter__(self):  # pragma: no cover - fails if production touches it
        type(self).iter_touches += 1
        raise RuntimeError("caller-owned mapping iterator executed")

    def __str__(self):  # pragma: no cover - fails if production touches it
        type(self).str_touches += 1
        raise RuntimeError("caller-owned mapping str executed")

    def __repr__(self):  # pragma: no cover - fails if production touches it
        type(self).repr_touches += 1
        raise RuntimeError("caller-owned mapping repr executed")


def _reset() -> None:
    HostileNameMeta.name_touches = 0
    HostileFailureValue.str_touches = 0
    HostileFailureValue.repr_touches = 0
    HostileFailureValue.format_touches = 0
    HostileFailureValue.iter_touches = 0
    HostileFailureInt.eq_touches = 0
    HostileMappingLike.iter_touches = 0
    HostileMappingLike.str_touches = 0
    HostileMappingLike.repr_touches = 0


def test_stage1768_detection_failure_exception_category_uses_no_hook_type_name() -> None:
    _reset()

    record = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name="stage-x",
        error=HostileException(),
        error_source="detection",
        affected_context="ctx",
    )).to_record()
    fatal_record = DetectionFailureState.fatal_failure(
        stage_name="stage-y",
        error=HostileException(),
        error_source="detection",
        affected_context="ctx",
    ).to_record()

    assert record["error_category"] == "HostileException"
    assert fatal_record["error_category"] == "HostileException"
    assert record["message"] == "HostileException"
    assert fatal_record["message"] == "HostileException"
    assert HostileNameMeta.name_touches == 0


def test_stage1768_detection_failure_dict_keys_use_no_hook_type_name_fallback() -> None:
    _reset()
    hostile_key = HostileFailureValue()
    hostile_value = HostileFailureValue()

    records = failure_state_records(({hostile_key: {hostile_value: hostile_value}},))

    assert records == ({"<HostileFailureValue>": {"<HostileFailureValue>": "<HostileFailureValue>"}},)
    assert HostileNameMeta.name_touches == 0
    assert HostileFailureValue.str_touches == 0
    assert HostileFailureValue.repr_touches == 0
    assert HostileFailureValue.format_touches == 0
    assert HostileFailureValue.iter_touches == 0


def test_stage1768_detection_failure_bool_flags_reject_int_subclass_without_eq_hook() -> None:
    _reset()
    hostile_flag = HostileFailureInt(1)

    record = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name="stage-x",
        error="boom",
        error_source="detection",
        confidence_degraded=hostile_flag,
        json_record_required=hostile_flag,
        replay_record_required=hostile_flag,
    )).to_record()

    assert record["confidence_degraded"] is True
    assert record["json_record_required"] is True
    assert record["replay_record_required"] is True
    assert HostileFailureInt.eq_touches == 0
    assert HostileNameMeta.name_touches == 0


def test_stage1768_detection_failure_unknown_iterable_rejected_without_hooks() -> None:
    _reset()
    hostile = HostileMappingLike()

    records = failure_state_records(hostile)

    assert records[0]["unavailable_reason"] == "detection_failure_iterable_unavailable"
    assert records[0]["affected_context"] == "HostileMappingLike"
    assert HostileNameMeta.name_touches == 0
    assert HostileMappingLike.iter_touches == 0
    assert HostileMappingLike.str_touches == 0
    assert HostileMappingLike.repr_touches == 0


def test_stage1768_detection_failure_state_source_blocks_raw_type_name_and_repr() -> None:
    source = read_python_file(Path("Virus_Scan/detection/models/failure_state.py"))

    assert "type(value).__name__" not in source
    assert "type(error).__name__" not in source
    assert "type(raw_key).__name__" not in source
    assert "repr(value)" not in source
    assert "no_hook_type_name" in source
