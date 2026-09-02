import pytest

from Virus_Scan.contracts.temporal_baseline import (
    empty_temporal_baselines,
    new_temporal_baseline_record,
    temporal_baseline_record_key,
    validate_temporal_baselines,
)
from Virus_Scan.models.clustering.vector_baseline import online_vector_update


class HostileModelCount:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __float__")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __int__")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")


def _temporal_store_with_count(count: object) -> dict[str, object]:
    identity = {
        "level": "exact",
        "engine": "renpy",
        "extension": ".rpy",
        "previous_stage": "asset",
        "current_stage": "runtime",
        "source_behavior": "download",
        "target_behavior": "execute",
    }
    key = temporal_baseline_record_key(**identity)
    record = new_temporal_baseline_record(**identity)
    record.update({
        "count": count,
        "mean": 2.0,
        "m2": 0.0,
        "minimum": 2.0,
        "maximum": 2.0,
        "histogram_counts": [0, 0, 0, 0, 2, 0, 0, 0, 0, 0],
        "last_update_ordinal": 2,
    })
    store = empty_temporal_baselines()
    store["records"][key] = record
    return store


def test_stage1663_temporal_count_rejects_nonintegral_values_without_truncation() -> None:
    validated = validate_temporal_baselines(_temporal_store_with_count(2))
    assert next(iter(validated["records"].values()))["count"] == 2

    for invalid in (2.0, 2.9, "3", "3.7"):
        with pytest.raises(ValueError, match="temporal baseline count invalid"):
            validate_temporal_baselines(_temporal_store_with_count(invalid))


def test_stage1663_vector_baseline_count_rejects_nonintegral_values_without_truncation() -> None:
    updated = online_vector_update({"count": 2.0, "mean": (1.0,), "m2": (0.0,)}, (3.0,))
    assert updated["count"] == 3

    truncated = online_vector_update({"count": 2.9, "mean": (1.0,), "m2": (0.0,)}, (3.0,))
    assert truncated["count"] == 1


def test_stage1663_vector_baseline_count_does_not_execute_hostile_numeric_hooks() -> None:
    HostileModelCount.touched = 0
    hostile = online_vector_update({"count": HostileModelCount(), "mean": (1.0,), "m2": (0.0,)}, (3.0,))
    assert HostileModelCount.touched == 0
    assert hostile["count"] == 1
