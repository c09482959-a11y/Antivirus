from __future__ import annotations

from unittest.mock import patch

from Virus_Scan.models.markov import feature_support as markov_feature_support
from Virus_Scan.models.markov import features as markov_features


class HostileValuesMapping:
    touched = 0

    def __getattribute__(self, name):  # pragma: no cover - failure proves hook execution
        if name == "values":
            type(self).touched += 1
            raise RuntimeError("caller-owned values attribute must not be inspected")
        return object.__getattribute__(self, name)

    def __iter__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("caller-owned iterator must not execute")


class HostileValuesMethod:
    touched = 0

    def values(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("caller-owned values method must not execute")


class HostileDictSubclass(dict):
    touched = 0

    def values(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("caller-owned dict-subclass values must not execute")



def test_stage1677_markov_mapping_total_rejects_values_attribute_without_hook() -> None:
    HostileValuesMapping.touched = 0

    total, reason = markov_feature_support.markov_mapping_total(HostileValuesMapping())

    assert total == 0
    assert reason == "non_mapping_markov_baseline"
    assert HostileValuesMapping.touched == 0



def test_stage1677_markov_mapping_total_rejects_values_method_without_hook() -> None:
    HostileValuesMethod.touched = 0

    total, reason = markov_feature_support.markov_mapping_total(HostileValuesMethod())

    assert total == 0
    assert reason == "non_mapping_markov_baseline"
    assert HostileValuesMethod.touched == 0



def test_stage1677_markov_mapping_total_rejects_dict_subclass_values_without_hook() -> None:
    HostileDictSubclass.touched = 0

    total, reason = markov_feature_support.markov_mapping_total(HostileDictSubclass({"decode": 3}))

    assert total == 0
    assert reason == "non_mapping_markov_baseline"
    assert HostileDictSubclass.touched == 0



def test_stage1677_compute_markov_features_records_invalid_baseline_without_values_hook() -> None:
    HostileValuesMethod.touched = 0

    with patch.object(
        markov_feature_support, "runtime_model_mapping_snapshot", lambda _name: HostileValuesMethod(),
    ):
        bundle = markov_features.compute_markov_features("static", ("decode", "exec"), "runtime")

    assert bundle["ready"] is False
    assert bundle["reason"] == "insufficient_markov_stage_support"
    assert bundle["support"] == 0
    assert HostileValuesMethod.touched == 0
