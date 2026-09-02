import json
from collections.abc import Mapping

from Virus_Scan.publication.model_evidence_projection.model_failure_sanitization import (
    sanitize_model_failure_records,
)
from Virus_Scan.publication.model_evidence_projection.safe_mapping import (
    json_value,
    mapping_readable,
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_keys,
)


class HostileMapping(Mapping):
    touched = 0

    def __getitem__(self, key):
        HostileMapping.touched += 1
        raise RuntimeError("do not getitem")

    def __iter__(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not len")

    def keys(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not keys")

    def get(self, key, default=None):
        HostileMapping.touched += 1
        raise RuntimeError("do not get")

    def items(self):
        HostileMapping.touched += 1
        raise RuntimeError("do not items")


class HostileList(list):
    touched = 0

    def __iter__(self):
        HostileList.touched += 1
        raise RuntimeError("do not iterate")


class HostileText:
    touched = 0

    def __str__(self):
        HostileText.touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        HostileText.touched += 1
        raise RuntimeError("do not repr")


def reset_hostiles():
    HostileMapping.touched = 0
    HostileList.touched = 0
    HostileText.touched = 0


def test_publication_safe_mapping_rejects_generic_mapping_without_mapping_hooks():
    reset_hostiles()

    keys, reason = safe_mapping_keys(HostileMapping())
    value = safe_mapping_get(HostileMapping(), "reason", replacement="missing")
    contains = safe_mapping_contains(HostileMapping(), "reason")
    readable = mapping_readable(HostileMapping())
    materialized = json_value(HostileMapping())

    assert HostileMapping.touched == 0
    assert keys == ()
    assert reason == "unreadable_model_evidence_mapping"
    assert value == "missing"
    assert contains is False
    assert readable is False
    assert materialized["unavailable_reason"] == "unreadable_model_evidence_mapping"
    assert json.dumps(materialized, sort_keys=True)


def test_publication_json_value_rejects_hostile_list_subclass_without_iterating():
    reset_hostiles()

    materialized = json_value(HostileList(["safe"]))

    assert HostileList.touched == 0
    assert materialized["unavailable_reason"] == "unsupported_model_evidence_text"
    assert materialized["value_type"] == "HostileList"
    assert json.dumps(materialized, sort_keys=True)


def test_model_failure_sanitization_rejects_hostile_list_subclass_without_iterating():
    reset_hostiles()

    records, unavailable, failures = sanitize_model_failure_records("model_failures", HostileList([{"reason": "x"}]))

    assert HostileList.touched == 0
    assert records == ()
    assert unavailable == {"model_failures": "non_mapping_model_failure_record"}
    assert failures[0]["reason"] == "non_mapping_model_failure_record"
    assert json.dumps(failures, sort_keys=True)


def test_publication_safe_mapping_preserves_dict_subclass_with_builtin_descriptors():
    class HostileDict(dict):
        touched = 0

        def keys(self):
            HostileDict.touched += 1
            raise RuntimeError("do not keys")

        def items(self):
            HostileDict.touched += 1
            raise RuntimeError("do not items")

        def get(self, key, default=None):
            HostileDict.touched += 1
            raise RuntimeError("do not get")

    data = HostileDict({"reason": "degraded", "metadata": {"kind": "safe"}})

    keys, reason = safe_mapping_keys(data)
    value = safe_mapping_get(data, "reason")
    materialized = json_value(data)

    assert HostileDict.touched == 0
    assert reason == ""
    assert keys == ("metadata", "reason")
    assert value == "degraded"
    assert materialized["reason"] == "degraded"
    assert materialized["metadata"]["kind"] == "safe"
    assert json.dumps(materialized, sort_keys=True)
