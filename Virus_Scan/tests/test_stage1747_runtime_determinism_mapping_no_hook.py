from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType

import pytest

from Virus_Scan.runtime.determinism import (
    canonicalize_evidence_record,
    canonicalize_result_mapping,
    deterministic_json_dumps,
    make_governance_snapshot,
    snapshot_runtime_state,
    stable_evidence_order,
    validate_deterministic_result_records,
)


class HostileMapping(Mapping):
    touched: dict[str, int] = {
        "items": 0,
        "keys": 0,
        "values": 0,
        "get": 0,
        "iter": 0,
        "len": 0,
        "getitem": 0,
        "str": 0,
        "repr": 0,
    }

    @classmethod
    def reset(cls) -> None:
        for key in cls.touched:
            cls.touched[key] = 0

    def __getitem__(self, key: object) -> object:
        type(self).touched["getitem"] += 1
        raise RuntimeError("getitem must not execute")

    def __iter__(self):
        type(self).touched["iter"] += 1
        raise RuntimeError("iter must not execute")

    def __len__(self) -> int:
        type(self).touched["len"] += 1
        raise RuntimeError("len must not execute")

    def items(self):
        type(self).touched["items"] += 1
        raise RuntimeError("items must not execute")

    def keys(self):
        type(self).touched["keys"] += 1
        raise RuntimeError("keys must not execute")

    def values(self):
        type(self).touched["values"] += 1
        raise RuntimeError("values must not execute")

    def get(self, key: object, default: object = None) -> object:
        type(self).touched["get"] += 1
        raise RuntimeError("get must not execute")

    def __str__(self) -> str:
        type(self).touched["str"] += 1
        raise RuntimeError("str must not execute")

    def __repr__(self) -> str:
        type(self).touched["repr"] += 1
        raise RuntimeError("repr must not execute")


def _hostile_proxy() -> MappingProxyType:
    return MappingProxyType(HostileMapping())


def _assert_no_hooks() -> None:
    assert HostileMapping.touched == {key: 0 for key in HostileMapping.touched}


def test_stage1747_runtime_determinism_rejects_hostile_mappingproxy_without_hooks() -> None:
    HostileMapping.reset()
    result = canonicalize_evidence_record(_hostile_proxy())
    _assert_no_hooks()
    assert result["unavailable_reason"] == "non_materializable_runtime_determinism_value"
    assert result["value_type"] == "mappingproxy"

    HostileMapping.reset()
    ordered = stable_evidence_order([{"tag": "ok"}, _hostile_proxy()])
    _assert_no_hooks()
    assert len(ordered) == 2
    assert any(type(item) is dict and dict.get(item, "tag") == "ok" for item in ordered)
    assert any(type(item) is type(_hostile_proxy()) for item in ordered)


def test_stage1747_runtime_result_mapping_rejects_hostile_mappingproxy_without_hooks() -> None:
    HostileMapping.reset()
    result = canonicalize_result_mapping(_hostile_proxy())
    _assert_no_hooks()
    assert result["runtime_result_mapping_unavailable"]["unavailable_reason"] == "non_materializable_runtime_result_mapping"

    HostileMapping.reset()
    with pytest.raises(TypeError, match="result records must be a mapping"):
        validate_deterministic_result_records(_hostile_proxy())
    _assert_no_hooks()


def test_stage1747_runtime_snapshot_and_json_dump_reject_hostile_mappingproxy_without_hooks() -> None:
    HostileMapping.reset()
    snapshot = snapshot_runtime_state(queue_state=_hostile_proxy())
    payload = snapshot.as_stable_payload()
    _assert_no_hooks()
    assert payload["queue_state"]["unavailable_reason"] == "non_materializable_runtime_determinism_value"

    HostileMapping.reset()
    governance = make_governance_snapshot(queue_state=_hostile_proxy())
    _assert_no_hooks()
    assert governance.as_stable_payload()["queue_state"]["unavailable_reason"] == "non_materializable_runtime_determinism_value"

    HostileMapping.reset()
    dumped = deterministic_json_dumps({"unsafe": _hostile_proxy()})
    _assert_no_hooks()
    assert json.loads(dumped)["unsafe"]["unavailable_reason"] == "non_materializable_runtime_determinism_value"


def test_stage1747_runtime_determinism_accepts_exact_dict_backed_mappingproxy() -> None:
    backed = MappingProxyType({
        "b/File.bin": {"verdict": "Low", "tags": ["z", "a"], "pid": 100},
        "A/file.bin": {"verdict": "Clean", "tags": ["b"]},
    })

    canonical = canonicalize_result_mapping(backed)

    assert tuple(canonical) == ("A/file.bin", "b/File.bin")
    assert canonical["b/File.bin"] == {"tags": ["a", "z"], "verdict": "Low"}
    assert validate_deterministic_result_records(backed) == ("A/file.bin", "b/File.bin")
