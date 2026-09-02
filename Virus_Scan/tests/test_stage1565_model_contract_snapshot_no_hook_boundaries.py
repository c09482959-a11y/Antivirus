"""Stage 1565: model contract snapshot/evidence deep-freeze boundaries do not invoke hostile mapping hooks."""

from __future__ import annotations

import json
from collections.abc import Mapping

from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_snapshot import (
    make_model_snapshot,
    make_replay_model_comparison_record,
    materialize_model_snapshot,
    materialize_replay_model_comparison_record,
)


class HostileHooks:
    calls: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.calls = []

    @classmethod
    def record(cls, name: str) -> None:
        cls.calls.append(name)
        raise AssertionError(f"hostile hook invoked: {name}")


class HostileMapping(Mapping):
    def __iter__(self):
        HostileHooks.record("__iter__")

    def __len__(self):
        HostileHooks.record("__len__")

    def __getitem__(self, key):
        HostileHooks.record("__getitem__")

    def keys(self):
        HostileHooks.record("keys")

    def items(self):
        HostileHooks.record("items")

    def values(self):
        HostileHooks.record("values")

    def get(self, key, default=None):
        HostileHooks.record("get")


class HostileScalar:
    def __str__(self):
        HostileHooks.record("__str__")

    def __repr__(self):
        HostileHooks.record("__repr__")

    def __format__(self, spec):
        HostileHooks.record("__format__")

    def __bool__(self):
        HostileHooks.record("__bool__")

    def __int__(self):
        HostileHooks.record("__int__")

    def __float__(self):
        HostileHooks.record("__float__")

    def __iter__(self):
        HostileHooks.record("scalar.__iter__")


class HostileIterable:
    def __iter__(self):
        HostileHooks.record("iterable.__iter__")


class HostileMeta(type):
    def __getattribute__(cls, name):
        if name in {"__name__", "__qualname__", "__module__"}:
            HostileHooks.record(f"metaclass.{name}")
        return type.__getattribute__(cls, name)


class HostileMetaclassObject(metaclass=HostileMeta):
    pass


def _json_safe(value: object) -> None:
    json.dumps(value, sort_keys=True, allow_nan=False)


def test_stage1565_model_evidence_rejects_unknown_mapping_without_hooks() -> None:
    HostileHooks.reset()
    materialized = materialize_model_evidence_record(
        make_model_evidence_record(
            HostileMapping(),
            model_name="graph",
            evidence_type="graph_evidence",
            model_version="v1",
        )
    )

    assert materialized["values_unavailable_reason"] == "unreadable_model_evidence_mapping"
    assert materialized["values_type"] == "HostileMapping"
    assert HostileHooks.calls == []
    _json_safe(materialized)


def test_stage1565_model_snapshot_and_replay_reject_unknown_mapping_without_hooks() -> None:
    HostileHooks.reset()
    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            HostileMapping(),
            model_name="profiles",
            snapshot_type="profile_snapshot",
            model_version="v1",
            failures=HostileIterable(),
        )
    )
    comparison = materialize_replay_model_comparison_record(
        make_replay_model_comparison_record(
            model_name="markov",
            expected=HostileMapping(),
            actual=HostileMapping(),
            matched=True,
            mismatch_fields=HostileIterable(),
        )
    )

    assert snapshot["values_unavailable_reason"] == "unreadable_model_snapshot_mapping"
    assert snapshot["failures_unavailable_reason"] == "unreadable_model_snapshot_failures"
    assert comparison["expected_unavailable_reason"] == "unreadable_model_snapshot_mapping"
    assert comparison["actual_unavailable_reason"] == "unreadable_model_snapshot_mapping"
    assert comparison["mismatch_fields_unavailable_reason"] == "unreadable_replay_mismatch_fields"
    assert HostileHooks.calls == []
    _json_safe(snapshot)
    _json_safe(comparison)


def test_stage1565_model_failure_rejects_unknown_mapping_and_iterable_without_hooks() -> None:
    HostileHooks.reset()
    failure = materialize_model_failure_record(
        make_model_failure_record(
            model_name="temporal",
            failure_type="temporal_failure",
            reason="bad_input",
            affected_fields=HostileIterable(),
            details=HostileMapping(),
        )
    )
    direct = materialize_model_failure_record(HostileMapping())

    assert failure["details"]["unavailable_reason"] == "unreadable_model_failure_mapping"
    assert failure["affected_fields"] == ()
    assert failure["affected_fields_unavailable_reason"] == "unreadable_model_failure_iterable"
    assert direct["unavailable_reason"] == "unreadable_model_failure_mapping"
    assert HostileHooks.calls == []
    _json_safe(failure)
    _json_safe(direct)


def test_stage1565_exact_dict_with_hostile_scalar_is_frozen_without_hooks() -> None:
    HostileHooks.reset()
    hostile = HostileScalar()
    hostile_meta = HostileMetaclassObject()
    values = {hostile: hostile, "nested": {"payload": hostile_meta}}

    evidence = materialize_model_evidence_record(
        make_model_evidence_record(
            values,
            model_name=hostile,
            evidence_type=hostile,
            model_version=hostile,
        )
    )
    snapshot = materialize_model_snapshot(
        make_model_snapshot(
            values,
            model_name=hostile,
            snapshot_type=hostile,
            model_version=hostile,
            ready=hostile,
            degraded=hostile,
            reason=hostile,
        )
    )

    assert evidence["<HostileScalar>"]["unavailable_reason"] == "unsupported_model_evidence_value"
    assert evidence["nested"]["payload"]["unavailable_reason"] == "unsupported_model_evidence_value"
    assert snapshot["values"]["<HostileScalar>"]["unavailable_reason"] == "unsupported_model_snapshot_value"
    assert snapshot["values"]["nested"]["payload"]["unavailable_reason"] == "unsupported_model_snapshot_value"
    assert HostileHooks.calls == []
    _json_safe(evidence)
    _json_safe(snapshot)
