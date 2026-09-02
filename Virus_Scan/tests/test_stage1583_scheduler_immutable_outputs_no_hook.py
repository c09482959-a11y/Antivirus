from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple, immutable_value, materialize_scheduler_mapping


class HostileSchedulerMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate scheduler mapping")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not measure scheduler mapping")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not index scheduler mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call mapping items")


class HostileSchedulerIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate scheduler iterable")


class HostileSchedulerKey:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify scheduler key")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr scheduler key")


def test_immutable_mapping_rejects_hostile_mapping_without_mapping_hooks() -> None:
    HostileSchedulerMapping.touched = 0

    frozen = immutable_mapping(HostileSchedulerMapping())
    materialized = materialize_scheduler_mapping(frozen)

    assert HostileSchedulerMapping.touched == 0
    assert materialized["scheduler_mapping_unavailable"] is True
    assert materialized["reason"] == "non_materializable_scheduler_mapping"
    assert materialized["evidence"]["unsupported_scheduler_value"] is True
    assert materialized["evidence"]["final_json_must_record"] is True


def test_immutable_tuple_rejects_hostile_iterable_without_iteration() -> None:
    HostileSchedulerIterable.touched = 0

    frozen = immutable_tuple(HostileSchedulerIterable())
    materialized = materialize_scheduler_mapping(frozen)

    assert HostileSchedulerIterable.touched == 0
    assert len(materialized) == 1
    assert materialized[0]["unsupported_scheduler_value"] is True
    assert materialized[0]["field_name"] == "scheduler_tuple"


def test_immutable_mapping_rejects_hostile_key_without_stringification() -> None:
    HostileSchedulerKey.touched = 0

    frozen = immutable_mapping({HostileSchedulerKey(): "value"})
    materialized = materialize_scheduler_mapping(frozen)

    assert HostileSchedulerKey.touched == 0
    assert "unsupported_scheduler_key_0" in materialized
    assert materialized["unsupported_scheduler_key_0"]["unsupported_scheduler_value"] is True
    assert materialized["unsupported_scheduler_key_0"]["field_name"] == "unsupported_scheduler_key_0"
