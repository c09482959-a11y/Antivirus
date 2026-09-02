from __future__ import annotations

from Virus_Scan.scheduler.execution.raw_work_executor import (
    envelope_from_raw_result,
    execute_raw_callable,
    normalize_raw_collector_value,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileMappingLike:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get")

    def as_dict(self):
        type(self).touched += 1
        raise RuntimeError("do not as_dict")


class HostilePath:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify path")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr path")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate tags")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify tags")


def _reset_hostiles() -> None:
    HostileText.touched = 0
    HostileMappingLike.touched = 0
    HostilePath.touched = 0
    HostileIterable.touched = 0


def test_stage1614_execute_raw_callable_rejects_hostile_path_and_exception_args_without_hooks() -> None:
    _reset_hostiles()
    path = HostilePath()
    stage = HostileText()
    err_arg = HostileText()

    def boom():
        raise RuntimeError(err_arg)

    env = execute_raw_callable(path, stage, boom)
    materialized = materialize_scheduler_mapping(env.result)

    assert env.ok is False
    assert HostilePath.touched == 0
    assert HostileText.touched == 0
    assert materialized["raw_execution_failed"] is True
    assert materialized["raw_execution_context"]["file_path_unavailable"]["unsupported_scheduler_value"] is True
    assert materialized["raw_execution_context"]["stage_unavailable"]["unsupported_scheduler_value"] is True
    assert "do not" not in env.error


def test_stage1614_envelope_from_raw_result_rejects_mapping_like_job_and_result_without_hooks() -> None:
    _reset_hostiles()
    job = HostileMappingLike()
    result = HostileMappingLike()

    env = envelope_from_raw_result(job, result)  # type: ignore[arg-type]
    materialized = materialize_scheduler_mapping(env.result)

    assert env.ok is False
    assert HostileMappingLike.touched == 0
    assert materialized["unsupported_scheduler_value"] is True
    assert materialized["raw_execution_boundary_evidence"]["job_unavailable"]["unsupported_scheduler_value"] is True
    assert "raw result mapping rejected" in env.error


def test_stage1614_envelope_from_raw_result_rejects_hostile_error_field_without_stringifying() -> None:
    _reset_hostiles()
    job = {"file": "sample.bin", "collector": "raw_stage", "attempt": 1, "seq": 2}
    result = {"error": HostileText(), "tags": ["scanner_failure"]}

    env = envelope_from_raw_result(job, result)
    materialized = materialize_scheduler_mapping(env.result)

    assert env.ok is False
    assert HostileText.touched == 0
    assert env.file == "sample.bin"
    assert env.collector == "raw_stage"
    assert materialized["raw_execution_boundary_evidence"]["error_unavailable"]["unsupported_scheduler_value"] is True


def test_stage1614_normalize_raw_collector_value_rejects_hostile_iterable_without_hooks() -> None:
    _reset_hostiles()
    hostile = HostileIterable()

    normalized = normalize_raw_collector_value(hostile)

    assert HostileIterable.touched == 0
    assert normalized["tags"] == []
    assert normalized["meta"]["raw_collector_value_unavailable"]["unsupported_scheduler_value"] is True


def test_stage1614_normalize_raw_collector_tuple_preserves_valid_tags_and_rejects_aux() -> None:
    _reset_hostiles()
    hostile_aux = HostileText()

    normalized = normalize_raw_collector_value((["alpha", "beta"], hostile_aux))

    assert HostileText.touched == 0
    assert normalized["tags"] == ["alpha", "beta"]
    assert normalized["meta"]["raw_collector_aux_unavailable"]["unsupported_scheduler_value"] is True
