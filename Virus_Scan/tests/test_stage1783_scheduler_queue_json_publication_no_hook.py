"""Stage1783 scheduler queue JSON publication no-hook regressions."""
from __future__ import annotations

from Virus_Scan.scheduler.runtime.queue_json_publication import (
    queue_write_claim_meta,
    queue_write_json_replace,
    queue_write_quarantine_sidecar,
    read_json_file,
)


class HostileValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    fspath_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.fspath_calls = 0

    @classmethod
    def counters(cls) -> dict[str, int]:
        return {
            "str": cls.str_calls,
            "repr": cls.repr_calls,
            "format": cls.format_calls,
            "bool": cls.bool_calls,
            "iter": cls.iter_calls,
            "float": cls.float_calls,
            "int": cls.int_calls,
            "fspath": cls.fspath_calls,
        }

    def __str__(self):  # pragma: no cover - execution is failure
        type(self).str_calls += 1
        raise AssertionError("hostile __str__ executed")

    def __repr__(self):  # pragma: no cover
        type(self).repr_calls += 1
        raise AssertionError("hostile __repr__ executed")

    def __format__(self, _spec):  # pragma: no cover
        type(self).format_calls += 1
        raise AssertionError("hostile __format__ executed")

    def __bool__(self):  # pragma: no cover
        type(self).bool_calls += 1
        raise AssertionError("hostile __bool__ executed")

    def __iter__(self):  # pragma: no cover
        type(self).iter_calls += 1
        raise AssertionError("hostile __iter__ executed")

    def __float__(self):  # pragma: no cover
        type(self).float_calls += 1
        raise AssertionError("hostile __float__ executed")

    def __int__(self):  # pragma: no cover
        type(self).int_calls += 1
        raise AssertionError("hostile __int__ executed")

    def __fspath__(self):  # pragma: no cover
        type(self).fspath_calls += 1
        raise AssertionError("hostile __fspath__ executed")


def assert_no_hostile_hooks() -> None:
    assert HostileValue.counters() == {
        "str": 0,
        "repr": 0,
        "format": 0,
        "bool": 0,
        "iter": 0,
        "float": 0,
        "int": 0,
        "fspath": 0,
    }


def test_stage1783_read_json_file_rejects_unsupported_path_without_hooks() -> None:
    HostileValue.reset()

    result = read_json_file(HostileValue(), default=None)

    assert_no_hostile_hooks()
    assert result["queue_json_read_failed"] is True
    assert result["queue_failure"] is True
    assert result["allow_learning"] is False
    assert result["path_unavailable_reason"] == "scheduler_path_rejected"


def test_stage1783_queue_write_json_replace_rejects_unsupported_boundary_values_without_hooks() -> None:
    HostileValue.reset()

    ok = queue_write_json_replace(
        HostileValue(),
        {"job_type": "unit", "file": "sample.bin"},
        tmp_suffix=HostileValue(),
        verify=HostileValue(),
        log_context=HostileValue(),
    )

    assert ok is False
    assert_no_hostile_hooks()


def test_stage1783_queue_write_claim_meta_does_not_truth_test_hostile_meta(tmp_path) -> None:
    HostileValue.reset()

    ok = queue_write_claim_meta(tmp_path / "claim.json", HostileValue())

    assert ok is True
    assert_no_hostile_hooks()


def test_stage1783_queue_write_quarantine_sidecar_rejects_unsupported_dest_without_hooks() -> None:
    HostileValue.reset()

    ok = queue_write_quarantine_sidecar(HostileValue(), {"status": "failed"})

    assert ok is False
    assert_no_hostile_hooks()


def test_stage1783_queue_json_exact_primitives_round_trip(tmp_path) -> None:
    target = tmp_path / "job.json"
    payload = {"job_type": "unit", "file": "sample.bin", "queue_identity": "stage1783"}

    assert queue_write_json_replace(target, payload, verify=True, log_context="stage1783") is True
    loaded = read_json_file(target, default={})

    assert loaded["job_type"] == "unit"
    assert loaded["file"] == "sample.bin"
    assert loaded["queue_identity"] == "stage1783"
    assert loaded["schema_version"] >= 1
