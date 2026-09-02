from __future__ import annotations

from Virus_Scan.scheduler.execution.raw_stage_input import build_raw_stage_input


class HostileChunkBytes:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("must not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("must not repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("must not format")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("must not bool")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("must not int")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("must not iter")


class RaisingChunkDeps:
    def raw_chunk_bytes(self):
        raise RuntimeError("chunk configuration unavailable")


class HostileChunkDeps:
    def __init__(self, value):
        self._value = value

    def raw_chunk_bytes(self):
        return self._value


class ExactChunkDeps:
    def raw_chunk_bytes(self):
        return 4096


def test_stage1811_raw_stage_input_records_chunk_bytes_exception_evidence() -> None:
    result = build_raw_stage_input({"file": "sample.bin", "collector": "identity"}, RaisingChunkDeps())

    assert result.size == 0
    assert result.boundary_failed is True
    evidence = result.out["raw_stage_boundary_evidence"]["raw_chunk_bytes_unavailable"]
    assert evidence["raw_stage_input_rejection_reason"] == "raw_stage_chunk_bytes_unavailable"
    assert evidence["exception_type"] == "RuntimeError"
    assert evidence["field_name"] == "raw_stage_chunk_bytes"


def test_stage1811_raw_stage_input_rejects_hostile_chunk_bytes_without_hooks() -> None:
    HostileChunkBytes.reset()
    hostile = HostileChunkBytes()

    result = build_raw_stage_input({"file": "sample.bin", "collector": "identity"}, HostileChunkDeps(hostile))

    assert HostileChunkBytes.touched == 0
    assert result.size == 0
    assert result.boundary_failed is True
    evidence = result.out["raw_stage_boundary_evidence"]["raw_chunk_bytes_unavailable"]
    assert evidence["raw_stage_input_rejection_reason"] == "raw_stage_chunk_bytes_rejected"
    assert evidence["field_name"] == "raw_stage_chunk_bytes"


def test_stage1811_raw_stage_input_preserves_exact_chunk_bytes() -> None:
    result = build_raw_stage_input({"file": "sample.bin", "collector": "identity"}, ExactChunkDeps())

    assert result.size == 4096
    assert result.safe_job["size"] == 4096
    assert result.boundary_failed is False
    assert "raw_stage_boundary_evidence" not in result.out
