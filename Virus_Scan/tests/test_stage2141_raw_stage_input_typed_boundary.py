"""Stage2141 raw-stage input typed boundary regression coverage."""
from __future__ import annotations

import inspect

from Virus_Scan.scheduler.execution import raw_stage_input, raw_stage_input_support
from Virus_Scan.scheduler.execution.raw_stage_input import build_raw_stage_input, normalise_raw_stage_out_tags


class RawInputDeps:
    def raw_chunk_bytes(self) -> int:
        return 512

    def normalize_raw_collector_value(self, value: object) -> dict[str, object]:
        return {"tags": ["tuple-tag"], "meta": {"source": "tuple"}}


class HostileKey:
    touched = 0
    __hash__ = object.__hash__

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __eq__(self, other: object) -> bool:
        type(self).touched += 1
        raise RuntimeError("raw-stage lookup must not call key equality")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("raw-stage lookup must not stringify keys")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("raw-stage lookup must not repr keys")


class HostileScalar:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("raw-stage scalar must not stringify")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("raw-stage scalar must not repr")

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("raw-stage scalar must not bool")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("raw-stage scalar must not iterate")


def test_stage2141_raw_stage_input_rejects_hostile_keys_without_equality_hooks() -> None:
    HostileKey.reset()
    result = build_raw_stage_input({HostileKey(): "ignored", "file": "sample.bin", "collector": "identity"}, RawInputDeps())

    assert HostileKey.touched == 0
    assert result.safe_job["file"] == "sample.bin"
    assert result.safe_job["collector"] == "identity"
    assert result.boundary_failed is False


def test_stage2141_raw_stage_input_records_replayable_seq_rejection_without_hooks() -> None:
    HostileScalar.reset()
    hostile = HostileScalar()

    result = build_raw_stage_input({"file": "sample.bin", "collector": "identity", "seq": hostile}, RawInputDeps())

    assert HostileScalar.touched == 0
    assert result.safe_job["seq"] is None
    assert result.boundary_failed is True
    evidence = result.out["raw_stage_boundary_evidence"]
    assert evidence["seq_unavailable"]["raw_stage_input_rejection_reason"] == "raw_stage_seq_rejected"


def test_stage2141_raw_stage_tag_normalization_uses_typed_domain_adapter() -> None:
    out: dict[str, object] = {"tags": ("tuple-tag",)}

    normalise_raw_stage_out_tags(out, RawInputDeps())

    assert out["tags"] == ["tuple-tag"]
    assert out["meta"] == {"source": "tuple"}


def test_stage2141_raw_stage_input_modules_have_no_local_any_surface() -> None:
    assert "Any" not in inspect.getsource(raw_stage_input)
    assert "Any" not in inspect.getsource(raw_stage_input_support)
