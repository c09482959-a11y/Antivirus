from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.execution.raw_work_executor import envelope_from_raw_result
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


class HostileKey:
    touched = 0

    def __hash__(self) -> int:
        return 17

    def __eq__(self, other: object) -> bool:
        type(self).touched += 1
        raise AssertionError("key equality hook executed")

    def __str__(self) -> str:
        type(self).touched += 1
        raise AssertionError("key string hook executed")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise AssertionError("key repr hook executed")


def test_stage2138_raw_work_executor_source_uses_typed_boundary_contracts() -> None:
    source_path = Path(__file__).parents[1] / "scheduler" / "execution" / "raw_work_executor.py"
    source = source_path.read_text(encoding="utf-8")

    assert "Any" not in source
    assert "Callable[...," not in source
    assert "def _raw_execution_text" not in source
    assert "def _raw_job_mapping" not in source
    assert "def _raw_mapping_value" not in source
    assert "def _raw_attempt" not in source


def test_stage2138_raw_mapping_lookup_rejects_hostile_keys_without_hooks() -> None:
    HostileKey.touched = 0
    hostile_key = HostileKey()
    job = {
        hostile_key: "should not compare",
        "file": "sample.bin",
        "collector": "raw_stage",
        "attempt": 1,
        "seq": 2,
    }
    result = {hostile_key: "not serialized", "tags": ["scanner_failure"]}

    envelope = envelope_from_raw_result(job, result)
    materialized = materialize_scheduler_mapping(envelope.result)

    assert HostileKey.touched == 0
    assert envelope.file == "sample.bin"
    assert envelope.collector == "raw_stage"
    assert envelope.attempt == 1
    assert envelope.seq == 2
    assert hostile_key not in materialized
    assert materialized["tags"] == ["scanner_failure"]
