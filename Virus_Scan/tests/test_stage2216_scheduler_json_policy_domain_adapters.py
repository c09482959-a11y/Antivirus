from pathlib import Path

from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.scheduler.evidence import scheduler_json_durable_support as durable_support
from Virus_Scan.scheduler.evidence import scheduler_json_writer_support as writer_support
from Virus_Scan.scheduler.evidence.scheduler_json_writer import (
    build_scheduler_json_section,
    raw_chunk_bytes,
    raw_queue_max_chunks,
    raw_queue_min_bytes,
)


def test_stage2216_durable_context_helpers_are_scheduler_domain_adapters():
    base = "scheduler_json"
    expected = {
        "context_failed": "scheduler_json_failed",
        "context_tmp": "scheduler_json_tmp",
        "context_final": "scheduler_json_final",
        "context_tmp_cleanup": "scheduler_json_tmp_cleanup",
        "context_bad_final_cleanup": "scheduler_json_bad_final_cleanup",
        "context_durability_cleanup": "scheduler_json_durability_cleanup",
        "context_durability_tmp_cleanup": "scheduler_json_durability_tmp_cleanup",
        "context_failed_final_probe": "scheduler_json_failed_final_probe",
        "context_failed_final_cleanup": "scheduler_json_failed_final_cleanup",
        "context_durable_write_failed": "scheduler_json_durable_write_failed",
    }

    for name, value in expected.items():
        helper = getattr(durable_support, name)
        assert helper(base) == value
        assert name in durable_support.__all__

    assert durable_support.durable_path_text(Path("queue") / "item.json") == "queue/item.json"
    assert "durable_path_text" in durable_support.__all__


def test_stage2216_durable_writer_uses_context_domain_adapters_instead_of_inline_suffix_policy():
    durable_source = read_python_file(Path("Virus_Scan/scheduler/evidence/scheduler_json_durable.py"))
    support_source = read_python_file(Path("Virus_Scan/scheduler/evidence/scheduler_json_durable_support.py"))

    for helper_name in (
        "context_failed",
        "context_tmp",
        "context_final",
        "context_tmp_cleanup",
        "context_bad_final_cleanup",
        "context_durability_cleanup",
        "context_durability_tmp_cleanup",
        "context_failed_final_probe",
        "context_failed_final_cleanup",
        "context_durable_write_failed",
        "durable_path_text",
    ):
        assert helper_name in durable_source
        assert helper_name in support_source

    for suffix_literal in (
        '"_failed"',
        '"_tmp"',
        '"_final"',
        '"_tmp_cleanup"',
        '"_bad_final_cleanup"',
        '"_durability_cleanup"',
        '"_durability_tmp_cleanup"',
        '"_failed_final_probe"',
        '"_failed_final_cleanup"',
        '"_durable_write_failed"',
    ):
        assert suffix_literal not in durable_source
        assert suffix_literal in support_source


def test_stage2216_raw_policy_helpers_are_scheduler_policy_domain_adapters():
    assert writer_support.raw_policy_label("GLOBAL_RAW_QUEUE_MAX_CHUNKS") == "raw_queue_max_chunks"
    assert writer_support.raw_policy_issue_label("raw_queue_max_chunks") == "raw_queue_max_chunks_policy_issue"
    assert writer_support.raw_policy_rejected_reason("raw_queue_max_chunks") == "raw_queue_max_chunks_policy_rejected"

    for name in (
        "raw_policy_label",
        "raw_policy_issue_label",
        "raw_policy_rejected_reason",
        "raw_policy_int",
    ):
        assert name in writer_support.__all__


def test_stage2216_raw_queue_policy_entrypoints_bind_canonical_names_and_bounds():
    issues: list[tuple[str, str]] = []
    values = {
        "GLOBAL_RAW_QUEUE_CHUNK_BYTES": "32",
        "GLOBAL_RAW_QUEUE_MAX_CHUNKS": "3",
        "GLOBAL_RAW_QUEUE_MIN_BYTES": "-5",
    }

    def runtime_value(name: str, default: int) -> object:
        return values.get(name, default)

    def record_suppressed(where: str, exc: BaseException) -> None:
        issues.append((where, str(exc)))

    assert raw_chunk_bytes(runtime_value=runtime_value, record_suppressed=record_suppressed) == 32
    assert raw_queue_max_chunks(runtime_value=runtime_value, record_suppressed=record_suppressed) == 3
    assert raw_queue_min_bytes(runtime_value=runtime_value, record_suppressed=record_suppressed) == 0
    assert issues == []


def test_stage2216_scheduler_json_section_adapter_preserves_canonical_defaults():
    section = build_scheduler_json_section([])

    assert section["scheduler_status"] == "ok"
    assert section["degraded"] is False
    assert section["fatal"] is False
    assert section["evidence"] == []
    assert section["checkpoint"] == {}
    assert section["replay_comparison_result"] == {}
