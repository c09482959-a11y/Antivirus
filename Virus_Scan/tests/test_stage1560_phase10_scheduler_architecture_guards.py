"""Stage 1560 Phase 10 scheduler architecture regression guards."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import bare_or_broad_exception_findings, local_import_and_dynamic_import_findings, python_files_under, read_python_file

from pathlib import Path


SCHEDULER_ROOT = Path("Virus_Scan/scheduler")


def test_stage1560_scheduler_has_no_imports_inside_functions_or_dynamic_imports() -> None:
    offenders: list[str] = []
    for path in python_files_under("Virus_Scan/scheduler"):
        offenders.extend(local_import_and_dynamic_import_findings(path))
    assert offenders == []


def test_stage1560_scheduler_has_no_bare_or_broad_exception_handlers() -> None:
    offenders: list[str] = []
    for path in python_files_under("Virus_Scan/scheduler"):
        offenders.extend(bare_or_broad_exception_findings(path))
    assert offenders == []


def test_stage1560_scheduler_json_boundaries_have_no_unknown_str_repr_or_as_dict_fallbacks() -> None:
    sources = {
        Path("Virus_Scan/scheduler/internal/immutable_outputs.py"): (
            "repr(value)",
            "return str(value)",
        ),
        Path("Virus_Scan/scheduler/runtime/queue_json_safety.py"): (
            "repr(value)",
            "return str(value)",
            "json.dumps(value, allow_nan=False)",
            "Path)",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_contract_support.py"): (
            "getattr(value",
            "as_dict",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_status_sources.py"): (
            "not in (None, \"\")",
            "not in (None, '')",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_checkpoint_projection.py"): (
            "or record.get(\"checkpoint_path\")",
            "or record.get('checkpoint_path')",
            "source.get(",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_contract_projection.py"): (
            "result.get(",
            "status.get(",
            "str(result",
            "str(status",
            "bool(status.get",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_scheduler_result_projection.py"): (
            "result.get(",
            "str(result",
            "bool(result.get",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_exact_fields.py"): (
            "str(value)",
            "source.get(",
            "isinstance(value, str)",
            "list(value)",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_compact_error_projection.py"): (
            "record.get(",
            "isinstance(record, Mapping)",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_evidence_mapping.py"): (
            "source.items(",
            "str(key)",
            "value in (None",
            "value.get(",
            "record.get(",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_failure_projection.py"): (
            "record.get(",
            "scan_integrity.get(",
            "str(category or",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_passive_status_projection.py"): (
            "source.items(",
            "record.get(",
            "status.get(",
            "str(status",
            "bool(status.get",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_projection.py"): (
            "record.get(",
            "isinstance(record, Mapping)",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_queue_projection.py"): (
            "source.get(",
            "status.get(",
            "str(status",
            "bool(status.get",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_replay_projection.py"): (
            "record.get(",
            "replay_status.get(",
            "str(replay_status",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_scheduler_status_projection.py"): (
            "record.get(",
            "scheduler_section.get(",
            "str(scheduler_section",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_status_sources.py"): (
            "source.get(",
            "record.get(",
        ),
        Path("Virus_Scan/scheduler/evidence/final_json_trace_projection.py"): (
            "source.get(",
            "status.get(",
            "str(status",
            "bool(status.get",
        ),
        Path("Virus_Scan/scheduler/replay/replay_projection.py"): (
            "default=str",
            "str(value or",
            "str(item)",
            "list(value)",
            "isinstance(value, str)",
        ),
        Path("Virus_Scan/scheduler/replay/replay_result_fields.py"): (
            "str(value)",
            "result.get(",
            "isinstance(value, str)",
            "list(value)",
        ),
        Path("Virus_Scan/scheduler/replay/replay_validator.py"): (
            "result.get(",
            " or result.get",
            "int(result.get",
            "results or",
            "self.records or",
        ),
    }
    for path, forbidden in sources.items():
        text = read_python_file(path)
        for marker in forbidden:
            assert marker not in text, f"{path} still contains {marker}"

    queue_json_source = read_python_file(Path("Virus_Scan/scheduler/runtime/queue_json_safety.py"))
    assert "isinstance(value, str) and len(value)" not in queue_json_source
    replay_source = read_python_file(Path("Virus_Scan/scheduler/replay/replay_projection.py"))
    assert "materialize_scheduler_mapping" in replay_source


def test_stage1560_stage_budget_uses_runtime_owner_and_no_disabled_tables() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/runtime/stage_budget.py"))
    table_source = read_python_file(Path("Virus_Scan/scheduler/runtime/stage_budget_tables.py"))

    assert "scheduler_runtime_state" in table_source
    assert "stage_tables_snapshot" in table_source
    assert "None or {}" not in source
    assert "return []" not in source


def test_stage1560_raw_stage_failure_integrity_fields_are_present() -> None:
    source = read_python_file(Path("Virus_Scan/scheduler/execution/raw_stage_failure.py"))
    required = (
        "raw_stage_failed",
        "queue_failure",
        "scheduler_failure",
        "scan_incomplete",
        "had_degraded_stage",
        "file_failed",
        "allow_learning",
        "final_json_must_record",
        "replay_must_record",
        "scheduler_failure_evidence",
    )
    for marker in required:
        assert marker in source


def test_stage1560_long_lived_scheduler_loops_use_guard_contract() -> None:
    targets = {
        Path("Virus_Scan/scheduler/orchestration/process_queue_monitor_loop.py"): "apply_process_queue_monitor_guard",
        Path("Virus_Scan/scheduler/orchestration/inmemory_parent_loop.py"): "advance_inmemory_parent_loop_guard",
        Path("Virus_Scan/scheduler/workers/inmemory_worker_process.py"): "advance_scheduler_loop_guard",
    }
    for path, marker in targets.items():
        source = read_python_file(path)
        assert marker in source


def test_stage1608_worker_exit_reconciliation_has_no_unknown_exit_result_hooks() -> None:
    owner_source = read_python_file(Path("Virus_Scan/scheduler/workers/process_queue_worker_exit.py"))
    evidence_source = read_python_file(Path("Virus_Scan/scheduler/workers/process_queue_worker_exit_evidence.py"))
    combined_source = owner_source + "\n" + evidence_source
    forbidden = (
        "hasattr(exit_result",
        "getattr(exit_result",
        "exit_result.as_evidence()",
        "int(exit_result)",
        "bool(getattr(exit_result",
        "str(output)",
        "f\"process queue worker {idx}",
    )
    for marker in forbidden:
        assert marker not in combined_source, f"worker-exit reconciliation still contains unsafe marker {marker}"
    assert "_unsupported_worker_exit_result_evidence" in owner_source
    assert "scheduler_worker_exit_result_unsupported" in evidence_source
