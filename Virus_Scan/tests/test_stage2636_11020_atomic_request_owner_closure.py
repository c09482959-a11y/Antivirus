from __future__ import annotations

import ast
from pathlib import Path

_RETIRED_PARALLEL_OWNER_NAMES = frozenset({
    "_scan_strings_from_request",
    "advance_scheduler_loop_guard_from_request",
    "append_archive_member_failure_evidence_from_request",
    "append_reduce_chain_from_request",
    "apply_ecosystem_gate_from_request",
    "build_baseline_route_from_request",
    "build_execution_event_from_request",
    "build_process_queue_publish_attempt_from_request",
    "build_recovery_history_transition_from_request",
    "build_scheduler_config_snapshot_from_request",
    "bytecode_chunk_from_request",
    "configure_scheduler_profile_policy_from_request",
    "contextual_expected_behavior_signal_from_request",
    "dotnet_chunk_from_request",
    "drain_completed_inmemory_worker_futures_from_request",
    "enrich_with_api_and_graph_from_request",
    "failure_from_request",
    "filetype_bucket_model_signal_from_request",
    "finalize_scheduler_pipeline_run_from_request",
    "finish_unretryable_reclaimed_job_from_request",
    "idle_queue_finalization_decision_from_request",
    "malformed_from_request",
    "orphan_recovery_action_evidence_from_request",
    "pure_pe_chunk_from_request",
    "queue_done_jobs_missing_results_from_request",
    "record_retry_integrity_persistence_failure_from_request",
    "request_cancel_only_from_request",
    "run_file_with_retry_from_request",
    "tag_effective_evidence_score_from_request",
    "validate_result_publication_from_request",
    "verify_and_repair_queue_integrity_from_request",
})


def test_production_has_no_compatibility_delegator_or_retired_parallel_owner() -> None:
    findings: list[str] = []
    for path in sorted(Path("Virus_Scan").rglob("*.py")):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(node, clean=False) or ""
            if "Compatibility adapter" in doc:
                findings.append(f"{path}:{node.lineno}:compatibility_adapter")
            if node.name in _RETIRED_PARALLEL_OWNER_NAMES:
                findings.append(f"{path}:{node.lineno}:retired_parallel_owner:{node.name}")
    assert findings == []
