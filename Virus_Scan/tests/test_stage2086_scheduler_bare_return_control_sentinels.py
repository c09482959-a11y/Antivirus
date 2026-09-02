"""Stage2086 scheduler bare-return sentinel closure guards."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Final

from Virus_Scan.scheduler.contracts.evidence_record_support import merge_field_issue
from Virus_Scan.scheduler.orchestration.process_queue_completion_evidence import (
    attach_scheduler_evidence_to_merged_results,
    attach_worker_exit_evidence_to_merged_results,
)
from Virus_Scan.scheduler.replay.replay_projection import iter_replay_evidence_items

_ROOT: Final = Path(__file__).resolve().parents[2]

_STAGE2086_BARE_RETURN_ROWS: Final = (
    ("Virus_Scan/scheduler/contracts/evidence_record_support.py", 16, "merge_field_issue", "void"),
    ("Virus_Scan/scheduler/evidence/scheduler_json_writer.py", 30, "_record_raw_policy_issue", "void"),
    ("Virus_Scan/scheduler/execution/raw_stage_input.py", 180, "normalise_raw_stage_out_tags", "void"),
    ("Virus_Scan/scheduler/internal/owned_indexed_sequence.py", 103, "owned_indexed_set", "void"),
    (
        "Virus_Scan/scheduler/orchestration/inmemory_timeout_config_job_evidence.py",
        81,
        "attach_timeout_config_evidence_to_job_records",
        "void",
    ),
    (
        "Virus_Scan/scheduler/orchestration/inmemory_timeout_config_job_evidence.py",
        83,
        "attach_timeout_config_evidence_to_job_records",
        "void",
    ),
    (
        "Virus_Scan/scheduler/orchestration/process_queue_completion_evidence.py",
        101,
        "attach_worker_exit_evidence_to_merged_results",
        "void",
    ),
    (
        "Virus_Scan/scheduler/orchestration/process_queue_completion_evidence.py",
        103,
        "attach_worker_exit_evidence_to_merged_results",
        "void",
    ),
    (
        "Virus_Scan/scheduler/orchestration/process_queue_completion_evidence.py",
        119,
        "attach_scheduler_evidence_to_merged_results",
        "void",
    ),
    (
        "Virus_Scan/scheduler/orchestration/process_queue_completion_evidence.py",
        122,
        "attach_scheduler_evidence_to_merged_results",
        "void",
    ),
    ("Virus_Scan/scheduler/queue/claim_candidates.py", 88, "_record_pending_claim_failure", "void"),
    ("Virus_Scan/scheduler/queue/identity_index_storage.py", 165, "prune_index_dir", "void"),
    ("Virus_Scan/scheduler/queue/identity_index_storage.py", 175, "prune_index_dir", "void"),
    ("Virus_Scan/scheduler/queue/reclaim_publication_support.py", 85, "append_action_evidence", "void"),
    ("Virus_Scan/scheduler/replay/replay_projection.py", 149, "iter_replay_evidence_items", "generator"),
    ("Virus_Scan/scheduler/replay/replay_projection.py", 152, "iter_replay_evidence_items", "generator"),
    ("Virus_Scan/scheduler/replay/replay_projection.py", 156, "iter_replay_evidence_items", "generator"),
    ("Virus_Scan/scheduler/runtime/child_console.py", 17, "install_child_console_handlers", "void"),
    (
        "Virus_Scan/scheduler/workers/inmemory_worker_assignment.py",
        42,
        "_report_invalid_inmemory_assignment",
        "void",
    ),
    (
        "Virus_Scan/scheduler/workers/inmemory_worker_thread_progress.py",
        105,
        "_record_heartbeat_failure",
        "void",
    ),
    ("Virus_Scan/scheduler/workers/ipc_lifecycle_common.py", 90, "record_method_rejection", "void"),
)


def _enclosing_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef:
    functions = tuple(
        node
        for node in ast.walk(tree)
        if type(node) in {ast.FunctionDef, ast.AsyncFunctionDef}
        and node.lineno <= line <= node.end_lineno
    )
    assert functions
    return max(functions, key=lambda node: node.lineno)


def test_stage2086_scheduler_bare_returns_are_void_or_generator_control() -> None:
    """Closed bare-return rows must not be externally observable success defaults."""
    for relative_path, line, symbol, expected_kind in _STAGE2086_BARE_RETURN_ROWS:
        path = _ROOT / relative_path
        source = path.read_text(encoding="utf-8")
        assert source.splitlines()[line - 1].strip() == "return"
        tree = ast.parse(source, filename=str(path))
        function = _enclosing_function(tree, line)
        assert function.name == symbol
        returns = tuple(
            node for node in ast.walk(function) if type(node) is ast.Return and node.lineno == line
        )
        assert len(returns) == 1
        assert returns[0].value is None
        if expected_kind == "void":
            assert function.returns is not None
            assert ast.unparse(function.returns) == "None"
        else:
            assert expected_kind == "generator"
            assert any(type(node) in {ast.Yield, ast.YieldFrom} for node in ast.walk(function))


def test_stage2086_representative_scheduler_void_sentinels_are_local_control() -> None:
    merged: dict[str, object] = {"scan": {}}
    assert merge_field_issue(merged, None) is None
    assert merged == {"scan": {}}
    assert attach_worker_exit_evidence_to_merged_results(merged, ()) is None
    assert merged == {"scan": {}}
    rejected_merged: Any = "not-a-dict"
    assert attach_scheduler_evidence_to_merged_results(rejected_merged, ()) is None
    assert tuple(iter_replay_evidence_items(None)) == ()
    assert tuple(iter_replay_evidence_items({"evidence": "kept"})) == ({"evidence": "kept"},)
