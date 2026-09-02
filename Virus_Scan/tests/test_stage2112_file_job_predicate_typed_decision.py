from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.file_job_predicate import (
    FileJobPredicateDecision,
    process_queue_file_job_decision,
    process_queue_is_file_job,
)


def test_stage2112_file_job_predicate_exposes_replayable_rejection_reasons() -> None:
    unsupported_record = process_queue_file_job_decision(object())
    assert unsupported_record == FileJobPredicateDecision(
        is_file_job=False,
        reason="process_queue_file_job_record_rejected",
        field_name="job",
    )

    raw_stage = process_queue_file_job_decision({"job_type": "raw_stage"})
    assert raw_stage == FileJobPredicateDecision(
        is_file_job=False,
        reason="process_queue_file_job_raw_stage",
        field_name="job_type",
    )

    admitted = process_queue_file_job_decision({"job_type": "file", "collector": ""})
    assert admitted == FileJobPredicateDecision(
        is_file_job=True,
        reason="process_queue_file_job_admitted",
        field_name="",
    )


def test_stage2112_public_bool_contract_uses_typed_decision_owner() -> None:
    assert process_queue_is_file_job({"job_type": "file"}) is True
    assert process_queue_is_file_job({"job_type": "raw_stage"}) is False
    assert process_queue_file_job_decision({"collector": "yes"}).reason == (
        "process_queue_file_job_collector_present"
    )


def test_stage2112_file_job_predicate_source_removed_hidden_false_returns() -> None:
    source = Path("Virus_Scan/scheduler/queue/file_job_predicate.py").read_text()
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "process_queue_is_file_job"
    )
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    assert [ast.unparse(node.value) for node in returns] == [
        "process_queue_file_job_decision(job).is_file_job"
    ]
