from __future__ import annotations

import ast
import inspect
import textwrap

from Virus_Scan.scheduler.evidence.final_json_projection import (
    FinalJsonSchedulerSectionDecision,
    build_final_json_scheduler_section,
    build_final_json_scheduler_section_decision,
)
from Virus_Scan.scheduler.queue.reclaim_publication_support import (
    JobIdentifierDecision,
    OwnedJobRecordDecision,
    job_identifier,
    job_identifier_decision,
    owned_job_record,
    owned_job_record_decision,
)
from Virus_Scan.scheduler.runtime.passive_asset_triage import (
    TerminalCleanAssetTriageDecision,
    is_terminal_clean_asset_triage,
    is_terminal_clean_asset_triage_decision,
)


class HostileObject:
    def __getattribute__(self, name: str):  # pragma: no cover - should never run
        raise AssertionError(f"hostile attribute accessed: {name}")

    def __bool__(self):  # pragma: no cover - should never run
        raise AssertionError("hostile bool invoked")

    def __str__(self):  # pragma: no cover - should never run
        raise AssertionError("hostile str invoked")


def _single_return_expression(function: object) -> str:
    parsed = ast.parse(textwrap.dedent(inspect.getsource(function)))
    returns = [node.value for node in ast.walk(parsed) if isinstance(node, ast.Return)]
    assert len(returns) == 1
    return ast.unparse(returns[0])


def test_stage2127_final_json_projection_exposes_no_section_decisions() -> None:
    hostile_decision = build_final_json_scheduler_section_decision(HostileObject())
    assert isinstance(hostile_decision, FinalJsonSchedulerSectionDecision)
    assert hostile_decision.section is None
    assert hostile_decision.reason == "record_not_exact_mapping"
    assert hostile_decision.record_is_mapping is False

    empty_decision = build_final_json_scheduler_section_decision({})
    assert empty_decision.section is None
    assert empty_decision.reason == "scheduler_evidence_not_found"
    assert empty_decision.record_is_mapping is True
    assert empty_decision.evidence_count == 0
    assert build_final_json_scheduler_section({}) is None


def test_stage2127_reclaim_publication_records_identifier_decisions() -> None:
    rejected = owned_job_record_decision(object())
    assert isinstance(rejected, OwnedJobRecordDecision)
    assert rejected.record is None
    assert rejected.reason == "job_record_not_mapping"
    assert rejected.accepted is False
    assert owned_job_record(object()) is None

    filtered = owned_job_record_decision({"id": "alpha", 1: "dropped"})
    assert filtered.record == {"id": "alpha"}
    assert filtered.reason == "job_record_available"
    assert filtered.accepted is True

    missing = job_identifier_decision(None)
    assert isinstance(missing, JobIdentifierDecision)
    assert missing.identifier == ""
    assert missing.reason == "job_record_missing"
    assert missing.available is False

    absent = job_identifier_decision({})
    assert absent.identifier == ""
    assert absent.reason == "job_identifier_missing"
    assert absent.available is False

    available = job_identifier_decision({"job_id": "job-7"})
    assert available.identifier == "job-7"
    assert available.reason == "job_id_available"
    assert available.available is True
    assert job_identifier({"file": "scan.bin"}) == "scan.bin"


def test_stage2127_passive_asset_triage_records_blocking_decisions() -> None:
    suspicious = is_terminal_clean_asset_triage_decision(["media_asset"], suspicious=True)
    assert isinstance(suspicious, TerminalCleanAssetTriageDecision)
    assert suspicious.is_terminal_clean is False
    assert suspicious.reason == "suspicious_asset_triage_blocked"

    blocked = is_terminal_clean_asset_triage_decision(["media_asset", "process_exec"])
    assert blocked.is_terminal_clean is False
    assert blocked.reason == "terminal_blocking_tag_present"

    clean = is_terminal_clean_asset_triage_decision(["media_asset"])
    assert clean.is_terminal_clean is True
    assert clean.reason == "terminal_clean_tag_present"
    assert is_terminal_clean_asset_triage(["media_asset"]) is True

    missing = is_terminal_clean_asset_triage_decision([])
    assert missing.is_terminal_clean is False
    assert missing.reason == "terminal_clean_tag_missing"


def test_stage2127_public_wrappers_are_decision_projections() -> None:
    assert _single_return_expression(build_final_json_scheduler_section) == (
        "build_final_json_scheduler_section_decision(record).section"
    )
    assert _single_return_expression(owned_job_record) == "owned_job_record_decision(job).record"
    assert _single_return_expression(job_identifier) == "job_identifier_decision(job_record).identifier"
    assert _single_return_expression(is_terminal_clean_asset_triage) == (
        "is_terminal_clean_asset_triage_decision(tags, suspicious=suspicious).is_terminal_clean"
    )
