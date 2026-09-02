from __future__ import annotations

import dataclasses

import pytest

from Virus_Scan.scheduler.context.inmemory_raw_dependencies import InMemoryRawDependencyInputs
from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies


def _noop(*args, **kwargs):
    return None


def test_phase9_inmemory_raw_dependency_contracts_do_not_expose_mutable_instance_dicts() -> None:
    assert dataclasses.is_dataclass(InMemoryRawScanDependencies)
    assert dataclasses.is_dataclass(InMemoryRawDependencyInputs)
    assert not hasattr(InMemoryRawScanDependencies(
        deep_scan_thorough=_noop,
        sniff_file_identity=_noop,
        get_scan_extension=_noop,
        runtime_value=_noop,
        normalize_stage=_noop,
        choose_effective_stage=_noop,
        global_raw_eligible=_noop,
        global_raw_file_id=_noop,
        build_raw_stage_jobs=_noop,
        raw_stage_job_build_dependencies=_noop,
        execute_stage_job=_noop,
        scheduler_thread_pool=object(),
        environ_get=_noop,
        record_issue=_noop,
        scanner_degraded_tags=_noop,
        finalize_tag_evidence_generation=_noop,
        normalize_tags=_noop,
        staged_enrichment_score=_noop,
        record_suppressed=_noop,
        set_scan_integrity=_noop,
        remember_scan_evidence=_noop,
        apply_integrity_tags=_noop,
        normalize_yara_hits=_noop,
        log_error=_noop,
        recoverable_exceptions=(Exception,),
        now=_noop,
    ), "__dict__")


def test_phase9_inmemory_raw_dependency_inputs_reject_hidden_runtime_attribute_mutation() -> None:
    inputs = InMemoryRawDependencyInputs(
        deep_scan_thorough=_noop,
        sniff_file_identity=_noop,
        get_scan_extension=_noop,
        runtime_value=_noop,
        normalize_stage=_noop,
        choose_effective_stage=_noop,
        global_raw_eligible=_noop,
        global_raw_file_id=_noop,
        build_raw_stage_jobs=_noop,
        raw_collector_cap=_noop,
        raw_chunk_bytes=_noop,
        raw_queue_max_chunks=_noop,
        retry_max=_noop,
        record_suppressed=_noop,
        yara_rules_state=object(),
        yara_parallel_group_count=_noop,
        execute_stage_job=_noop,
        record_issue=_noop,
        scanner_degraded_tags=_noop,
        finalize_tag_evidence_generation=_noop,
        normalize_tags=_noop,
        staged_enrichment_score=_noop,
        set_scan_integrity=_noop,
        remember_scan_evidence=_noop,
        apply_integrity_tags=_noop,
        normalize_yara_hits=_noop,
        log_error=_noop,
    )

    assert not hasattr(inputs, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        inputs.runtime_override = _noop  # type: ignore[attr-defined]
