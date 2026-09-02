from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
import inspect
import json
from Virus_Scan.scheduler.replay import replay_snapshot as hybrid_state
from Virus_Scan.scheduler.execution import queue_executor as grqs
from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore
from Virus_Scan.scheduler.queue import raw_queue_counts
from Virus_Scan.scheduler.queue import progress as queue_progress
from Virus_Scan.scheduler.evidence import suppressed_failures
from Virus_Scan.scheduler.queue import claim_sidecar as process_queue_claims
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.queue.raw_integrity import mark_raw_integrity_failure as _mark_raw_integrity_failure_impl
from Virus_Scan.utils.tagging import ordered_unique_tags
sniff_file_identity = raw_deps.sniff_file_identity
get_scan_extension = raw_deps.get_scan_extension
normalize_stage = raw_deps.normalize_stage
choose_effective_stage = raw_deps.choose_effective_stage
runtime_value = raw_deps.runtime_value
_global_raw_eligible = raw_deps._global_raw_eligible
_global_raw_file_id = raw_deps._global_raw_file_id
build_raw_stage_jobs = raw_deps.build_raw_stage_jobs
_stage113_record_process_queue_suppressed = suppressed_failures.record_process_queue_suppressed
_set_scan_integrity = raw_deps._set_scan_integrity


def _raw_queue_live_count(queue_dir):
    return raw_queue_counts.raw_queue_live_count(
        queue_dir,
        queue_progress_counts=queue_progress.queue_progress_counts_global,
        report=_stage113_record_process_queue_suppressed,
        live_hard_cap=int(runtime_value("RAW_LIVE_HARD_CAP", 900) or 900),
    )


def _record_degraded_integrity(path, exc, where, *, set_scan_integrity=_set_scan_integrity, report=_stage113_record_process_queue_suppressed):
    info = {
        "raw_queue_degraded": True,
        "had_degraded_stage": True,
        "scan_incomplete": True,
        "allow_learning": False,
        "failure_info": {"stage": str(where), "exception_type": type(exc).__name__, "error": str(exc)},
    }
    set_scan_integrity(path, info)
    report(f"stage121.{where}", exc)


def _mark_raw_integrity_failure(path, integrity, **kwargs):
    return _mark_raw_integrity_failure_impl(
        path,
        integrity,
        set_scan_integrity=_set_scan_integrity,
        report=lambda where, exc: None,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        **kwargs,
    )


def _global_raw_publish_job(queue_dir, job):
    return False


def _global_raw_process_one_job(queue_dir, only_file_id=None):
    return False


def _global_raw_queue_scan_dependencies(**overrides):
    def dep(name, default):
        return overrides.get(name, default)

    return grqs.GlobalRawQueueScanDependencies(
        sniff_file_identity=dep("sniff_file_identity", sniff_file_identity),
        get_scan_extension=dep("get_scan_extension", get_scan_extension),
        normalize_stage=dep("normalize_stage", normalize_stage),
        choose_effective_stage=dep("choose_effective_stage", choose_effective_stage),
        runtime_value=dep("runtime_value", runtime_value),
        global_raw_eligible=dep("global_raw_eligible", _global_raw_eligible),
        raw_queue_live_count=dep("raw_queue_live_count", _raw_queue_live_count),
        global_raw_file_id=dep("global_raw_file_id", _global_raw_file_id),
        build_raw_stage_jobs=dep("build_raw_stage_jobs", build_raw_stage_jobs),
        raw_stage_job_build_dependencies=dep("raw_stage_job_build_dependencies", raw_deps._raw_stage_job_build_dependencies),
        raw_accumulator_store=dep("raw_accumulator_store", RawAccumulatorStore),
        global_raw_publish_job=dep("global_raw_publish_job", _global_raw_publish_job),
        global_raw_process_one_job=dep("global_raw_process_one_job", _global_raw_process_one_job),
        ordered_unique_tags=dep("ordered_unique_tags", ordered_unique_tags),
        finalize_tag_evidence_generation=dep("finalize_tag_evidence_generation", raw_deps.finalize_tag_evidence_generation),
        apply_integrity_tags=dep("apply_integrity_tags", lambda tags, integrity, marker='raw_accumulator_incomplete': raw_deps._raw_apply_integrity_tags_impl(tags, integrity, marker=marker, scanner_degraded_tags=raw_deps._contract_scanner_degraded_tags)),
        normalize_tags=dep("normalize_tags", raw_deps.normalize_tags),
        staged_enrichment_score=dep("staged_enrichment_score", raw_deps.score_inmemory_raw_stage_observations),
        scanner_degraded_tags=dep("scanner_degraded_tags", raw_deps._contract_scanner_degraded_tags),
        mark_raw_integrity_failure=dep("mark_raw_integrity_failure", _mark_raw_integrity_failure),
        remember_scan_evidence=dep("remember_scan_evidence", raw_deps._remember_scan_evidence),
        normalize_yara_hits=dep("normalize_yara_hits", raw_deps.normalize_yara_hits),
        set_scan_integrity=dep("set_scan_integrity", _set_scan_integrity),
        log_error=dep("log_error", raw_deps.log_error),
        record_issue=dep("record_issue", raw_deps._record_raw_queue_issue),
        record_degradation=dep("record_degradation", _record_degraded_integrity),
    )


def _hybrid_queue_state_delta(queue_dir, *, report=_stage113_record_process_queue_suppressed, **delta):
    return hybrid_state.hybrid_queue_state_delta(queue_dir, report=lambda where, exc: report(f"stage121.{where}", exc), **delta)


def _queue_cleanup_orphan_claim_meta(active_dir, *, min_age_sec=0.0, max_remove=8192):
    return process_queue_claims._queue_cleanup_orphan_claim_meta(active_dir, max_remove=max_remove)


def test_stage121_global_raw_outer_failure_records_degraded_integrity(tmp_path):
    target = tmp_path / "bad.bin"
    target.write_bytes(b"x")
    calls = []
    integrity = {}
    outcome = grqs.scan_file_via_global_raw_queue(
        str(target),
        tmp_path,
        pretriage_tags=["force"],
        pretriage_suspicious=True,
        deps=_global_raw_queue_scan_dependencies(
            sniff_file_identity=lambda path: (_ for _ in ()).throw(OSError("identity denied")),
            set_scan_integrity=lambda path, info: integrity.update(info),
            record_degradation=lambda path, exc, where: _record_degraded_integrity(
                path,
                exc,
                where,
                set_scan_integrity=lambda p, info: integrity.update(info),
                report=lambda where, exc: calls.append((where, type(exc).__name__)),
            ),
        ),
    )
    assert outcome.ok is False
    assert outcome.status == "failed"
    assert outcome.reason == "global_raw_scan_file_via_queue_failed"
    assert outcome.exception_type == "OSError"

    assert integrity["raw_queue_degraded"] is True
    assert integrity["had_degraded_stage"] is True
    assert integrity["scan_incomplete"] is True
    assert integrity["allow_learning"] is False
    assert integrity["failure_info"]["stage"] == "global_raw_scan_file_via_queue"
    assert ("stage121.global_raw_scan_file_via_queue", "OSError") in calls


def test_stage121_hybrid_queue_state_delta_is_transactional(tmp_path):
    calls = []
    hybrid_state.hybrid_queue_state_set(tmp_path, {})
    hybrid_state.hybrid_queue_state_set(tmp_path, {"raw_pending": 2})
    before = hybrid_state.hybrid_queue_state_get(tmp_path)
    _hybrid_queue_state_delta(
        tmp_path,
        report=lambda where, exc: calls.append((where, type(exc).__name__)),
        raw_pending=3,
        raw_done=object(),
    )
    after = hybrid_state.hybrid_queue_state_get(tmp_path)

    assert before == {"raw_pending": 2}
    assert after == before
    assert ("stage121.hybrid_queue_state_delta_invalid", "HybridQueueStateError") in calls


def test_stage121_hybrid_queue_state_get_invalid_age_reports(tmp_path):
    calls = []
    hybrid_state.hybrid_queue_state_set(tmp_path, {"raw_pending": 1})
    assert hybrid_state.hybrid_queue_state_get(
        tmp_path,
        max_age_sec=object(),
        report=lambda where, exc: calls.append((f"stage121.{where}", type(exc).__name__)),
    ) is None
    assert ("stage121.hybrid_queue_state_get_invalid", "TypeError") in calls


def test_stage121_orphan_claim_meta_cleanup_records_age_failure(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    orphan = active / "abc.json.claim"
    orphan.write_text(json.dumps({"worker": "x"}), encoding="utf-8")
    removed = _queue_cleanup_orphan_claim_meta(active, min_age_sec=1.0)

    assert removed == 1
    assert not orphan.exists()


def test_stage121_raw_queue_outer_broad_handlers_reduced():
    src = inspect.getsource(grqs.scan_file_via_global_raw_queue)
    assert "except Exception" not in src
