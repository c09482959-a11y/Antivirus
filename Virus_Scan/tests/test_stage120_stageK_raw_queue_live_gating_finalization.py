from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from pathlib import Path

from Virus_Scan.scheduler.execution import queue_executor as grqs
from Virus_Scan.scheduler.context import inmemory_raw_dependency_factory as raw_deps
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore
from Virus_Scan.scheduler.queue import raw_queue_counts
from Virus_Scan.scheduler.queue import progress as queue_progress
from Virus_Scan.scheduler.evidence import suppressed_failures
from Virus_Scan.scanners import raw_chunk_core
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.scheduler.queue.raw_integrity import mark_raw_integrity_failure as _mark_raw_integrity_failure_impl
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
sniff_file_identity = raw_deps.sniff_file_identity
get_scan_extension = raw_deps.get_scan_extension
normalize_stage = raw_deps.normalize_stage
choose_effective_stage = raw_deps.choose_effective_stage
runtime_value = raw_deps.runtime_value
_global_raw_eligible = raw_deps._global_raw_eligible
_global_raw_file_id = raw_deps._global_raw_file_id
build_raw_stage_jobs = raw_deps.build_raw_stage_jobs
staged_enrichment_score = raw_deps.score_inmemory_raw_stage_observations
_remember_scan_evidence = raw_deps._remember_scan_evidence
normalize_yara_hits = raw_deps.normalize_yara_hits
queue_progress_counts_global = queue_progress.queue_progress_counts_global
_stage113_record_process_queue_suppressed = suppressed_failures.record_process_queue_suppressed


def _raw_queue_live_count(
    queue_dir,
    *,
    queue_progress_counts=queue_progress_counts_global,
    report=_stage113_record_process_queue_suppressed,
    runtime_value_reader=runtime_value,
):
    return raw_queue_counts.raw_queue_live_count(
        queue_dir,
        queue_progress_counts=queue_progress_counts,
        report=report,
        live_hard_cap=int(runtime_value_reader("RAW_LIVE_HARD_CAP", 900) or 900),
    )


def _mark_raw_integrity_failure(path, integrity, **kwargs):
    return _mark_raw_integrity_failure_impl(
        path,
        integrity,
        set_scan_integrity=raw_deps._set_scan_integrity,
        report=lambda where, exc: None,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        **kwargs,
    )


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
        finalize_tag_evidence_generation=dep("finalize_tag_evidence_generation", finalize_tag_evidence_generation),
        apply_integrity_tags=dep("apply_integrity_tags", lambda tags, integrity, marker='raw_accumulator_incomplete': raw_deps._raw_apply_integrity_tags_impl(tags, integrity, marker=marker, scanner_degraded_tags=raw_deps._contract_scanner_degraded_tags)),
        normalize_tags=dep("normalize_tags", raw_deps.normalize_tags),
        staged_enrichment_score=dep("staged_enrichment_score", staged_enrichment_score),
        scanner_degraded_tags=dep("scanner_degraded_tags", raw_deps._contract_scanner_degraded_tags),
        mark_raw_integrity_failure=dep("mark_raw_integrity_failure", _mark_raw_integrity_failure),
        remember_scan_evidence=dep("remember_scan_evidence", _remember_scan_evidence),
        normalize_yara_hits=dep("normalize_yara_hits", normalize_yara_hits),
        set_scan_integrity=dep("set_scan_integrity", raw_deps._set_scan_integrity),
        log_error=dep("log_error", raw_deps.log_error),
        record_issue=dep("record_issue", raw_deps._record_raw_queue_issue),
        record_degradation=dep("record_degradation", lambda path, exc, where: None),
    )


def _global_raw_publish_job(queue_dir, job):
    raise NotImplementedError("test must provide canonical publish behavior")


def _global_raw_process_one_job(queue_dir, only_file_id=None):
    raise NotImplementedError("test must provide canonical execution behavior")


def test_stage120_raw_queue_surface_removed_after_canonical_owner_collapse():
    assert not Path(__file__).resolve().parents[1].joinpath('scheduler/raw_queue.py').exists()


def test_stage120_live_count_failure_fails_closed(tmp_path):
    calls = []
    assert _raw_queue_live_count(
        tmp_path,
        queue_progress_counts=lambda q: (_ for _ in ()).throw(OSError('counts unreadable')),
        report=lambda where, exc: calls.append((where, type(exc).__name__)),
        runtime_value_reader=lambda name, default=None: 37 if name == 'RAW_LIVE_HARD_CAP' else default,
    ) == 37
    assert ('raw_live_count_failed_closed', 'OSError') in calls


def test_stage120_context_decode_anchor_failure_scans_instead_of_skipping():
    class BadAnchors:
        def __iter__(self):
            raise TypeError('anchor registry corrupt')

    calls = []

    assert raw_chunk_core.should_context_scan(
        'nothing interesting',
        context_anchors=BadAnchors(),
        report=lambda where, exc: calls.append((where, type(exc).__name__)),
    ) is True
    assert raw_chunk_core.should_decode_scan(
        'A' * 120,
        decode_anchors=BadAnchors(),
        report=lambda where, exc: calls.append((where, type(exc).__name__)),
    ) is True
    assert ('raw_context_anchor_boundary_failed', 'TypeError') in calls
    assert ('raw_decode_anchor_boundary_failed', 'TypeError') in calls


def test_stage120_scoring_failure_marks_raw_result_degraded(tmp_path):
    target = tmp_path / 'x.bin'
    target.write_bytes(b'hello')
    file_id = 'fid-stage120-score'
    store = RawAccumulatorStore(tmp_path, file_id)
    store.init(target, expected=1, initial_tags=['global_raw_queue_scan'], effective_stage='binary', ext_stage='binary', identity={'tags': []})
    store.append({'collector': 'identity', 'seq': 0, 'tags': ['identity'], 'strings_blob': 'hello'})

    processed = {'n': 0}
    def _process_once(queue_dir, only_file_id=None):
        if processed['n'] < 4:
            store.append({'collector': 'identity', 'seq': processed['n'], 'tags': ['identity'], 'strings_blob': 'hello'})
            processed['n'] += 1
            return True
        return False
    result = grqs.scan_file_via_global_raw_queue(
        str(target),
        tmp_path,
        timeout_sec=1,
        pretriage_tags=['suspicious_anchor'],
        pretriage_suspicious=True,
        deps=_global_raw_queue_scan_dependencies(
            global_raw_file_id=lambda path: file_id,
            raw_queue_live_count=lambda queue_dir: 0,
            sniff_file_identity=lambda path: {'tags': []},
            get_scan_extension=lambda path: '.bin',
            normalize_stage=lambda ext: 'binary',
            choose_effective_stage=lambda ext_stage, identity: 'binary',
            global_raw_eligible=lambda path, effective_stage=None: True,
            build_raw_stage_jobs=lambda path, fid, effective_stage, ext_stage, identity, **kwargs: [{'file': str(target), 'file_id': file_id, 'collector': 'identity', 'seq': 0}] * 4,
            global_raw_publish_job=lambda queue_dir, job: True,
            global_raw_process_one_job=_process_once,
            finalize_tag_evidence_generation=finalize_tag_evidence_generation,
            staged_enrichment_score=lambda *a, **k: (_ for _ in ()).throw(RuntimeError('scoring broke')),
            remember_scan_evidence=lambda *a, **k: None,
            normalize_yara_hits=lambda hits: list(hits or []),
        ),
    )

    assert result is not None
    tags = set(result.get('tags') or [])
    assert {'raw_stage_scoring_failed', 'scanner_failure', 'scanner_degraded', 'scan_incomplete'} <= tags
    integrity = result.get('scan_integrity') or {}
    assert integrity.get('had_degraded_stage') is True
    assert integrity.get('allow_learning') is False


def test_stage120_evidence_failure_marks_raw_result_degraded(tmp_path):
    target = tmp_path / 'x.bin'
    target.write_bytes(b'hello')
    file_id = 'fid-stage120-evidence'
    store = RawAccumulatorStore(tmp_path, file_id)
    store.init(target, expected=1, initial_tags=['global_raw_queue_scan'], effective_stage='binary', ext_stage='binary', identity={'tags': []})
    store.append({'collector': 'identity', 'seq': 0, 'tags': ['identity'], 'strings_blob': 'hello'})

    processed = {'n': 0}
    def _process_once(queue_dir, only_file_id=None):
        if processed['n'] < 4:
            store.append({'collector': 'identity', 'seq': processed['n'], 'tags': ['identity'], 'strings_blob': 'hello'})
            processed['n'] += 1
            return True
        return False
    result = grqs.scan_file_via_global_raw_queue(
        str(target),
        tmp_path,
        timeout_sec=1,
        pretriage_tags=['suspicious_anchor'],
        pretriage_suspicious=True,
        deps=_global_raw_queue_scan_dependencies(
            global_raw_file_id=lambda path: file_id,
            raw_queue_live_count=lambda queue_dir: 0,
            sniff_file_identity=lambda path: {'tags': []},
            get_scan_extension=lambda path: '.bin',
            normalize_stage=lambda ext: 'binary',
            choose_effective_stage=lambda ext_stage, identity: 'binary',
            global_raw_eligible=lambda path, effective_stage=None: True,
            build_raw_stage_jobs=lambda path, fid, effective_stage, ext_stage, identity, **kwargs: [{'file': str(target), 'file_id': file_id, 'collector': 'identity', 'seq': 0}] * 4,
            global_raw_publish_job=lambda queue_dir, job: True,
            global_raw_process_one_job=_process_once,
            finalize_tag_evidence_generation=finalize_tag_evidence_generation,
            staged_enrichment_score=lambda *a, **k: (0.0, []),
            remember_scan_evidence=lambda *a, **k: (_ for _ in ()).throw(OSError('evidence store denied')),
            normalize_yara_hits=lambda hits: list(hits or []),
        ),
    )

    assert result is not None
    tags = set(result.get('tags') or [])
    assert {'raw_evidence_record_failed', 'scanner_failure', 'scanner_degraded', 'scan_incomplete'} <= tags
    integrity = result.get('scan_integrity') or {}
    assert integrity.get('had_degraded_stage') is True
    assert integrity.get('allow_learning') is False
