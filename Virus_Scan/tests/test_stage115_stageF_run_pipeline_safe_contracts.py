from dataclasses import replace
import inspect

import pytest

from Virus_Scan.scheduler.api import runner as public_runner
from Virus_Scan.scheduler.orchestration import scheduler_runner as pipeline
from Virus_Scan.scheduler.orchestration.scheduler_file_execution_context import build_scheduler_file_execution_dependencies
from Virus_Scan.scheduler.orchestration.scheduler_target_planning import SchedulerTargetPlanningResult


def test_stage115_public_runner_delegates_to_canonical_execution_owner():
    src = inspect.getsource(public_runner.run_pipeline_safe)
    assert 'raw_queue.run_pipeline_safe' not in src
    assert 'run_scheduler_pipeline' in src
    assert public_runner.run_pipeline_safe.__module__ == 'Virus_Scan.scheduler.api.runner'


def test_stage115_canonical_pipeline_has_no_dynamic_global_probes():
    src = inspect.getsource(pipeline.run_scheduler_pipeline)
    assert 'globals()' not in src
    assert 'locals()' not in src
    assert 'getattr(__import__' not in src


def test_stage115_pipeline_imports_explicit_integrity_dependencies():
    # These dependencies used to be optional globals() probes in the old raw_queue
    # entry point. They are now static module-level contracts on the canonical
    # scheduler execution owner and directly injectable for tests.
    deps = pipeline.default_scheduler_pipeline_dependencies()
    for name in (
        'set_scan_integrity',
        'clear_scan_integrity',
        'flush_all_persistent_models',
        'write_partial_scheduler_results',
        'plan_scheduler_targets',
    ):
        assert callable(getattr(deps, name))
    assert callable(deps.build_scheduler_file_execution_dependencies)


def test_stage115_partial_output_failure_records_telemetry(tmp_path):
    calls = []

    def _raise_partial(**kwargs):
        raise OSError('partial denied')

    deps = replace(
        pipeline.default_scheduler_pipeline_dependencies(),
        plan_scheduler_targets=lambda *args, **kwargs: SchedulerTargetPlanningResult(files=(), total_files=0),
        write_partial_scheduler_results=_raise_partial,
        flush_all_persistent_models=lambda force=True: None,
        clear_profile_scoring_snapshot=lambda: None,
        freeze_profile_scoring_snapshot=lambda: None,
    )
    with pytest.raises(OSError) as excinfo:
        public_runner.run_pipeline_safe(
            str(tmp_path),
            scheduler='serial',
            max_workers=1,
            partial_output_path=tmp_path / 'partial.json',
            dependencies=deps,
        )
    calls.append(('partial_output_failed', str(excinfo.value)))
    assert calls == [('partial_output_failed', 'partial denied')]


def test_stage115_finalizer_failure_is_logged(tmp_path):
    calls = []
    sample = tmp_path / 'sample.txt'
    sample.write_text('hello', encoding='utf-8')

    class RouteOutcome(tuple):
        @property
        def identity(self):
            return {'declared_extension': '.txt'}

    file_deps = replace(
        build_scheduler_file_execution_dependencies(),
        scan_file_by_type=lambda path, **_kwargs: RouteOutcome((['text_asset'], False)),
        terminal_asset_triage=lambda tags, suspicious=False: True,
        make_terminal_asset_result=lambda path, tags, **kwargs: {
            'file': path, 'tags': list(tags), 'learn_eligible': True,
            'classification': 'benign_clean', 'class': 'benign_clean',
            'verdict': 'benign_clean', 'score': 0.0, 'effective_stage': 'test',
            'previous_stage': 'unknown', 'fast_path': False,
            'scan_integrity': {
                'allow_learning': True, 'file_failed': False,
                'had_degraded_stage': False, 'ok': True, 'failure_count': 0,
            },
            'engine_context': {'engine': 'text', 'baseline_key': 'text::text::.txt::text'},
            'container_engine': 'text', 'artifact_engine': 'text',
            'declared_extension': '.txt', 'sniffed_type': 'text',
            'effective_analysis_engine': 'text', 'baseline_key': 'text::text::.txt::text',
            'extension_baseline': 'text/.txt', 'contextual_baseline': 'text::text::.txt',
            'fingerprint_evidence': ['extension:.txt'],
        },
        attach_routing_evidence_to_record=lambda result, *args, **kwargs: result,
        effective_stage_for_path=lambda tags, path: 'test',
    )
    deps = replace(
        pipeline.default_scheduler_pipeline_dependencies(),
        plan_scheduler_targets=lambda *args, **kwargs: SchedulerTargetPlanningResult(files=(str(sample),), total_files=1),
        build_scheduler_file_execution_dependencies=lambda: file_deps,
        flush_all_persistent_models=lambda force=True: (_ for _ in ()).throw(OSError('flush denied')),
        write_partial_scheduler_results=lambda **kwargs: kwargs['last_partial_write'],
        clear_profile_scoring_snapshot=lambda: None,
        freeze_profile_scoring_snapshot=lambda: None,
        log_error=lambda message: calls.append(message),
    )
    public_runner.run_pipeline_safe(str(tmp_path), scheduler='serial', max_workers=1, dependencies=deps)
    assert any('persistent model flush failed at pipeline end' in message for message in calls)
