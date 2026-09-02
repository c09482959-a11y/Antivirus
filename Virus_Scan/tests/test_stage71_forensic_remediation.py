from pathlib import Path
import ast


ROOT = Path(__file__).resolve().parents[1]

def _src(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def test_stage71_process_queue_engine_is_direct_canonical_boundary():
    src = _src('scheduler/queue/claim.py')
    assert 'ProcessQueueComponentSet' not in src
    assert 'ProcessQueueDependencies' not in src
    assert 'self.components' not in src
    assert 'def claim_process_queue_job(' in src
    assert 'def _claim_process_queue_job(' not in src
    assert 'def _finish_process_queue_job(' not in src
    assert 'def _reclaim_stale_process_queue_jobs(' not in src
    finalization_src = _src('scheduler/queue/process_queue_finalization.py')
    recovery_src = _src('scheduler/queue/orphan_recovery.py')
    assert 'def _finish_process_queue_job(' in finalization_src
    assert 'def _reclaim_stale_process_queue_jobs(' in recovery_src


def test_stage71_process_queue_component_facade_removed_after_simplification():
    assert not (ROOT / 'scheduler/process_queue_components.py').exists()


def test_stage71_raw_scheduler_facade_removed_after_phase9_convergence():
    assert not (ROOT / 'scheduler/raw_queue.py').exists()

def test_stage71_event_publisher_facade_removed_and_bus_uses_direct_economics_ledger():
    assert not (ROOT / 'runtime/event_publisher.py').exists()
    src = _src('runtime/causal_event_stream.py')
    assert 'observe_runtime_economics' in src
    assert 'EventPublisher' not in src


def test_stage71_recovery_classification_is_owned_by_reconciliation():
    assert not (ROOT / 'scheduler/recovery_coordinator.py').exists()
    assert not (ROOT / 'scheduler/raw_queue.py').exists()
    recovery_src = _src('scheduler/queue/recovery_decisions.py')
    assert 'def classify_queue_failure(' in recovery_src
    assert 'runtime_economics_controller' not in recovery_src


def test_stage71_compatibility_budget_module_removed_after_phase9_convergence():
    assert not (ROOT / 'runtime/compatibility_budget.py').exists()
