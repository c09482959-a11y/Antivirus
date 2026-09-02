from __future__ import annotations

from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex


def test_scheduler_state_index_owns_transition_counters_without_registry_recount():
    index = InMemorySchedulerStateIndex()
    index.sync_record(1, {"state": "queued"}, due_at=1.0)
    index.sync_record(2, {"state": "assigned", "cost": {"heavy": True, "weight": 3}}, due_at=1.0)
    index.sync_record(3, {"state": "running", "cost": {"heavy": True, "weight": 2}}, due_at=1.0)

    assert index.queued_unstarted_count() == 1
    assert index.logical_inflight_count() == 2
    assert index.queued_or_active_count() == 3
    assert index.active_heavy_weight() == 5
    assert index.active_job_ids() == (2, 3)


def test_scheduler_state_index_updates_counters_on_state_transition_and_terminal_removal():
    index = InMemorySchedulerStateIndex()
    index.sync_record(7, {"state": "queued"}, due_at=1.0)
    index.sync_record(7, {"state": "running", "cost": {"heavy": True, "weight": 4}}, due_at=2.0)

    assert index.queued_unstarted_count() == 0
    assert index.logical_inflight_count() == 1
    assert index.active_heavy_weight() == 4

    index.sync_record(7, {"state": "done"}, due_at=None)
    assert index.queued_or_active_count() == 0
    assert index.active_heavy_weight() == 0
    assert index.active_job_ids() == ()
    assert index.pending_deadline_count() == 0

def test_scheduler_state_index_deadline_heap_returns_only_due_jobs_in_deadline_order():
    index = InMemorySchedulerStateIndex()
    index.sync_record(3, {"state": "queued"}, due_at=30.0)
    index.sync_record(1, {"state": "running"}, due_at=10.0)
    index.sync_record(2, {"state": "assigned"}, due_at=20.0)

    assert index.pending_deadline_count() == 3
    assert index.pop_due(9.0) == ()
    assert index.pop_due(10.0) == (1,)
    assert index.pending_deadline_count() == 2
    assert index.pop_due(25.0) == (2,)
    assert index.pop_due(30.0) == (3,)
    assert index.pending_deadline_count() == 0


def test_scheduler_state_index_reschedule_lazily_invalidates_stale_heap_entry():
    index = InMemorySchedulerStateIndex()
    index.sync_record(7, {"state": "running"}, due_at=5.0)
    index.schedule_at(7, 50.0)

    assert index.pending_deadline_count() == 1
    assert index.pop_due(5.0) == ()
    assert index.pending_deadline_count() == 1
    assert index.pop_due(50.0) == (7,)
    assert index.pending_deadline_count() == 0


def test_scheduler_state_index_deadline_invalidation_and_terminal_transition_remove_due_work():
    index = InMemorySchedulerStateIndex()
    index.sync_record(8, {"state": "assigned"}, due_at=5.0)
    index.invalidate_deadline(8)

    assert index.pending_deadline_count() == 0
    assert index.pop_due(5.0) == ()

    index.schedule_at(8, 6.0)
    assert index.pending_deadline_count() == 1
    index.sync_record(8, {"state": "done"}, due_at=None)

    assert index.indexed_job_count() == 0
    assert index.pending_deadline_count() == 0
    assert index.pop_due(6.0) == ()

