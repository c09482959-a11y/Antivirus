from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import inmemory_stage_is_pre_execution


def test_generic_scan_stage_is_not_pre_execution_for_stall_classification():
    assert inmemory_stage_is_pre_execution("start") is True
    assert inmemory_stage_is_pre_execution("cache_lookup") is True
    assert inmemory_stage_is_pre_execution("type_scan") is True
    assert inmemory_stage_is_pre_execution("scan") is False
    assert inmemory_stage_is_pre_execution("image") is False
    assert inmemory_stage_is_pre_execution("archive") is False

from Virus_Scan.scheduler.workers.inmemory_lifecycle_policy import inmemory_start_wait_budget


def test_assigned_start_wait_uses_bounded_start_ownership_budget():
    rec = {"timeout_budget": {"timeout_budget": 3600.0}}
    assert inmemory_start_wait_budget(rec, 300.0) == 120.0
    small = {"timeout_budget": {"timeout_budget": 46.0}}
    assert inmemory_start_wait_budget(small, 300.0) == 30.0
