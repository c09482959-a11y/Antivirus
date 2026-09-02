from pathlib import Path

from Virus_Scan.scheduler.runtime import resource_priority


def test_resource_priority_owned_by_runtime_resource_priority():
    env = {}
    profile, cfg = resource_priority.apply_resource_priority_profile("low", env=env)

    assert profile == "low"
    assert cfg["process_queue_max_children"] == 24
    assert env["UMIGE_RESOURCE_PRIORITY"] == "low"
    assert env["UMIGE_PROCESS_QUEUE_MAX_CHILDREN"] == "24"
    snapshot = resource_priority.resource_priority_snapshot(env=env)
    assert snapshot["profile"] == "low"
    assert snapshot["config"]["elastic_min_workers"] == 4


def test_obsolete_root_resource_priority_module_deleted():
    assert not Path("Virus_Scan/scheduler/resource_priority.py").exists()
