from pathlib import Path

from Virus_Scan.scheduler.runtime.backpressure_policy import elastic_target_workers, smooth_worker_target


def testelastic_target_workers_is_backpressure_owned():
    assert elastic_target_workers(None, False, raw_live=0, max_workers=4) == 4
    assert not Path("Virus_Scan/scheduler/execution/worker_policy.py").exists()


def testsmooth_worker_target_is_backpressure_owned():
    assert smooth_worker_target(2, 10) >= 3
    assert not Path("Virus_Scan/scheduler/execution/worker_policy.py").exists()
