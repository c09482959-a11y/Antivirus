import os
from pathlib import Path

from Virus_Scan.scheduler.runtime.backpressure_policy import dynamic_process_queue_target, smooth_worker_target


def testsmooth_worker_target_uses_static_env_defaults():
    old_up = os.environ.pop("UMIGE_ELASTIC_SCALE_UP_STEP", None)
    old_down = os.environ.pop("UMIGE_ELASTIC_SCALE_DOWN_STEP", None)
    try:
        assert smooth_worker_target(1, 3) == 3
        assert smooth_worker_target(30, 1) == 20
    finally:
        if old_up is not None:
            os.environ["UMIGE_ELASTIC_SCALE_UP_STEP"] = old_up
        if old_down is not None:
            os.environ["UMIGE_ELASTIC_SCALE_DOWN_STEP"] = old_down


def testdynamic_process_queue_target_is_backpressure_owned():
    target, _cpu = dynamic_process_queue_target(4, 2)

    assert 1 <= target <= 4
    assert not Path("Virus_Scan/scheduler/execution/worker_policy.py").exists()
