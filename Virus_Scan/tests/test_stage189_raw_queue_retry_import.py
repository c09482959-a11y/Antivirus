import ast
from pathlib import Path

from Virus_Scan.scheduler.queue.retry_policy import run_file_with_retry


def test_raw_queue_retry_policy_is_owned_by_execution_module():
    assert run_file_with_retry.__module__ == "Virus_Scan.scheduler.queue.retry_policy"


def test_raw_queue_no_longer_reexports_retry_policy():
    assert not Path(__file__).resolve().parents[1].joinpath("scheduler/raw_queue.py").exists()
