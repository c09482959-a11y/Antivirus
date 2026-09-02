from types import SimpleNamespace

import pytest

from Virus_Scan.orchestration.lifecycle import run_scan


class _Runtime:
    parent_cli = False
    scan_started_at = 0.0

    def __init__(self):
        self.environment = SimpleNamespace(publish=lambda values: None, publish_defaults=lambda values: None)
        self.owner = SimpleNamespace(update=lambda values, domain=None: None)
        self.config = None


def _args(tmp_path):
    return SimpleNamespace(
        dir=str(tmp_path),
        workers=1,
        strict=False,
        per_file_timeout=1,
        progress_every=1,
        throttle=0.0,
        max_files=None,
        no_freeze_baseline=False,
        flush_during_scan=False,
        output=str(tmp_path / "scan_results.json"),
        partial_output_every=1,
        slow_file_warn=1.0,
        scheduler="serial",
        file_list=None,
        work_queue_dir=None,
        worker_output=None,
    )


def test_scan_service_returns_scheduler_results_directly(tmp_path):
    expected = {"sample.py": {"score": 42}}

    def run_pipeline_safe(*args, **kwargs):
        return expected

    assert run_scan(_args(tmp_path), compiled_rules=None, scheduler_pipeline=run_pipeline_safe) is expected


def test_scan_service_does_not_convert_scheduler_failure_to_empty_clean_result(tmp_path):
    class SchedulerFailure(RuntimeError):
        pass

    def run_pipeline_safe(*args, **kwargs):
        raise SchedulerFailure("scheduler failure must remain explicit")

    with pytest.raises(SchedulerFailure, match="scheduler failure"):
        run_scan(_args(tmp_path), compiled_rules=None, scheduler_pipeline=run_pipeline_safe)
