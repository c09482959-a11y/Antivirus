from types import SimpleNamespace

from Virus_Scan.orchestration.lifecycle import run_scan


class _Runtime:
    parent_cli = False


def _args(tmp_path, no_yara=False):
    return SimpleNamespace(
        dir=str(tmp_path),
        workers=1,
        strict=False,
        per_file_timeout=20,
        progress_every=10,
        throttle=0.0,
        max_files=None,
        no_freeze_baseline=False,
        flush_during_scan=False,
        output=str(tmp_path / "scan_results.json"),
        partial_output_every=10,
        slow_file_warn=2.0,
        scheduler="serial",
        file_list=None,
        work_queue_dir=None,
        worker_output=None,
        no_yara=no_yara,
    )


def test_scan_service_disables_scheduler_yara_when_rules_unavailable(tmp_path):
    captured = {}

    def fake_run_pipeline_safe(*args, **kwargs):
        captured.update(kwargs)
        return {}

    run_scan(_args(tmp_path, no_yara=False), compiled_rules=None, scheduler_pipeline=fake_run_pipeline_safe)

    assert captured["yara_enabled"] is False


def test_scan_service_enables_scheduler_yara_only_with_rules(tmp_path):
    captured = {}

    def fake_run_pipeline_safe(*args, **kwargs):
        captured.update(kwargs)
        return {}

    run_scan(_args(tmp_path, no_yara=False), compiled_rules=object(), scheduler_pipeline=fake_run_pipeline_safe)

    assert captured["yara_enabled"] is True
