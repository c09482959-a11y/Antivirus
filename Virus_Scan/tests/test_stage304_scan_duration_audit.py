from Virus_Scan.scheduler.api.runner import run_pipeline_safe


def test_stage304_scheduler_records_per_file_scan_duration(tmp_path):
    sample = tmp_path / "clean.txt"
    sample.write_text("hello benign world", encoding="utf-8")
    results = run_pipeline_safe(
        str(tmp_path),
        compiled_rules=None,
        scheduler="serial",
        max_workers=0,
        max_files=1,
        freeze_existing_baselines=False,
        defer_profile_flush=True,
        slow_file_warn_sec=999.0,
    )
    record = results[str(sample)]
    assert "scan_duration_seconds" in record
    assert isinstance(record["scan_duration_seconds"], (int, float))
    assert record["scan_duration_seconds"] >= 0
