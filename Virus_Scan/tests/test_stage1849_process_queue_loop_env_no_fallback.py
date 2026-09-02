"""Stage 1849: queue-child env parsing has one active scalar route."""
from __future__ import annotations

from pathlib import Path


def test_stage1849_process_queue_loop_source_has_no_scheduler_fallback_scalar_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scheduler/execution/process_queue_loop.py").read_text(encoding="utf-8")
    config_source = (root / "scheduler/execution/process_queue_loop_config.py").read_text(encoding="utf-8")

    for checked_source in (source, config_source):
        for forbidden in (
            "fallback=",
            "scheduler_int(",
            "scheduler_float(",
            "scheduler_text(",
        ):
            assert forbidden not in checked_source

    assert "no_hook_text(" in config_source
    assert "_queue_child_env_value" in config_source
    assert "_queue_child_env_value" in source
    for checked_source in (source, config_source):
        for obsolete in (
            "parse_queue_child_output_buffer",
            "QueueChildOutputBufferConfigDecision",
            "QueueChildScalarDecision",
            "_queue_child_exact_int_text",
            "_queue_child_exact_float_text",
            "UMIGE_IO_MEMORY_FLUSH",
            "io_memory_flush",
        ):
            assert obsolete not in checked_source


def test_stage1849_process_queue_runner_and_setup_sources_close_adjacent_fallback_rows() -> None:
    root = Path(__file__).resolve().parents[1]
    runner_source = (root / "scheduler/execution/process_queue_runner.py").read_text(encoding="utf-8")
    setup_source = (root / "scheduler/execution/process_queue_setup.py").read_text(encoding="utf-8")
    support_source = (root / "scheduler/execution/process_queue_setup_support.py").read_text(encoding="utf-8")

    for source in (runner_source, setup_source, support_source):
        for forbidden in (
            "fallback=",
            "scheduler_int(",
            "scheduler_float(",
        ):
            assert forbidden not in source

    assert "scheduler_minimum_int" in runner_source
    assert "scheduler_minimum_int" in setup_source
    assert "process_queue_setup_log_message" in setup_source
    assert "process_queue_setup_log_message" in support_source
    assert "float.__format__(cpu_sample" in support_source
    assert 'f"bulk scan dynamic queue feed' not in setup_source
    assert 'return f"{cpu_sample:.1f}%"' not in support_source
