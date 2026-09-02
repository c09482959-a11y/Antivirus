"""Stage2101: deleted queue-child output buffering remains unreachable."""
from __future__ import annotations

from pathlib import Path


def test_stage2101_deleted_queue_child_output_buffer_config_is_unreachable() -> None:
    root = Path(__file__).resolve().parents[1]
    sources = {
        "loop_config": (root / "scheduler/execution/process_queue_loop_config.py").read_text(encoding="utf-8"),
        "child_mode": (root / "scheduler/orchestration/process_queue_child_mode.py").read_text(encoding="utf-8"),
        "resource_priority": (root / "scheduler/runtime/resource_priority.py").read_text(encoding="utf-8"),
        "publication_contracts": (
            root / "scheduler/workers/child_result_publication_contracts.py"
        ).read_text(encoding="utf-8"),
    }
    obsolete = (
        "output_buffer",
        "WorkerOutputBuffer",
        "QueueChildOutputBuffer",
        "parse_queue_child_output_buffer",
        "UMIGE_IO_MEMORY_FLUSH",
        "io_memory_flush",
        "_queue_child_exact_int_text",
        "_queue_child_exact_float_text",
        "queue_child_env_int",
        "queue_child_env_float",
    )

    violations = [
        (owner, token)
        for owner, source in sources.items()
        for token in obsolete
        if token in source
    ]

    assert violations == []
    assert "_queue_child_env_value" in sources["loop_config"]
    assert "no_hook_text(" in sources["loop_config"]
