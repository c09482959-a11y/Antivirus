from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEDULER = ROOT / "scheduler"


def test_stage835_state_io_queue_boundary_module_is_restored():
    path = SCHEDULER / "queue" / "state_io.py"
    assert path.exists(), "queue/state_io.py is an existing Phase 6 queue boundary module and must not be deleted"
    source = path.read_text(encoding="utf-8")
    assert "def read_queue_json_file" in source
    assert "QUEUE_STATE_READ_EXCEPTIONS" in source


def test_stage835_removed_surfaces_remain_dead_after_state_io_restore():
    removed = (
        SCHEDULER / "ownership" / "claim_registry.py",
        SCHEDULER / "runtime" / "resource_limits.py",
        SCHEDULER / "runtime" / "freeze_runtime.py",
        SCHEDULER / "api" / "public_results.py",
        SCHEDULER / "execution" / "stage_parallel.py",
        SCHEDULER / "internal" / "validation.py",
        SCHEDULER / "ownership" / "claim_validation.py",
        SCHEDULER / "queue" / "inmemory_retry_recovery_evidence.py",
        SCHEDULER / "queue" / "raw_queue_monitor.py",
    )
    for path in removed:
        assert not path.exists(), f"dead scheduler surface still present: {path}"
