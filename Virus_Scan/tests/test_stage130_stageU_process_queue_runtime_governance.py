from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "scheduler" / "queue" / "claim.py"


def test_stage130_process_queue_runtime_install_surface_removed():
    source = ROOT.read_text(encoding="utf-8")
    assert "class ProcessQueueRuntime" not in source
    assert "bind_process_queue_state_runtime" not in source
    assert "_process_queue_runtime_snapshot" not in source


def test_stage130_process_queue_uses_direct_canonical_helpers():
    source = ROOT.read_text(encoding="utf-8")
    assert "globals()" not in source
    assert "importlib" not in source
    assert ("sys" + "." + "modules") not in source
