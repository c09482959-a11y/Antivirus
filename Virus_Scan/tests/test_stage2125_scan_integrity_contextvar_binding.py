from __future__ import annotations

from Virus_Scan.runtime.scan_integrity_state import RuntimeScanIntegrityState


def test_stage2125_scan_integrity_state_clear_all_invalidates_entries() -> None:
    state = RuntimeScanIntegrityState()
    state.set("sample", {"status": "ok"})
    assert state.get("sample") == {"status": "ok"}

    state.clear_all()

    assert state.get("sample") == {}

    state.set("sample", {"status": "new"})
    assert state.get("sample") == {"status": "new"}
