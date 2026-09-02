from __future__ import annotations

import errno

from Virus_Scan.runtime import detector_state, scan_run_guard, structured_failures


class _Telemetry:
    def event(self, *args, **kwargs):
        return None


def test_stage2076_detector_exception_args_use_explicit_probe() -> None:
    probe = detector_state._detector_exception_args(ValueError("boom"))
    assert probe.args == ("boom",)
    assert probe.unavailable_reason == ""

    rejected = detector_state._detector_exception_args(Exception("custom"))
    assert rejected.args == ()
    assert rejected.unavailable_reason == "detector_error_type_rejected"


def test_stage2076_pid_probe_records_explicit_dead_and_degraded_evidence() -> None:
    def missing_process(pid: int, sig: int) -> None:
        raise ProcessLookupError("missing")

    missing = scan_run_guard._pid_probe(999999, kill_probe=missing_process)
    assert missing.alive is False
    assert missing.evidence == "parent_scan_guard_pid_not_found"

    def esrch(pid: int, sig: int) -> None:
        err = OSError("esrch")
        err.errno = errno.ESRCH
        raise err

    probe = scan_run_guard._pid_probe(999999, kill_probe=esrch)
    assert probe.alive is False
    assert probe.evidence == "parent_scan_guard_pid_esrch"

    def permission_denied(pid: int, sig: int) -> None:
        raise PermissionError("denied")

    degraded = scan_run_guard._pid_probe(999999, kill_probe=permission_denied)
    assert degraded.alive is True
    assert degraded.evidence == "parent_scan_guard_pid_permission_denied"


def test_stage2076_telemetry_callback_lookup_uses_explicit_probe() -> None:
    ok = structured_failures._telemetry_event_callback(_Telemetry())
    assert ok.callback is _Telemetry.event
    assert ok.unavailable_reason == ""

    def broken_getattr_static(owner: type, name: str, default: object = None) -> object:
        raise TypeError("lookup blocked")

    unavailable = structured_failures._telemetry_event_callback(
        _Telemetry(),
        static_lookup=broken_getattr_static,
    )
    assert unavailable.callback is None
    assert unavailable.unavailable_reason == "failure_telemetry_callback_lookup_failed"
    assert any(
        "failure_telemetry_callback_lookup" in item
        for item in structured_failures.failure_recorder_internal_errors()
    )
