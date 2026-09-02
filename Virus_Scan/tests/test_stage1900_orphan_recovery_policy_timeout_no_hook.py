from __future__ import annotations

import Virus_Scan.scheduler.queue.orphan_recovery_timeout_evidence as evidence_module
from Virus_Scan.scheduler.queue.orphan_recovery_policy import load_queue_reclaim_policy
from Virus_Scan.scheduler.queue.orphan_recovery_timeout import classify_reclaim_timeout
from Virus_Scan.scheduler.queue.orphan_recovery_timeout_evidence import (
    resolve_reclaim_float_value,
    resolve_reclaim_int_value,
)


class HostileNumeric:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileJobText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str job text")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr job text")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not bool job text")


class HostileProbeError(RuntimeError):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str exception")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr exception")


class HostileQueueDir:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str queue")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr queue")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath queue")


def test_stage1900_policy_values_reject_hostile_numbers_without_hooks():
    HostileNumeric.touched = 0
    hostile = HostileNumeric()

    policy = load_queue_reclaim_policy(
        stale_sec=hostile,
        max_retries=hostile,
        progress_stall_sec=hostile,
        per_file_timeout_sec=hostile,
    )

    assert HostileNumeric.touched == 0
    assert policy.stale == 300.0
    assert policy.retries == 0
    assert policy.progress_stall == 300.0
    assert policy.file_timeout == 300.0
    reasons = {record["reason"] for record in policy.evidence}
    assert "queue_reclaim_stale_sec_malformed" in reasons
    assert "queue_reclaim_max_retries_malformed" in reasons
    assert "queue_reclaim_progress_stall_sec_malformed" in reasons
    assert "queue_reclaim_per_file_timeout_sec_malformed" in reasons


def test_stage1900_resolvers_are_owned_policy_apis_without_legacy_safe_exports():
    assert not hasattr(evidence_module, "safe_reclaim_float")
    assert not hasattr(evidence_module, "safe_reclaim_int")
    assert evidence_module.__all__[-2:] == ("resolve_reclaim_float_value", "resolve_reclaim_int_value")

    evidence = []
    hostile = HostileNumeric()
    HostileNumeric.touched = 0
    assert resolve_reclaim_float_value(value=hostile, field="example_float", default_value=12.5, evidence=evidence) == 12.5
    assert resolve_reclaim_int_value(value=hostile, field="example_int", default_value=3, evidence=evidence) == 3
    assert HostileNumeric.touched == 0
    assert {record["reason"] for record in evidence} == {"example_float_malformed", "example_int_malformed"}


def test_stage1900_timeout_job_text_and_probe_error_do_not_execute_hooks():
    HostileJobText.touched = 0
    HostileProbeError.touched = 0
    HostileQueueDir.touched = 0

    def raw_stage_progress_recent(_queue_dir, quiet_sec=None):
        raise HostileProbeError("probe")

    decision = classify_reclaim_timeout(
        job={"file": HostileJobText(), "job_type": HostileJobText(), "recursion_depth": 0},
        queue_dir=HostileQueueDir(),
        claim_age=500.0,
        progress_age=500.0,
        hb_age=500.0,
        heartbeat_fresh=False,
        pid_alive=False,
        stale=300.0,
        file_timeout=1.0,
        progress_stall=60.0,
        timeout_expired=True,
        checkpoint_stalled=True,
        raw_stage_progress_recent=raw_stage_progress_recent,
    )

    assert HostileJobText.touched == 0
    assert HostileProbeError.touched == 0
    assert HostileQueueDir.touched == 0
    assert decision.timeout_expired is True
    assert decision.timeout_evidence["raw_global_progress_probe_failed"] is True
    probe_evidence = decision.timeout_evidence["raw_global_progress_probe_evidence"]
    assert probe_evidence["detail"] == "raw_progress_probe_failed"
    assert probe_evidence["queue_dir_type"] == "HostileQueueDir"
