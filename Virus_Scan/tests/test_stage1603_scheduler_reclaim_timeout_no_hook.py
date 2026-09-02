from __future__ import annotations

from Virus_Scan.scheduler.queue.orphan_recovery_timeout import classify_reclaim_timeout


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


class HostileJobMapping:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not getitem")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileQueueDir:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not str queue_dir")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr queue_dir")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")


def test_stage1603_reclaim_timeout_rejects_hostile_numeric_policy_without_hooks():
    HostileNumeric.touched = 0
    hostile = HostileNumeric()

    decision = classify_reclaim_timeout(
        job={"file": "", "job_type": "file", "recursion_depth": hostile},
        queue_dir="queue",
        claim_age=hostile,
        progress_age=hostile,
        hb_age=hostile,
        heartbeat_fresh=True,
        pid_alive=True,
        stale=hostile,
        file_timeout=hostile,
        progress_stall=hostile,
        timeout_expired=False,
        checkpoint_stalled=False,
        raw_stage_progress_recent=lambda _queue_dir, quiet_sec=None: False,
    )

    assert HostileNumeric.touched == 0
    evidence = decision.timeout_evidence
    assert evidence["reclaim_timeout_policy_failed"] is True
    reasons = {item["reason"] for item in evidence["reclaim_timeout_policy_evidence"]}
    assert "file_timeout_malformed" in reasons
    assert "progress_stall_malformed" in reasons
    assert "stale_malformed" in reasons
    assert "claim_age_malformed" in reasons
    assert "progress_age_malformed" in reasons
    assert "hb_age_malformed" in reasons
    assert "recursion_depth_malformed" in reasons


def test_stage1603_reclaim_timeout_rejects_hostile_job_mapping_without_hooks():
    HostileJobMapping.touched = 0

    decision = classify_reclaim_timeout(
        job=HostileJobMapping(),
        queue_dir="queue",
        claim_age=1.0,
        progress_age=1.0,
        hb_age=1.0,
        heartbeat_fresh=True,
        pid_alive=True,
        stale=300.0,
        file_timeout=300.0,
        progress_stall=300.0,
        timeout_expired=False,
        checkpoint_stalled=False,
        raw_stage_progress_recent=lambda _queue_dir, quiet_sec=None: False,
    )

    assert HostileJobMapping.touched == 0
    evidence = decision.timeout_evidence
    assert evidence["reclaim_timeout_policy_failed"] is True
    reasons = {item["reason"] for item in evidence["reclaim_timeout_policy_evidence"]}
    assert "job_record_malformed" in reasons


def test_stage1603_reclaim_timeout_raw_probe_failure_rejects_hostile_queue_dir_text():
    HostileQueueDir.touched = 0

    def raw_stage_progress_recent(_queue_dir, quiet_sec=None):
        raise RuntimeError("probe failed")

    decision = classify_reclaim_timeout(
        job={"file": "", "job_type": "file"},
        queue_dir=HostileQueueDir(),
        claim_age=1.0,
        progress_age=1.0,
        hb_age=1.0,
        heartbeat_fresh=True,
        pid_alive=True,
        stale=300.0,
        file_timeout=300.0,
        progress_stall=300.0,
        timeout_expired=False,
        checkpoint_stalled=False,
        raw_stage_progress_recent=raw_stage_progress_recent,
    )

    assert HostileQueueDir.touched == 0
    evidence = decision.timeout_evidence["raw_global_progress_probe_evidence"]
    assert evidence["queue_dir_type"] == "HostileQueueDir"
    assert evidence["detail"] == "raw_progress_probe_failed"
