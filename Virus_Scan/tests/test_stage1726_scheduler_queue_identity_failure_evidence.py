from Virus_Scan.scheduler.queue.integrity import (
    QUEUE_IDENTITY_COLLECTION_FAILED,
    QueueIntegrityVerificationRequest,
    collect_jobs_by_identity,
    verify_and_repair_queue_integrity,
)


class HostileQueueDir:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("queue dir truthiness must not execute")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("queue dir str must not execute")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("queue dir repr must not execute")

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("queue dir fspath must not execute")


def test_stage1726_collect_jobs_by_identity_failure_returns_evidence_without_queue_dir_hooks():
    HostileQueueDir.touched = 0
    reports = []
    queue_dir = HostileQueueDir()

    result = collect_jobs_by_identity(
        queue_dir,
        job_dirs=lambda _q: (_ for _ in ()).throw(OSError("identity scan denied")),
        safe_listdir=lambda _d: (),
        is_job_json_name=lambda _name: False,
        read_json=lambda _p, default=None: {},
        job_identity=lambda _job, name=None: "unused",
        merge_claim_meta=lambda _p, job: job,
        report=lambda stage, exc, **kw: reports.append((stage, type(exc).__name__, kw)),
    )

    assert HostileQueueDir.touched == 0
    assert result != {}
    assert QUEUE_IDENTITY_COLLECTION_FAILED in result
    record = result[QUEUE_IDENTITY_COLLECTION_FAILED][0]
    assert record["queue_identity_collection_failed"] is True
    assert record["queue_integrity_unavailable"] is True
    assert record["final_json_must_record"] is True
    assert record["job"]["queue_info"]["queue_identity_collection_failed"] is True
    assert record["queue_dir_evidence"]["queue_dir_reason"] == "scheduler_path_rejected"
    assert reports[0][0] == "queue_identity_collection_failed"
    assert reports[0][1] == "OSError"
    assert "queue_dir" not in reports[0][2].get("extra", {})
    assert reports[0][2]["extra"]["queue_dir_evidence"]["queue_dir_reason"] == "scheduler_path_rejected"


def test_stage1726_verify_integrity_marks_collection_failure_incomplete_without_quarantine(tmp_path):
    quarantined = []
    failure_groups = {
        QUEUE_IDENTITY_COLLECTION_FAILED: [
            {
                "state": "queue_identity_collection_failed",
                "path": "",
                "name": "queue_identity_collection_failed",
                "job": {"queue_info": {"queue_identity_collection_failed": True}},
                "queue_identity_collection_failed": True,
                "queue_integrity_unavailable": True,
                "final_json_must_record": True,
            }
        ]
    }

    summary = verify_and_repair_queue_integrity(QueueIntegrityVerificationRequest(
        tmp_path,
        all_files=None,
        phase="startup",
        repair=True,
        ensure_dirs=lambda _q: None,
        cleanup_diagnostic_tmp_files=lambda _q, max_age_sec=60.0: None,
        identity_collector=lambda _q: failure_groups,
        active_claim_is_protected=lambda *a, **k: False,
        quarantine_job=lambda *a, **k: quarantined.append((a, k)) or True,
        queue_now=lambda: 1.0,
        report=lambda *a, **k: None,
    ))

    assert summary["integrity_complete"] is False
    assert summary["integrity_error"] == "queue_identity_collection_failed"
    assert summary["queue_identity_collection_failed"] is True
    assert summary["queue_identity_collection_evidence"][0]["queue_identity_collection_failed"] is True
    assert summary["queue_identity_collection_evidence"][0]["queue_integrity_unavailable"] is True
    assert quarantined == []
