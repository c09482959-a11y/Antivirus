from Virus_Scan.scheduler.orchestration.process_queue_completion import _attach_worker_exit_evidence_to_merged_results
from Virus_Scan.scheduler.orchestration.process_queue_completion_evidence import collect_nonclean_worker_exit_evidence


class HostileEvidenceMapping:
    touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("mapping get hook executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("mapping items hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("mapping iter hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("mapping repr hook executed")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("mapping str hook executed")


class HostileStatus:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("int hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("bool hook executed")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("repr hook executed")


class HostileIntegrity(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        type(self).touched += 1
        raise RuntimeError("integrity get hook executed")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("integrity items hook executed")


def test_stage1611_worker_exit_completion_rejects_hostile_evidence_without_hooks():
    HostileEvidenceMapping.touched = 0
    hostile = HostileEvidenceMapping()
    merged = {"sample.bin": {"class": "ERROR", "scan_integrity": {}}}

    _attach_worker_exit_evidence_to_merged_results(merged, (hostile,))

    assert HostileEvidenceMapping.touched == 0
    evidence = merged["sample.bin"]["scan_integrity"]["process_queue_worker_exit_evidence"]
    assert evidence[0]["process_queue_worker_exit_evidence_unavailable"] is True
    assert evidence[0]["worker_exit_evidence_rejection_reason"] == "worker_exit_evidence_mapping_rejected"
    assert evidence[0]["final_json_must_record"] is True


def test_stage1611_worker_exit_completion_rejects_hostile_status_without_numeric_hooks():
    HostileStatus.touched = 0
    evidence = ({"worker_exit_status": HostileStatus(), "worker_wait_timed_out": False, "worker_failure_markers": ()},)

    collected = collect_nonclean_worker_exit_evidence(evidence)

    assert HostileStatus.touched == 0
    assert collected
    assert collected[0]["worker_exit_status"]["unsupported_scheduler_value"] is True


def test_stage1611_worker_exit_completion_does_not_call_hostile_integrity_methods():
    HostileIntegrity.touched = 0
    merged = {"sample.bin": {"class": "ERROR", "scan_integrity": HostileIntegrity({"preserve": True})}}
    evidence = ({"worker_exit_status": -1, "worker_wait_timed_out": True, "worker_failure_markers": ("timeout",)},)

    _attach_worker_exit_evidence_to_merged_results(merged, evidence)

    assert HostileIntegrity.touched == 0
    integrity = merged["sample.bin"]["scan_integrity"]
    assert "process_queue_worker_exit_evidence" in integrity
    assert "preserve" not in integrity


def test_stage1611_worker_exit_completion_preserves_exact_dict_evidence():
    merged = {"sample.bin": {"class": "ERROR", "scan_integrity": {"existing": "yes"}}}
    evidence = ({"worker_exit_status": 4, "worker_wait_timed_out": False, "worker_failure_markers": ()},)

    _attach_worker_exit_evidence_to_merged_results(merged, evidence)

    integrity = merged["sample.bin"]["scan_integrity"]
    assert integrity["existing"] == "yes"
    assert integrity["process_queue_worker_exit_evidence"][0]["worker_exit_status"] == 4
