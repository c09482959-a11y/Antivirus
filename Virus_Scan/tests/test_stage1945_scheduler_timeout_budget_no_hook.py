from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path
import zipfile

from Virus_Scan.scheduler.timeout.timeout_budget import TimeoutBudget, compute_timeout_budget
from Virus_Scan.scheduler.timeout.timeout_budget_policy import TimeoutBudgetPolicyRequest, compute_timeout_budget_policy
from Virus_Scan.scheduler.timeout.timeout_budget_workload import safe_file_size_with_error


class HostileBudgetValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("no bool")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("no float")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("no int")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("no str")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("no repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("no format")


class ProbeMustNotRun:
    called = 0

    def __call__(self, path):
        type(self).called += 1
        raise RuntimeError("probe must not run")


def _reset() -> None:
    HostileBudgetValue.touched = 0
    ProbeMustNotRun.called = 0


def test_stage1945_timeout_budget_evidence_rejects_hostile_fields_without_hooks() -> None:
    _reset()
    hostile = HostileBudgetValue()
    budget = TimeoutBudget(
        workload_class=hostile,
        method=hostile,
        hard_timeout_seconds=hostile,
        stall_timeout_seconds=hostile,
        heartbeat_stale_seconds=hostile,
        file_size=hostile,
        compressed_size=hostile,
        estimated_uncompressed_size=hostile,
        archive_member_count=hostile,
        largest_member_size=hostile,
        compression_ratio=hostile,
        recursion_depth=hostile,
        nested_archive_count=hostile,
        deep_scan=hostile,
        image_pixels=hostile,
        inspection_error=hostile,
    )

    evidence = budget.as_evidence()

    assert evidence["workload_class"] == "generic_scan"
    assert evidence["scan_method"] == "generic_scan"
    assert evidence["timeout_budget"] == 0.0
    assert evidence["file_size"] == 0
    assert evidence["inspection_error"] is None
    assert HostileBudgetValue.touched == 0


def test_stage1945_compute_timeout_budget_rejects_caller_owned_size_probe(tmp_path: Path) -> None:
    _reset()
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"payload")
    probe = ProbeMustNotRun()

    budget = compute_timeout_budget(payload, configured_timeout_seconds=10, file_size_probe=probe)
    evidence = budget.as_evidence()

    assert budget.file_size == 0
    assert "scheduler_file_size_probe_rejected" in (budget.inspection_error or "")
    assert evidence["final_json_must_record"] is True
    assert ProbeMustNotRun.called == 0


def test_stage1945_safe_file_size_rejects_noncanonical_probe_without_calling_it() -> None:
    _reset()
    probe = ProbeMustNotRun()

    size, error = safe_file_size_with_error("payload.bin", getsize=probe)

    assert size == 0
    assert error == "scheduler_file_size_probe_rejected"
    assert ProbeMustNotRun.called == 0


def test_stage1945_timeout_budget_policy_rejects_hostile_request_fields_without_hooks() -> None:
    _reset()
    hostile = HostileBudgetValue()
    output = compute_timeout_budget_policy(
        TimeoutBudgetPolicyRequest(
            workload=hostile,
            file_size_mb=hostile,
            expanded_size_mb=hostile,
            largest_member_mb=hostile,
            archive_member_count=hostile,
            compression_ratio=hostile,
            recursion_depth=hostile,
            nested_archive_count=hostile,
            image_pixels=hostile,
            inspection_error=hostile,
            deep_scan=hostile,
            configured_floor=hostile,
        ),
        clamp_hard_budget=lambda value: value,
    )

    assert output.hard_timeout_seconds >= 120.0
    assert output.stall_timeout_seconds >= 45.0
    assert HostileBudgetValue.touched == 0


def test_stage1945_timeout_budget_uses_exact_metric_reads(tmp_path: Path) -> None:
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nested.bin", b"x" * 128)

    budget = compute_timeout_budget(archive, configured_timeout_seconds=10)
    evidence = budget.as_evidence()

    assert budget.workload_class == "archive"
    assert evidence["archive_member_count"] == 1
    assert evidence["estimated_uncompressed_size"] == 128
    assert evidence["compression_ratio"] is not None


def test_stage1945_timeout_budget_source_keeps_no_legacy_fallback_or_raw_metric_gets() -> None:
    budget_source = read_python_file(Path("Virus_Scan/scheduler/timeout/timeout_budget.py"))
    policy_source = read_python_file(Path("Virus_Scan/scheduler/timeout/timeout_budget_policy.py"))
    workload_source = read_python_file(Path("Virus_Scan/scheduler/timeout/timeout_budget_workload.py"))
    inspection_source = read_python_file(Path("Virus_Scan/scheduler/timeout/timeout_workload_inspection.py"))

    assert "fallback=" not in budget_source
    assert ".get(" not in budget_source
    assert "safe_file_size_with_error(path, getsize=file_size_probe)" not in budget_source
    assert "float(request.file_size_mb or 0.0)" not in policy_source
    assert "float(request.expanded_size_mb or 0.0)" not in policy_source
    assert "float(request.largest_member_mb or 0.0)" not in policy_source
    assert "float(request.compression_ratio or 0.0)" not in policy_source
    assert "int(request.archive_member_count or 0)" not in policy_source
    assert "int(request.recursion_depth or 0)" not in policy_source
    assert "int(request.nested_archive_count or 0)" not in policy_source
    assert "float(request.image_pixels or 0)" not in policy_source
    assert " or 0" not in policy_source
    assert "f\"scheduler_path_rejected" not in workload_source
    assert "int(info.file_size or 0)" not in inspection_source
    assert "int(member.size or 0)" not in inspection_source
    assert "f\"archive_path_unavailable:" not in inspection_source
