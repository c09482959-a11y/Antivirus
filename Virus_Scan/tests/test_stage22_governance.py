import pytest

from Virus_Scan.runtime.structured_failures import record_suppressed_failure, failure_snapshot
from Virus_Scan.scheduler.queue.admission import build_workload_classification_plan
from Virus_Scan.scheduler.queue.admission_fairness import weighted_fair_interleave
from Virus_Scan.runtime.resource_quotas import RuntimeBudget, ResourceQuotaExceeded
from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.heuristics import evaluate_script_execution, evaluate_downloader_behavior


def test_structured_failure_records_visible():
    tag = record_suppressed_failure("unit", ValueError("bad"), domain="parse", tags=[])
    assert tag.startswith("failure_parse")
    assert failure_snapshot()["records"]


def test_weighted_fair_interleave_keeps_light_work_first():
    files=["a.zip", "b.zip", "c.dll", "d.png", "e.txt", "f.ps1"]
    out=weighted_fair_interleave(build_workload_classification_plan(files).targets)
    ordered = [target.path for target in out]
    assert sorted(ordered)==sorted(files)
    assert ordered[0] in {"d.png", "e.txt", "f.ps1"}


def test_runtime_budget_hard_limits():
    b = RuntimeBudget(max_descendants=1)
    b.reserve_descendant(1)

    with pytest.raises(ResourceQuotaExceeded, match="runtime_descendant_limit"):
        b.reserve_descendant(1)


def test_heuristic_registry_publishes_atomic_tags_and_canonical_chain_evidence():
    result = evaluate_script_execution("powershell -enc AAAA")
    assert "encoded_powershell" in result["tags"]
    assert "process_exec" in result["tags"]
    assert "encoded_powershell_execution_chain" not in result["tags"]
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(result["tags"])))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:encoded_powershell_weak"
    )
    assert decision.status == "confirmed"
    downloader = evaluate_downloader_behavior("DownloadString(http://x); IEX")
    assert "remote_payload_download" in downloader["tags"]
