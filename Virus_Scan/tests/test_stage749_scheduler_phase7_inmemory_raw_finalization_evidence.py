from dataclasses import dataclass

from Virus_Scan.scheduler.workers.inmemory_raw_finalization import finalize_inmemory_raw_scan_result


@dataclass(frozen=True)
class _Plan:
    identity: dict
    effective_stage: str
    jobs: list
    file_id: str


class _Deps:
    recoverable_exceptions = (RuntimeError, ValueError, TypeError)

    def __init__(self):
        self.suppressed = []
        self.integrity = None
        self.evidence = None

    def finalize_tag_evidence_generation(self, *_args, **_kwargs):
        raise RuntimeError("tag finalization failed")

    def scanner_degraded_tags(self):
        return ["scheduler_worker_degraded"]

    def normalize_tags(self, tags):
        return list(dict.fromkeys(list(tags or [])))

    def staged_enrichment_score(self, *_args, **_kwargs):
        return 0.0, []

    def record_suppressed(self, label, exc):
        self.suppressed.append((label, type(exc).__name__))

    def set_scan_integrity(self, path, integrity):
        self.integrity = dict(integrity)

    def remember_scan_evidence(self, path, **evidence):
        self.evidence = dict(evidence)

    def record_issue(self, *_args, **_kwargs):
        raise AssertionError("record_issue should not be needed for recoverable tag finalization failure")

    def apply_integrity_tags(self, tags, integrity, marker):
        if integrity.get("had_degraded_stage"):
            return list(tags or []) + [marker]
        return list(tags or [])

    def normalize_yara_hits(self, hits):
        return list(hits or [])


def test_stage749_inmemory_raw_tag_finalization_failure_is_result_evidence():
    deps = _Deps()
    result = finalize_inmemory_raw_scan_result(
        path="raw.bin",
        pretriage_tags=["pre"],
        raw_results=[{"tags": ["raw"], "errors": []}],
        plan=_Plan(identity={"tags": ["id"]}, effective_stage="deep", jobs=[{"seq": 1}], file_id="fid"),
        deps=deps,
    )

    assert deps.suppressed == [("monitor_loop_suppressed", "RuntimeError")]
    assert deps.integrity["had_degraded_stage"] is True
    assert deps.integrity["worker_raw_finalization_failed"] is True
    assert deps.integrity["worker_raw_finalization_failures"] == ("finalize_tag_evidence_generation:RuntimeError",)
    assert "scheduler_worker_degraded" in result["tags"]
    assert "inmemory_raw_incomplete" in result["tags"]
    assert "finalize_tag_evidence_generation:RuntimeError" in result["errors"]
