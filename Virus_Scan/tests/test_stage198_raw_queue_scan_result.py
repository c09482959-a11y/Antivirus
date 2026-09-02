from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.scanners.raw_queue_scan_result import RawQueueScanResultDependencies, build_global_raw_scan_result


def _deps(events):
    def mark(path, integrity, **kwargs):
        integrity = dict(integrity)
        integrity[kwargs.get("marker", "marked")] = True
        return integrity

    return RawQueueScanResultDependencies(
        ordered_unique_tags=lambda tags: list(dict.fromkeys(tags)),
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        apply_integrity_tags=lambda tags, integrity, marker: list(tags) + ([marker] if integrity.get("had_degraded_stage") else []),
        normalize_tags=lambda tags: list(dict.fromkeys(tags or [])),
        staged_enrichment_score=lambda tags, stage, base: (12.5, ["x"]),
        scanner_degraded_tags=lambda tags=None: list(tags or []) + ["scanner_degraded"],
        mark_raw_integrity_failure=mark,
        remember_scan_evidence=lambda path, **kwargs: events.append((path, kwargs)),
        normalize_yara_hits=lambda hits: list(hits or []),
        set_scan_integrity=lambda path, integrity: events.append(("integrity", dict(integrity))),
    )


def test_build_global_raw_scan_result_sets_integrity_and_evidence():
    events = []
    result = build_global_raw_scan_result(
        path="sample.bin",
        file_id="fid",
        accum={"expected": 2, "completed": 2, "failed": 0, "tags": ["a", "a"], "strings_parts": ["x"], "yara_hits": ["hit"], "effective_stage": "binary"},
        identity={"tags": []},
        effective_stage="binary",
        deps=_deps(events),
    )
    assert result["file_id"] == "fid"
    assert result["scan_integrity"]["missing_chunks"] == 0
    assert "staged_detection" in result["tags"]
    assert ("integrity", {"raw_expected": 2, "raw_completed": 2, "missing_chunks": 0, "raw_failed": 0, "raw_retried": 0, "had_degraded_stage": False}) in events
    assert any(e[0] == "sample.bin" for e in events)


def test_build_global_raw_scan_result_degrades_on_evidence_failure():
    events = []
    deps = _deps(events)
    deps = RawQueueScanResultDependencies(
        **{**deps.__dict__, "remember_scan_evidence": lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))}
    )
    result = build_global_raw_scan_result(
        path="sample.bin",
        file_id="fid",
        accum={"expected": 1, "completed": 0, "failed": 1, "tags": [], "strings_parts": []},
        identity={"tags": ["extension_mismatch"]},
        effective_stage="other",
        deps=deps,
    )
    assert result["suspicious"] is True
    assert result["scan_integrity"]["raw_evidence_record_failed"] is True
    assert "scanner_degraded" in result["tags"]
