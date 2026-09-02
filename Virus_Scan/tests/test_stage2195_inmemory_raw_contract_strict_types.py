"""Stage2195 in-memory raw dependency contract strict-typing closure."""
from __future__ import annotations

from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation

import ast
from pathlib import Path

from Virus_Scan.scheduler.contracts.inmemory_raw import InMemoryRawScanDependencies
from Virus_Scan.scheduler.workers.inmemory_raw_plan import build_inmemory_raw_plan_decision

SOURCE = Path("Virus_Scan/scheduler/contracts/inmemory_raw.py")


def test_stage2195_inmemory_raw_dependency_contract_exports_no_any_annotations() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    any_names = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "Any"]
    assert any_names == []
    assert "typing import Any" not in source
    assert "Callable[...," not in source


def test_stage2195_inmemory_raw_dependency_contract_keeps_slots_and_runtime_plan_path() -> None:
    calls: list[tuple[str, object]] = []

    deps = InMemoryRawScanDependencies(
        deep_scan_thorough=lambda: False,
        sniff_file_identity=lambda _path: {"tags": ("identity",)},
        get_scan_extension=lambda _path: ".bin",
        runtime_value=lambda _name, default: default,
        normalize_stage=lambda _ext: "binary",
        choose_effective_stage=lambda _stage, _identity: "binary",
        global_raw_eligible=lambda _path, *, effective_stage: effective_stage == "binary",
        global_raw_file_id=lambda _path: "fid",
        build_raw_stage_jobs=lambda _path, _file_id, _effective, _ext_stage, _identity, *, deps: (
            {"seq": 1},
            {"seq": 2},
        ),
        raw_stage_job_build_dependencies=lambda: object(),
        execute_stage_job=lambda job: {"ok": True, "job": job},
        scheduler_thread_pool=lambda *, max_workers, thread_name_prefix: object(),
        environ_get=lambda _name, default: default,
        record_issue=lambda issue, exc, fatal=False, extra=None: calls.append((issue, type(exc).__name__)),
        scanner_degraded_tags=lambda: ("degraded",),
        finalize_tag_evidence_generation=finalize_tag_evidence_generation,
        normalize_tags=lambda tags: tuple(tags) if isinstance(tags, (list, tuple)) else (tags,),
        staged_enrichment_score=lambda _tags, _stage, _score: (0.0, ()),
        record_suppressed=lambda label, exc: calls.append((label, type(exc).__name__)),
        set_scan_integrity=lambda _path, _integrity: None,
        remember_scan_evidence=lambda _path, **_evidence: None,
        apply_integrity_tags=lambda tags, _integrity, marker="inmemory_raw_incomplete": tuple(tags),
        normalize_yara_hits=lambda hits: tuple(hits) if isinstance(hits, (list, tuple)) else (),
        log_error=lambda message: calls.append(("log_error", message)),
        recoverable_exceptions=(RuntimeError, ValueError, TypeError, OSError, UnicodeError),
        now=lambda: 10.0,
    )

    assert not hasattr(deps, "__dict__")
    decision = build_inmemory_raw_plan_decision(
        path="sample.bin",
        timeout_sec=1,
        pretriage_tags=("force",),
        pretriage_suspicious=False,
        pretriage_stage=None,
        deps=deps,
    )
    assert decision.reason == "inmemory_raw_plan_available"
    assert decision.plan is not None
    assert decision.plan.file_id == "fid"
    assert calls == []
