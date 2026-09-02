from Virus_Scan.scanners.api.filetype_policy_contracts import ENGINE_SPECIFIC_FILETYPE_BUCKETS
from Virus_Scan.stress.forensic_corpus_synthesis import (
    ARCHIVE_FILE_TYPE_EXTENSIONS,
    DEEP_SCAN_CONFIGURATION,
    ENGINE_ANCHOR_FILENAMES,
    FAST_PATH_CONFIGURATION,
    OFFICE_FILE_TYPE_EXTENSIONS,
    PE_FILE_TYPE_EXTENSIONS,
    SCRIPT_FILE_TYPE_EXTENSIONS,
    coverage_summary,
    engine_file_type_contracts,
    synthesize_10000_stress_plan,
)


def _registry_extensions() -> set[tuple[str, str]]:
    required: set[tuple[str, str]] = set()
    for engine, buckets in ENGINE_SPECIFIC_FILETYPE_BUCKETS.items():
        for policy in buckets.values():
            for ext in policy.get("extensions", ()):  # registry-owned file type list
                normalized = str(ext).lstrip(".")
                required.add((engine, normalized if normalized.startswith(".") else f".{normalized}"))
    return required


def test_stage643_synthesis_covers_all_registry_engine_filetypes() -> None:
    contracts = engine_file_type_contracts()
    covered = {(contract.engine, contract.extension) for contract in contracts}
    assert _registry_extensions() <= covered


def test_stage643_synthesis_builds_balanced_10000_case_plan() -> None:
    plan = synthesize_10000_stress_plan()
    summary = coverage_summary(plan)
    assert plan.total_samples == 10_000
    assert plan.benign_samples == 5_000
    assert plan.malicious_samples == 5_000
    assert len(plan.cases) == 10_000
    assert sum(1 for case in plan.cases if case.classification == "benign") == 5_000
    assert sum(1 for case in plan.cases if case.classification == "malicious") == 5_000
    assert {"renpy", "rpgm", "unity", "generic"} <= set(summary["engines"])


def test_stage643_synthesis_covers_script_pe_office_archive_and_engine_specific_configs() -> None:
    plan = synthesize_10000_stress_plan()
    extensions = {case.extension for case in plan.cases}
    assert set(SCRIPT_FILE_TYPE_EXTENSIONS) <= extensions
    assert set(PE_FILE_TYPE_EXTENSIONS) <= extensions
    assert set(OFFICE_FILE_TYPE_EXTENSIONS) <= extensions
    assert set(ARCHIVE_FILE_TYPE_EXTENSIONS) <= extensions
    assert FAST_PATH_CONFIGURATION["path"] == "fast"
    assert FAST_PATH_CONFIGURATION["replay_checkpoint_generation"] is True
    assert DEEP_SCAN_CONFIGURATION["path"] == "deep"
    assert DEEP_SCAN_CONFIGURATION["recursive_archives"] is True
    assert DEEP_SCAN_CONFIGURATION["nested_archives"] is True
    assert DEEP_SCAN_CONFIGURATION["yara"] is True
    assert DEEP_SCAN_CONFIGURATION["yara_light"] is True
    assert DEEP_SCAN_CONFIGURATION["full_evidence_generation"] is True


def test_stage643_synthesis_includes_worker_queue_restart_timeout_archive_matrices() -> None:
    case = synthesize_10000_stress_plan().cases[0]
    assert case.worker_matrix == (1, 2, 4, 8, "max_configured")
    assert "max_configured" in case.queue_depth_matrix
    assert "during_json_write" in case.restart_point_matrix
    assert "forced_timeout" in case.timeout_pressure_matrix
    assert 8 in case.archive_depth_matrix
    assert "seeded_shuffle" in case.scan_order_matrix


def test_stage644_synthesis_includes_every_engine_anchor_filename() -> None:
    plan = synthesize_10000_stress_plan()
    paths = {case.relative_path for case in plan.cases}
    for anchors in ENGINE_ANCHOR_FILENAMES.values():
        assert set(anchors) <= paths


def test_stage645_synthesis_declares_json_persistence_artifacts_and_zero_loss_invariants() -> None:
    plan = synthesize_10000_stress_plan()
    contract = plan.json_persistence_contract
    assert contract.fast_path_artifacts == (
        "fast_path_results.json",
        "fast_path_replay_results.json",
        "fast_path_forensic_audit.json",
    )
    assert contract.deep_scan_artifacts == (
        "deep_scan_results.json",
        "deep_scan_replay_results.json",
        "deep_scan_forensic_audit.json",
    )
    assert contract.cross_path_artifacts == ("cross_path_comparison.json",)
    assert contract.persistence_counters == (
        "generated_results",
        "reconciled_results",
        "serialized_results",
        "written_results",
        "replay_recovered_results",
    )
    assert dict(contract.zero_loss_requirements) == {
        "missing_results": 0,
        "duplicate_results": 0,
        "serialization_mismatches": 0,
        "replay_mismatches": 0,
        "json_corruption_events": 0,
        "failed_persistence_events": 0,
    }
