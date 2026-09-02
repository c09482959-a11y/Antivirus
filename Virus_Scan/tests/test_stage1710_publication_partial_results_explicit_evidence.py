import json
from pathlib import Path

from Virus_Scan.publication.json_finalization.partial_results import (
    PARTIAL_RECOVERY_EVIDENCE_KEY,
    load_partial_results,
    recover_results_from_partial,
)


class HostilePartialPath:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("partial result path string hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("partial result path repr hook executed")


def test_stage1710_load_partial_results_rejects_hostile_path_without_hooks():
    HostilePartialPath.touched = 0

    result = load_partial_results(HostilePartialPath())

    assert HostilePartialPath.touched == 0
    evidence = result[PARTIAL_RECOVERY_EVIDENCE_KEY]
    assert evidence["partial_result_recovery_failed"] is True
    assert evidence["reason"] == "partial_result_path_rejected"
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_record"] is True


def test_stage1710_non_mapping_partial_result_emits_explicit_recovery_evidence(tmp_path: Path):
    output = tmp_path / "scan_results.json"
    Path(str(output) + ".partial").write_text(json.dumps(["not", "a", "mapping"]), encoding="utf-8")

    result = recover_results_from_partial(str(output), {"current": {"classification": "clean"}})

    assert result["current"] == {"classification": "clean"}
    evidence = result[PARTIAL_RECOVERY_EVIDENCE_KEY]
    assert evidence["partial_result_recovery_failed"] is True
    assert evidence["reason"] == "partial_result_not_mapping"
    assert evidence["error_category"] == "partial_result_recovery_failed"
    assert evidence["error_source"] == "publication.json_finalization.partial_results"


def test_stage1710_missing_partial_result_remains_legitimate_empty_absence(tmp_path: Path):
    output = tmp_path / "scan_results.json"

    assert load_partial_results(str(output)) == {}
