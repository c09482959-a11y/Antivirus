from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


from pathlib import Path
from unittest.mock import patch

from Virus_Scan.contracts.yara_hits import normalize_yara_hits, yara_expected_behavior
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path
from Virus_Scan.detection.scoring.weighting import contextual_expected
from Virus_Scan.detection.scoring.weighting.static_layer import compute_quick_static_layer
from Virus_Scan.detection.scoring.weighting.tag_audit import audit_tags_for_scoring
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.utils.tagging import ordered_unique_tags


class HostileText:
    def __str__(self):  # pragma: no cover - exercised through boundary calls
        raise RuntimeError("hostile text")

    def __repr__(self):  # pragma: no cover
        raise RuntimeError("hostile repr")

    def __bool__(self):  # pragma: no cover
        raise RuntimeError("hostile bool")


class HostileIterable:
    def __iter__(self):  # pragma: no cover
        raise RuntimeError("hostile iterator")

    def __bool__(self):  # pragma: no cover
        raise RuntimeError("hostile bool")


class HostileMidIteration:
    def __iter__(self):
        yield "process_exec"
        raise RuntimeError("hostile iteration tail")


class HostileNumeric:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile numeric hook")

    def __float__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __int__(self):  # pragma: no cover
        return self._touch()

    def __bool__(self):  # pragma: no cover
        return self._touch()

    def __str__(self):  # pragma: no cover
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()

    def __format__(self, spec):  # pragma: no cover
        return self._touch()


class HostileTruth:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):  # pragma: no cover - failure proves hook execution
        type(self).touched += 1
        raise RuntimeError("hostile truth hook")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("hostile iter hook")

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise RuntimeError("hostile text hook")


def test_ordered_unique_tags_records_unreadable_tag_evidence_without_crashing() -> None:
    tags = ordered_unique_tags(["process_exec", HostileText(), "process_exec"])

    assert "process_exec" in tags
    assert "tag_normalization_failure_evidence" in tags
    assert "detection_stage_degraded" in tags


def test_tag_validation_records_hostile_tag_container_and_text_evidence() -> None:
    assert validate_tags_for_path(HostileIterable(), path=HostileText(), strings_blob=HostileText(), source=HostileText()) == [
        "tag_normalization_failure_evidence",
        "tag_validation_failure_evidence",
        "detection_stage_degraded",
    ]

    mixed = validate_tags_for_path([HostileText(), "process_exec"], path=HostileText(), strings_blob=HostileText(), source=HostileText())
    assert "tag_normalization_failure_evidence" in mixed
    assert "tag_validation_failure_evidence" in mixed
    assert "detection_stage_degraded" in mixed


def test_scoring_tag_audit_and_static_layer_rejects_caller_owned_iterables_without_partial_iteration() -> None:
    audit = audit_tags_for_scoring(HostileMidIteration(), api_calls=[HostileText()])
    assert "process_exec" not in audit["behavior"]
    assert "process_exec" not in audit["scoreable"]
    assert audit["degraded"] is True
    assert audit["failure_evidence"] == ["detection_observation_unavailable"]

    static_evidence = scoreable_tag_evidence(
        HostileMidIteration(),
        allowed_evidence_kinds=frozenset({
            "observed", "normalized", "derived", "composite",
        }),
    )
    static_chains = evaluate_chain_evidence(tags=static_evidence)
    static = compute_quick_static_layer(
        static_evidence, static_chains, yara_hits=HostileIterable(),
    )
    assert static["name"] == "Layer 1 Quick Score"
    assert static["score"] >= 0.0
    assert "yara_static_evidence_degraded" in static["hits"]
    assert static["scanner_degraded"] is True


def test_yara_hit_normalization_records_hostile_inputs_without_raw_crashes() -> None:
    assert normalize_yara_hits(HostileIterable()) == ["yara_hit_normalization_failure_evidence"]
    assert "yara_hit_normalization_failure_evidence" in normalize_yara_hits(["safe_rule", HostileText()])
    assert yara_expected_behavior(HostileText()) == "rule_match_unavailable"

from Virus_Scan.detection.scoring.prefilter.fast_benign_bypass import extremely_strict_fast_benign_bypass_after_prefilter
from Virus_Scan.detection.scoring.weighting.contextual_expected import contextual_expected_behavior_signal
from Virus_Scan.detection.scoring.weighting.filetype_model import filetype_bucket_model_signal
from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence


def test_contextual_filetype_stage_and_fast_bypass_scoring_bound_hostile_inputs() -> None:
    contextual = contextual_expected_behavior_signal("other", HostileText(), HostileMidIteration(), strings_blob=HostileText())
    assert contextual["applied"] is False
    assert contextual["scanner_degraded"] is True
    assert contextual["failure_evidence"][0]["affected_context"] == "<unreadable_path>"

    filetype = filetype_bucket_model_signal("media", HostileText(), HostileMidIteration(), strings_blob=HostileText())
    assert filetype["context"]["execution_capability"] == "unknown"
    assert not any(record["tag"] == "process_exec" for record in filetype["records"])
    assert any(record["tag"] == "detection_observation_unavailable" for record in filetype["records"])

    stage_evidence = scoreable_tag_evidence(
        HostileMidIteration(),
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    stage_score, stage_hits = staged_enrichment_score(
        stage_evidence, evaluate_chain_evidence(tags=stage_evidence),
        HostileText(), asset_score=HostileText(),
    )
    assert stage_score >= 0.0
    assert isinstance(stage_hits, list)

    bypass = extremely_strict_fast_benign_bypass_after_prefilter(HostileText(), tags=HostileMidIteration(), suspicious=HostileText())
    assert bypass["force_full"] is True
    assert bypass["failure_evidence"][0]["affected_context"] == "<unreadable_path>"


def test_fast_benign_bypass_rejects_hostile_truth_inputs_without_bool_hooks() -> None:
    HostileTruth.reset()

    suspicious = extremely_strict_fast_benign_bypass_after_prefilter("sample.txt", suspicious=HostileTruth())
    yara = extremely_strict_fast_benign_bypass_after_prefilter("sample.txt", yara_hits=HostileTruth())

    assert suspicious["force_full"] is True
    assert suspicious["failure_evidence"][0]["message"] == "unsafe_fast_bypass_suspicious_rejected"
    assert yara["force_full"] is True
    assert yara["failure_evidence"][0]["message"] == "unsafe_fast_bypass_yara_hits_rejected"
    assert HostileTruth.touched == 0


def test_contextual_expected_detection_rejects_hostile_baseline_counts_without_hooks() -> None:
    HostileNumeric.reset()
    hostile = HostileNumeric()
    baseline = {"files": hostile, "tags": {"safe_tag": hostile}}
    evidence = physical_tag_evidence(("safe_tag",), source_detector="contextual_expected", source_stage="score_input")
    with patch.object(
        contextual_expected,
        "read_extension_baseline_snapshot",
        lambda _engine, _file_path: baseline,
    ):
        signal = contextual_expected.contextual_expected_behavior_signal("other", "sample.txt", evidence)

    assert signal["applied"] is False
    assert signal["scanner_degraded"] is True
    assert signal["reason"] == "unsafe_context_files_seen_rejected"
    assert signal["failure_evidence"][0]["message"] == "unsafe_context_files_seen_rejected"
    assert HostileNumeric.touched == 0


def test_contextual_expected_detection_marks_hostile_tag_count_unavailable_without_hooks() -> None:
    HostileNumeric.reset()
    hostile = HostileNumeric()
    bundle = physical_tag_evidence(("safe_tag",), source_detector="contextual_expected", source_stage="score_input")
    persisted = bundle.records[0].to_record()
    persisted["observation_count"] = hostile
    baseline = {
        "files": 30,
        "tag_evidence": {
            "records": {bundle.records[0].evidence_id: persisted},
        },
    }
    with patch.object(
        contextual_expected,
        "read_extension_baseline_snapshot",
        lambda _engine, _file_path: baseline,
    ):
        signal = contextual_expected.contextual_expected_behavior_signal("other", "sample.txt", bundle)

    assert signal["applied"] is False
    assert signal["reason"] == "no_common_non_anchor_tags"
    assert signal["records"][0]["unavailable_reason"] == "persisted_tag_observation_count_rejected"
    assert HostileNumeric.touched == 0


def test_contextual_expected_detection_source_removed_audited_hook_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/weighting/contextual_expected.py"))

    assert "return (safe_clamp(new_score, 0.0, 100.0), signal)" not in source
    assert "float(tag_counts.get(tag, 0) or 0)" not in source
    assert "'expected_ratio': safe_clamp(expected_ratio)" not in source


def test_fast_benign_bypass_source_removed_audited_hook_patterns() -> None:
    source = read_python_file(Path("Virus_Scan/detection/scoring/prefilter/fast_benign_bypass.py"))

    assert "caller compatibility exports" not in source
    assert "f'router_stage_{curr_stage}'" not in source
    assert "type(error).__name__" not in source
