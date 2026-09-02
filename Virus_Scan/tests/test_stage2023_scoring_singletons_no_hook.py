from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.calibration.analytical_bundle import (
    AnalyticalCalibrationBundleRequest,
    build_analytical_calibration_bundle,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.scoring.escalation.high_gate import high_gate_authority
from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation
from Virus_Scan.detection.scoring.full_analysis.failure_attachment import attach_failure_evidence
from Virus_Scan.detection.scoring.weighting.concrete_attack_cap import apply_no_concrete_attack_cap
from Virus_Scan.detection.scoring.weighting.filetype_model import filetype_bucket_model_signal
from Virus_Scan.detection.scoring.weighting.tag_audit import audit_tag_class
from Virus_Scan.detection.scoring.weighting.tag_entropy import tag_entropy


class HostileScoringInput:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile scoring hook")

    def __str__(self):  # pragma: no cover - failure proves hook execution
        return self._touch()

    def __repr__(self):  # pragma: no cover
        return self._touch()

    def __bool__(self):  # pragma: no cover
        return self._touch()

    def __float__(self):  # pragma: no cover
        return self._touch()

    def __iter__(self):  # pragma: no cover
        return self._touch()


def test_stage2023_scoring_singletons_reject_hostile_inputs_without_hooks() -> None:
    HostileScoringInput.reset()
    hostile = HostileScoringInput()

    capped, cap_meta = apply_no_concrete_attack_cap(hostile, evaluate_chain_evidence(tags=hostile), path="sample.exe")
    filetype = filetype_bucket_model_signal(hostile, hostile, hostile, strings_blob=hostile)

    assert capped == 0.0
    assert cap_meta is None
    assert audit_tag_class(hostile) == "unknown"
    assert tag_entropy(hostile) == 0.0
    assert 0.0 <= filetype["filetype_anomaly"] <= 1.0
    assert HostileScoringInput.touched == 0


def test_stage2023_scoring_singletons_preserve_wrapped_payload_shapes() -> None:
    bundle = build_analytical_calibration_bundle(
        AnalyticalCalibrationBundleRequest(
            path="sample.py",
            tags=normalize_tag_evidence(
                ("process_exec",), source_detector="stage2023", source_stage="calibration"
            ),
        )
    )
    explanation = build_reproducible_score_explanation(
        final_score=1.0,
        explanation="raw",
        path="sample.py",
        active_profile="other",
    )
    attached = attach_failure_evidence(
        "raw",
        ({
            "stage_name": "stage",
            "state": "degraded",
            "error_category": "RecoverableDetectionFailure",
            "error_source": "test",
            "affected_context": "",
            "confidence_degraded": True,
            "json_record_required": True,
            "replay_record_required": True,
            "fatal": False,
            "message": "msg",
        },),
    )
    high = high_gate_authority(
        evaluate_chain_evidence(tags=("encoded_powershell",)),
        tags=("encoded_powershell",),
    )

    assert bundle["lineage_id"].startswith("detection-calibration-")
    assert explanation["unstructured_explanation"] == "raw"
    assert attached["unstructured_explanation"] == "raw"
    assert high["allowed_high"] is True


def test_stage2023_scoring_singletons_source_removed_audited_patterns() -> None:
    snippets_by_file = {
        "Virus_Scan/detection/scoring/calibration/analytical_bundle.py": ('f"detection-calibration-{digest[:16]}"',),
        "Virus_Scan/detection/scoring/escalation/high_gate.py": ("allowed = bool(single or timeline_chains or explicit_hits or yara_ok or certutil_decode_authority)",),
        "Virus_Scan/detection/scoring/explainability/score_components.py": ('"legacy_explanation"',),
        "Virus_Scan/detection/scoring/full_analysis/failure_attachment.py": ("'legacy_explanation'",),
        "Virus_Scan/detection/scoring/weighting/chain_bonus.py": ("blocked.append(f'chain_boost_blocked:{name}:{reason}')",),
        "Virus_Scan/detection/scoring/weighting/concrete_attack_cap.py": ("except RECOVERABLE_RUNTIME_ERRORS:\n        return 0.0",),
        "Virus_Scan/detection/scoring/weighting/filetype_model.py": ("'filetype_anomaly': safe_clamp(score / max(1, len(tag_buckets)))",),
        "Virus_Scan/detection/scoring/weighting/tag_audit.py": ("except TAG_SCAN_RECOVERABLE_EXCEPTIONS:\n        return 'unknown'",),
        "Virus_Scan/detection/scoring/weighting/tag_entropy.py": ("for count in counts.values():",),
    }

    for file_name, snippets in snippets_by_file.items():
        source = Path(file_name).read_text(encoding="utf-8")
        assert [snippet for snippet in snippets if snippet in source] == []
