import ast
from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.full_analysis.cap_inputs import apply_score_caps
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence

_CAP_INPUTS_PATH = Path("Virus_Scan/detection/scoring/full_analysis/cap_inputs.py")


def _base_kwargs(**overrides):
    kwargs = {
        "score_val": 72.0,
        "explanation": {"base": "stage1117"},
        "path": "game/script.rpyc",
        "tags": normalize_tag_evidence(("renpy_bytecode_noise_suppressed",), source_detector="stage1117", source_stage="score_caps"),
        "active_profile": "renpy",
        "engine_confidence": {"baseline_suppression_allowed": False},
        "baseline_maturity": {"mature": False},
        "evidence_provenance": {"source": "stage1117"},
        "failure_evidence": (),
    }
    kwargs.update(overrides)
    if type(kwargs["tags"]) is not TagEvidence:
        kwargs["tags"] = normalize_tag_evidence(
            kwargs["tags"], source_detector="stage1117", source_stage="score_caps"
        )
    kwargs["chain_evidence"] = evaluate_chain_evidence(tags=kwargs["tags"])
    return kwargs


def _non_lowering_high_gate(score_val, chain_evidence, **kwargs):
    del chain_evidence
    return float(score_val or 0.0) + 5.0, {"reason": "not_lowered"}


def _lowering_high_gate(score_val, chain_evidence, **kwargs):
    del chain_evidence
    return 21.0, {"reason": "synthetic_high_gate", "weak_or_structural_hits": ("weak",)}


def _failing_high_gate(score_val, chain_evidence, **kwargs):
    del score_val, chain_evidence
    raise ValueError("synthetic high-gate failure")


def test_stage1117_score_cap_helpers_stay_bounded_after_decomposition():
    tree = ast.parse(_CAP_INPUTS_PATH.read_text(encoding="utf-8"))
    oversized = {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.end_lineno - node.lineno + 1 > 40
    }

    assert oversized == {}


def test_stage1117_renpy_bytecode_noise_cap_behavior_is_preserved():
    result = apply_score_caps(**_base_kwargs(high_gate_func=_non_lowering_high_gate))
    explanation = result.mutable_explanation()

    assert result.score_val == 18.0
    assert any(cap["name"] == "renpy_bytecode_noise_cap" for cap in explanation["caps"])
    assert explanation["engine_confidence"] == {"baseline_suppression_allowed": False}
    assert explanation["evidence_provenance"] == {"source": "stage1117"}


def test_stage1117_pickle_proven_graph_bypasses_renpy_noise_cap():
    result = apply_score_caps(**_base_kwargs(
        tags=("renpy_bytecode_noise_suppressed", "pickle_dangerous_global", "pickle_reduce_opcode"),
        high_gate_func=_non_lowering_high_gate,
    ))
    explanation = result.mutable_explanation()

    assert result.score_val == 72.0
    assert not any(cap["name"] == "renpy_bytecode_noise_cap" for cap in explanation.get("caps", ()))


def test_stage1117_anchor_high_gate_cap_and_failure_evidence_remain_visible():
    capped = apply_score_caps(**_base_kwargs(path="payload.exe", tags=("weak_script_signal",), high_gate_func=_lowering_high_gate))
    capped_explanation = capped.mutable_explanation()

    assert capped.score_val == 21.0
    assert capped_explanation["anchor_chain_high_gate"]["reason"] == "synthetic_high_gate"
    assert any(cap["name"] == "anchor_chain_high_gate" for cap in capped_explanation["caps"])

    failed = apply_score_caps(**_base_kwargs(path="payload.exe", tags=(), high_gate_func=_failing_high_gate))
    failure_records = tuple(failed.failure_evidence)

    assert failure_records
    assert any(record["stage_name"] == "score_caps_anchor_chain_high_gate" for record in failure_records)
    assert any(record["json_record_required"] is True for record in failure_records)
    assert any(record["replay_record_required"] is True for record in failure_records)
