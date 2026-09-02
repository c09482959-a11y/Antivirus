"""Pure score-cap owner for full-analysis detection."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.utils.stages import normalize_profile_extension
from Virus_Scan.detection.contracts.string_predicates import is_renpy_bytecode_path
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.models.stage_value_utils import thaw_detection_value
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.profiles.selection import DETECTION_PROFILE_NAMES, canonical_profile_name
from Virus_Scan.detection.scoring.escalation.high_gate import apply_anchor_chain_high_gate
from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation
from Virus_Scan.detection.scoring.full_analysis.failure_attachment import attach_failure_evidence
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import ScoreBreakdown
from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    full_analysis_float,
    full_analysis_mapping,
    full_analysis_mapping_get,
    full_analysis_sequence,
)
from Virus_Scan.detection.scoring.weighting.concrete_attack_cap import apply_no_concrete_attack_cap
from Virus_Scan.detection.scoring.weighting.contextual_expected import (
    ContextualExpectedScoreRequest,
    apply_contextual_expected_behavior_score_from_request,
)


DetectionValue = object
DetectionSequence = Sequence[DetectionValue]
DetectionMapping = Mapping[str, DetectionValue]
MutableDetectionMapping = dict[str, DetectionValue]
StageFailureRecords = tuple[DetectionValue, ...]
StageFailureResult = tuple[DetectionValue, StageFailureRecords]
ScoreCapHighGate = Callable[..., tuple[DetectionValue, DetectionMapping]]

_RENPY_BYTECODE_VALIDATED_ANCHOR_TAGS = frozenset((
    'wmi_exec', 'win32_process_create', 'admin_share_access', 'smb_activity',
    'remote_service_creation', 'remote_scheduled_task', 'credential_dump_attempt',
    'lsass_access', 'token_secret_access', 'credential_api_access', 'powershell_exec',
    'cmd_exec', 'process_exec', 'memory_write', 'thread_execution', 'memory_protect',
    'network_exfiltration', 'token_exfiltration', 'mimikatz_credential_dump',
    'high_confidence_credential_theft', 'pickle_reduce_opcode',
    'pickle_callable_reference', 'pickle_dangerous_global', 'pickle_global_reference',
))


def _with_stage_failure(
    failures: DetectionSequence, *, stage_name: str, error_source: str,
    error: BaseException | str, path: DetectionValue,
) -> StageFailureRecords:
    out = list(full_analysis_sequence(failures))
    out.append(recoverable_failure_evidence(
        stage_name=stage_name,
        error_source=error_source,
        error=error,
        affected_context=str(path),
    ))
    return tuple(out)


def _contextual_baseline_engine(active_profile: DetectionValue) -> str:
    engine = canonical_profile_name(active_profile)
    if engine not in DETECTION_PROFILE_NAMES:
        return 'other'
    return engine


def _suppressed_contextual_baseline(
    score_val: DetectionValue, *, engine: str, path: DetectionValue,
    engine_confidence: DetectionMapping, baseline_maturity: DetectionValue,
) -> MutableDetectionMapping:
    score = full_analysis_float(score_val)
    return {
        'applied': False,
        'reason': 'engine_confidence_below_threshold',
        'engine': engine,
        'extension': normalize_profile_extension(path),
        'engine_confidence': engine_confidence,
        'baseline_maturity': baseline_maturity,
        'old_score': score,
        'new_score': score,
    }


def _record_contextual_baseline(
    explanation: DetectionValue, *, score_val: DetectionValue, old_score: float,
    engine: str, path: DetectionValue, contextual_baseline: DetectionMapping,
) -> None:
    if not isinstance(explanation, dict):
        return
    explanation['contextual_expected_behavior'] = contextual_baseline
    if full_analysis_float(score_val) >= old_score:
        return
    explanation.setdefault('caps', []).append({
        'name': 'learned_engine_extension_expected_behavior_reducer',
        'old_score': old_score,
        'new_score': score_val,
        'engine': engine,
        'extension': normalize_profile_extension(path),
        'expected_tags': list(full_analysis_sequence(full_analysis_mapping_get(contextual_baseline, 'expected_tags', ()))),
        'anchors': list(full_analysis_sequence(full_analysis_mapping_get(contextual_baseline, 'anchors', ()))),
    })


def _apply_contextual_expected_cap(
    score_val: DetectionValue, explanation: DetectionValue, *, path: DetectionValue,
    tag_evidence: TagEvidence, active_profile: DetectionValue,
    engine_confidence: DetectionMapping, baseline_maturity: DetectionValue,
    failures: StageFailureRecords, routing_evidence_context: object | None = None,
    router_identity: object | None = None,
) -> StageFailureResult:
    try:
        engine = _contextual_baseline_engine(active_profile)
        old_score = full_analysis_float(score_val)
        engine_confidence_map = full_analysis_mapping(engine_confidence)
        if full_analysis_mapping_get(engine_confidence_map, 'baseline_suppression_allowed', True) is False:
            baseline = _suppressed_contextual_baseline(
                score_val, engine=engine, path=path,
                engine_confidence=engine_confidence_map, baseline_maturity=baseline_maturity,
            )
        else:
            score_val, baseline = apply_contextual_expected_behavior_score_from_request(
                ContextualExpectedScoreRequest(
                    score=score_val,
                    engine=engine,
                    file_path=path,
                    tag_evidence=tag_evidence,
                    routing_evidence_context=routing_evidence_context,
                    router_identity=router_identity,
                )
            )
        _record_contextual_baseline(explanation, score_val=score_val, old_score=old_score,
                                    engine=engine, path=path, contextual_baseline=baseline)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failures = _with_stage_failure(
            failures, stage_name='score_caps_contextual_expected_behavior',
            error_source='apply_contextual_expected_behavior_score_from_request', error=e, path=path,
        )
    return score_val, failures


def _apply_concrete_attack_cap(
    score_val: DetectionValue, explanation: DetectionValue, *, path: DetectionValue,
    chain_evidence: ChainEvidence, failures: StageFailureRecords,
) -> StageFailureResult:
    try:
        capped_score, pe_cap = apply_no_concrete_attack_cap(
            score_val, chain_evidence, path=path,
        )
        if full_analysis_mapping(pe_cap):
            score_val = capped_score
            if isinstance(explanation, dict):
                explanation.setdefault('caps', []).append(pe_cap)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failures = _with_stage_failure(
            failures, stage_name='score_caps_no_concrete_attack',
            error_source='apply_no_concrete_attack_cap', error=e, path=path,
        )
    return score_val, failures


def _apply_anchor_chain_high_gate(
    score_val: DetectionValue, explanation: DetectionValue, *, path: DetectionValue,
    tags: DetectionSequence,
    chain_evidence: ChainEvidence, failures: StageFailureRecords,
    high_gate_func: ScoreCapHighGate,
) -> StageFailureResult:
    try:
        gated_score, high_gate_meta = high_gate_func(
            score_val, chain_evidence,
            tags=tags, path=path,
        )
        if full_analysis_float(gated_score) < full_analysis_float(score_val):
            old_score = full_analysis_float(score_val)
            score_val = gated_score
            _record_high_gate_cap(explanation, old_score=old_score, score_val=score_val, meta=high_gate_meta)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failures = _with_stage_failure(
            failures, stage_name='score_caps_anchor_chain_high_gate',
            error_source='apply_anchor_chain_high_gate', error=e, path=path,
        )
    return score_val, failures


def _record_high_gate_cap(
    explanation: DetectionValue, *, old_score: float, score_val: DetectionValue,
    meta: DetectionMapping,
) -> None:
    if not isinstance(explanation, dict):
        return
    explanation.setdefault('caps', []).append({
        'name': 'anchor_chain_high_gate',
        'old_score': old_score,
        'new_score': score_val,
        'reason': full_analysis_mapping_get(meta, 'reason'),
        'weak_or_structural_hits': list(full_analysis_sequence(full_analysis_mapping_get(meta, 'weak_or_structural_hits', ()))),
    })
    explanation['anchor_chain_high_gate'] = meta


def _pickle_graph_proven_for_rpyc(chain_evidence: ChainEvidence) -> bool:
    return any(
        decision.status == "confirmed"
        and decision.scoreable
        and decision.candidate.family == "pickle_execution"
        for decision in chain_evidence.decisions
    )


def _should_cap_renpy_bytecode_noise(
    path: DetectionValue,
    tags: DetectionSequence,
    chain_evidence: ChainEvidence,
) -> bool:
    original_tags = set(full_analysis_sequence(tags))
    return (
        is_renpy_bytecode_path(path)
        and 'renpy_bytecode_noise_suppressed' in original_tags
        and not _pickle_graph_proven_for_rpyc(chain_evidence)
        and not original_tags & _RENPY_BYTECODE_VALIDATED_ANCHOR_TAGS
    )

def _apply_renpy_bytecode_noise_cap(
    score_val: DetectionValue, explanation: DetectionValue, *, path: DetectionValue,
    tags: DetectionSequence, chain_evidence: ChainEvidence, failures: StageFailureRecords,
) -> StageFailureResult:
    try:
        if _should_cap_renpy_bytecode_noise(path, tags, chain_evidence):
            old_score = full_analysis_float(score_val)
            score_val = min(old_score, 18.0)
            if isinstance(explanation, dict):
                explanation.setdefault('caps', []).append({
                    'name': 'renpy_bytecode_noise_cap',
                    'old_score': old_score,
                    'new_score': score_val,
                })
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failures = _with_stage_failure(
            failures, stage_name='score_caps_renpy_bytecode_noise',
            error_source='renpy_bytecode_noise_cap', error=e, path=path,
        )
    return score_val, failures


def _record_score_context(
    explanation: DetectionValue, *, engine_confidence: DetectionMapping,
    baseline_maturity: DetectionValue, evidence_provenance: DetectionValue,
) -> None:
    if not isinstance(explanation, dict):
        return
    explanation['engine_confidence'] = engine_confidence
    explanation['baseline_maturity'] = baseline_maturity
    explanation['evidence_provenance'] = evidence_provenance


def _finalize_breakdown(
    *, score_val: DetectionValue, explanation: DetectionValue, path: DetectionValue,
    active_profile: DetectionValue, tags: TagEvidence, failures: StageFailureRecords,
) -> ScoreBreakdown:
    explanation = attach_failure_evidence(explanation, failures)
    explanation = build_reproducible_score_explanation(
        final_score=score_val,
        explanation=explanation,
        path=path,
        active_profile=active_profile,
    )
    return ScoreBreakdown(
        score_val=score_val,
        explanation=explanation,
        tags=tags,
        failure_evidence=failures,
    )


def _canonical_score_cap_tag_evidence(tags: object) -> TagEvidence:
    if type(tags) is not TagEvidence:
        raise TypeError('score_cap_tag_evidence_required')
    return tags


def _canonical_score_cap_chain_evidence(value: object) -> ChainEvidence:
    if type(value) is not ChainEvidence:
        raise TypeError('score_cap_chain_evidence_required')
    return value


def apply_score_caps(
    *, score_val: DetectionValue, explanation: DetectionValue, path: DetectionValue,
    tags: TagEvidence, chain_evidence: ChainEvidence,
    active_profile: DetectionValue, engine_confidence: DetectionValue,
    baseline_maturity: DetectionValue, evidence_provenance: DetectionValue,
    failure_evidence: DetectionSequence = (), routing_evidence_context: object | None = None,
    router_identity: object | None = None,
    high_gate_func: ScoreCapHighGate = apply_anchor_chain_high_gate,
) -> ScoreBreakdown:
    """Apply final caps to one exact tag and chain evidence pair."""
    explanation = thaw_detection_value(full_analysis_mapping(explanation))
    failures = tuple(full_analysis_sequence(failure_evidence))
    tag_evidence = _canonical_score_cap_tag_evidence(tags)
    canonical_chains = _canonical_score_cap_chain_evidence(chain_evidence)
    projected_tags = full_analysis_sequence(tag_evidence.tags)
    engine_confidence = full_analysis_mapping(engine_confidence)
    score_val, failures = _apply_contextual_expected_cap(
        score_val, explanation, path=path, tag_evidence=tag_evidence, active_profile=active_profile,
        engine_confidence=engine_confidence, baseline_maturity=baseline_maturity, failures=failures,
        routing_evidence_context=routing_evidence_context,
        router_identity=router_identity,
    )
    _record_score_context(
        explanation, engine_confidence=engine_confidence, baseline_maturity=baseline_maturity, evidence_provenance=evidence_provenance,
    )
    score_val, failures = _apply_concrete_attack_cap(
        score_val, explanation, path=path, chain_evidence=canonical_chains,
        failures=failures,
    )
    score_val, failures = _apply_anchor_chain_high_gate(
        score_val, explanation, path=path, tags=projected_tags,
        chain_evidence=canonical_chains, failures=failures,
        high_gate_func=high_gate_func,
    )
    score_val, failures = _apply_renpy_bytecode_noise_cap(
        score_val, explanation, path=path, tags=projected_tags, chain_evidence=canonical_chains, failures=failures)
    return _finalize_breakdown(
        score_val=score_val, explanation=explanation, path=path,
        active_profile=active_profile, tags=tag_evidence, failures=failures,
    )


__all__ = ('apply_score_caps',)
