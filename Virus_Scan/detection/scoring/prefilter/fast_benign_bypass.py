"""Strict after-prefilter benign bypass owner.

Owns the post-prefilter boring-text bypass decision only. It does not own raw
prefilter scanning, scoring, chain evaluation, or caller API exports.
"""

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.models.detection_result import build_fast_benign_detection_result
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.registries.prefilter_defaults import STRICT_FAST_BENIGN_BYPASS_VERSION
from Virus_Scan.detection.contracts.binary_predicates import strict_fast_file_is_boring_text
from Virus_Scan.detection.attack.api import official_attack_fast_path_policy
from Virus_Scan.utils.stages import normalize_stage


@dataclass(frozen=True, slots=True)
class _FastBypassGate:
    proceed: bool
    result: object


def _fast_bypass_text(value: object, default: object='<unreadable_path>') -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='fast_bypass_text_missing',
        unsupported_reason='fast_bypass_text_rejected',
    )
    if reason:
        return default
    return text


def _fast_bypass_bool_status(value: object, reason: object) -> tuple[bool, str]:
    if value is None:
        return (False, '')
    if type(value) in (bool, int, float, str, bytes, bytearray, tuple, list, set, frozenset, dict):
        return (bool(value), '')
    items = no_hook_mapping_items(value)
    if items is not None:
        return (len(items) > 0, '')
    return (False, reason)


def _fast_bypass_failure(path: object, error: object, *, error_category: object=None) -> object:
    error_text = _fast_bypass_text(error, no_hook_type_name(error))
    return {
        "fast_path": False,
        "force_full": True,
        "tags": ["detection_stage_degraded", "fast_benign_bypass_degraded", "failure_evidence_recorded"],
        "failure_evidence": [{
            "stage_name": "fast_benign_bypass_after_prefilter",
            "state": "degraded",
            "error_category": error_category if type(error_category) is str else no_hook_type_name(error),
            "error_source": "extremely_strict_fast_benign_bypass_after_prefilter",
            "affected_context": _fast_bypass_text(path),
            "confidence_degraded": True,
            "json_record_required": True,
            "replay_record_required": True,
            "fatal": False,
            "message": error_text,
        }],
    }


def _fast_bypass_gate(path: object, suspicious: object, yara_hits: object, compiled_rules: object) -> _FastBypassGate:
    if compiled_rules is not None:
        return _FastBypassGate(False, None)
    suspicious_value, suspicious_reason = _fast_bypass_bool_status(suspicious, 'unsafe_fast_bypass_suspicious_rejected')
    if suspicious_reason:
        return _FastBypassGate(False, _fast_bypass_failure(path, suspicious_reason, error_category='RecoverableDetectionFailure'))
    if suspicious_value:
        return _FastBypassGate(False, None)
    yara_active, yara_reason = _fast_bypass_bool_status(yara_hits, 'unsafe_fast_bypass_yara_hits_rejected')
    if yara_reason:
        return _FastBypassGate(False, _fast_bypass_failure(path, yara_reason, error_category='RecoverableDetectionFailure'))
    return _FastBypassGate(not yara_active, None)


def _has_behavioral_fast_tags(norm_tags: list[str]) -> bool:
    allowed_prefixes = ('router_stage_',)
    allowed_exact = {'strict_fast_benign_bypass', 'fast_path_non_learning', 'benign', 'text_file'}
    return any(
        tag not in allowed_exact and not any(tag.startswith(prefix) for prefix in allowed_prefixes)
        for tag in norm_tags
    )


def extremely_strict_fast_benign_bypass_after_prefilter(path: object, tags: object=None, *, suspicious: object=False, yara_hits: object=None, compiled_rules: object=None) -> object:
    """Return a benign fast-path result only after every strict gate passes."""
    try:
        gate = _fast_bypass_gate(path, suspicious, yara_hits, compiled_rules)
        if not gate.proceed:
            return gate.result
        fast_path_allowed, fast_path_model_evidence = official_attack_fast_path_policy()
        if not fast_path_allowed:
            return None
        norm_tags = normalize_tags(tags)
        if _has_behavioral_fast_tags(norm_tags):
            return None
        ok, meta = strict_fast_file_is_boring_text(path)
        if not ok:
            return None
        curr_stage = normalize_stage(get_scan_extension(path))
        out_tags = normalize_tags(['strict_fast_benign_bypass', 'router_stage_' + curr_stage, 'fast_path_non_learning'])
        return build_fast_benign_detection_result(
            path=path,
            score=3.0,
            confidence=0.2,
            tags=out_tags,
            prefilter_tags=norm_tags,
            effective_stage=curr_stage,
            reason='strict_fast_benign_bypass_after_prefilter',
            version=STRICT_FAST_BENIGN_BYPASS_VERSION,
            constraints=dict(meta, yara_active=False, after_prefilter=True),
            model_evidence=fast_path_model_evidence,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        return _fast_bypass_failure(path, error)
