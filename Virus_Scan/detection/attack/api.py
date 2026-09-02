"""Public official Enterprise ATT&CK repository and mapping API."""
from __future__ import annotations

import json
from types import MappingProxyType

from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.attack.publication import parse_official_attack_probability_evidence
from Virus_Scan.runtime.api import mitre_runtime_snapshot
from Virus_Scan.detection.attack.evaluation_stage import unavailable_attack_mapping_result


def _plain_status(value: object) -> object:
    if type(value) in (str, bool, int, float, type(None)):
        return value
    if type(value) is tuple:
        return tuple(_plain_status(item) for item in value[:256])
    if type(value) is dict:
        return {key: _plain_status(item) for key, item in tuple(dict.items(value))[:256] if type(key) is str}
    if type(value) is MappingProxyType:
        return {key: _plain_status(item) for key, item in tuple(value.items())[:256] if type(key) is str}
    return "unavailable"


def attack_repository_status() -> dict[str, object]:
    runtime = mitre_runtime_snapshot()
    materialized = _plain_status(runtime.status)
    record = materialized if type(materialized) is dict else {}
    record.update({
        "enabled": runtime.enabled,
        "available": runtime.available,
    })
    if runtime.repository is not None:
        record.update(runtime.repository.to_record())
    return record


def _official_attack_probability_record(
    result: AttackMappingResult,
    *,
    repository_status: dict[str, object],
) -> dict[str, object]:
    record = result.to_record()
    record["mapping_scope"] = "official_attack_techniques"
    record["technique_ids_claimed"] = bool(record["confirmed"])
    record["repository_status"] = repository_status
    record["verified_yara_observation_count"] = 0
    record["yara_alignment_count"] = 0
    return record


def unavailable_official_attack_probability_evidence(
    reason: str,
) -> dict[str, object]:
    if type(reason) is not str or reason == "" or len(reason) > 256:
        raise ValueError("official_attack_unavailable_reason_invalid")
    result = unavailable_attack_mapping_result(reason)
    return _official_attack_probability_record(
        result,
        repository_status=attack_repository_status(),
    )



def official_attack_fast_path_policy() -> tuple[bool, dict[str, object]]:
    """Return whether a scanner fast path may skip official ATT&CK mapping.

    A live repository requires the complete structured observation/Chain/mapping
    pipeline.  When ATT&CK is disabled or unavailable, a fast path remains
    permissible only with explicit zero-probability unavailable evidence.
    """
    runtime = mitre_runtime_snapshot()
    if runtime.enabled and runtime.available:
        return False, {}
    if not runtime.enabled:
        reason = "mitre_disabled"
    else:
        status_reason = runtime.status.get("unavailable_reason")
        reason = (
            str.__str__(status_reason)
            if type(status_reason) is str and status_reason and len(status_reason) <= 256
            else "mitre_repository_unavailable"
        )
    return True, {
        "feature_probabilities": {"mitre": 0.0},
        "unavailable_reasons": {"mitre": reason},
        "mitre_evidence": unavailable_official_attack_probability_evidence(reason),
    }

def official_attack_probability_evidence(result: AttackMappingResult) -> dict[str, object]:
    """Project one immutable mapping result without rerunning ATT&CK evaluation."""
    if type(result) is not AttackMappingResult:
        raise TypeError("official_attack_mapping_result_required")
    return _official_attack_probability_record(
        result,
        repository_status=attack_repository_status(),
    )


def serialize_official_attack_probability_evidence(evidence: object) -> str:
    if type(evidence) is not dict:
        raise TypeError("official_attack_evidence_mapping_required")
    try:
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        canonical = parse_official_attack_probability_evidence(encoded)
        return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("official_attack_evidence_not_json_safe") from exc


def materialize_official_attack_probability_evidence(value: object) -> dict[str, object]:
    try:
        return parse_official_attack_probability_evidence(value)
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError, OverflowError):
        return {
            "mapping_scope": "official_attack_techniques",
            "technique_ids_claimed": False,
            "ready": False,
            "probability": 0.0,
            "probability_unavailable_reason": "",
            "unavailable_reason": "mitre_evidence_json_invalid",
        }


__all__ = (
    "attack_repository_status",
    "official_attack_fast_path_policy",
    "materialize_official_attack_probability_evidence",
    "official_attack_probability_evidence",
    "unavailable_official_attack_probability_evidence",
    "serialize_official_attack_probability_evidence",
)
