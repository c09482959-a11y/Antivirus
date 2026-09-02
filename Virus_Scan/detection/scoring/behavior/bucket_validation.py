"""Detection-owned behavior bucket validation and credential-family scoring.

This module owns semantic scoring over scanner-produced facts.  Scanner modules
observe binary/text facts and tags; detection scoring interprets those facts into
bucket anomaly, high-risk indicator, and credential-family score records.
"""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.contracts.detection_observation import DETECTION_OBSERVATION_UNAVAILABLE_TAG
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    norm_lower_set,
    ordered_unique_tags,
)

from Virus_Scan.detection.contracts.filetype_context import (
    NON_EXECUTION_CAPABILITIES,
    filetype_validation_context,
)
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.contracts.tag_evidence import (
    distinct_root_tag_evidence_records,
    evidence_level_for_tag,
)
from Virus_Scan.detection.api.tag_evidence_contracts import (
    TagEvidence,
    normalize_tag_evidence,
)
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.scoring.weighting.policy_constants import HIGH_RISK_BUCKETS
from Virus_Scan.detection.profiles.baseline_snapshot import (
    behavior_bucket_probability_record,
)
from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_behavior_bucket

PLR2004N0_3 = 0.3
PLR2004N0_6 = 0.6
PLR2004N0_75 = 0.75

if TYPE_CHECKING:
    from collections.abc import (
        Iterable,
        Mapping,
    )

_BEHAVIOR_MODEL_VERSION_TEXT, _BEHAVIOR_MODEL_VERSION_REASON = no_hook_text(
    detection_registry_value("BEHAVIOR_MODEL_VERSION", "detection_behavior_bucket_v1"),
    missing_reason="behavior_model_version_missing",
    unsupported_reason="behavior_model_version_rejected",
)
BEHAVIOR_MODEL_VERSION = _BEHAVIOR_MODEL_VERSION_TEXT or "detection_behavior_bucket_v1"
CREDENTIAL_TAGS = frozenset(
    detection_registry_value(
        "CREDENTIAL_FAMILY_TAGS",
        frozenset(
            {
                "credential_access",
                "credential_access_attempt",
                "credential_dump_attempt",
                "browser_profile_access",
                "browser_extraction",
                "dpapi_access",
                "credential_api_access",
                "token_secret_access",
                "lsass_access",
                "memory_dump",
            }
        ),
    )
)

BehaviorValue = object
BehaviorRecord = dict[str, BehaviorValue]


def _behavior_text(value: BehaviorValue, *, default: str = "", missing_reason: str = "missing_behavior_text", unsupported_reason: str = "unsafe_behavior_text_value_rejected") -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return default, reason
    return text.strip().lower(), ""


def _behavior_token(value: BehaviorValue, *, default: str = "") -> str:
    text, _reason = _behavior_text(value, default=default)
    return text


def _behavior_record(value: BehaviorValue) -> BehaviorRecord:
    if type(value) is not dict:
        return {}
    record: BehaviorRecord = {}
    for key, item in dict.items(value):
        if type(key) is str:
            record[str.__str__(key)] = item
    return record


def _behavior_record_value(record: Mapping[str, BehaviorValue], key: str, default: BehaviorValue = None) -> BehaviorValue:
    return record.get(key, default)


def _behavior_record_text(record: Mapping[str, BehaviorValue], key: str, default: str = "") -> str:
    return _behavior_token(_behavior_record_value(record, key, default), default=default)


def _behavior_record_bool(record: Mapping[str, BehaviorValue], key: str) -> bool:
    return _behavior_record_value(record, key, default=False) is True


def _behavior_probability(value: BehaviorValue) -> float:
    return safe_clamp(value)


def _behavior_record_probability(record: Mapping[str, BehaviorValue], key: str, default: float = 0.0) -> float:
    return _behavior_probability(_behavior_record_value(record, key, default))


def _behavior_ratio(value: float, count: int) -> float:
    denominator = count if count > 0 else 1
    return safe_clamp(value / denominator)


def _engine_extension_value(engine: BehaviorValue, extension: BehaviorValue) -> str:
    engine_text = _behavior_token(engine, default="other") or "other"
    extension_text = _behavior_token(extension, default="")
    return engine_text + ":" + extension_text


_BEHAVIOR_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})


def _normalized_behavior_tags(tags: Iterable[BehaviorValue] | None) -> list[str]:
    """Return one deterministic behavior tag per evidence root.

    Raw public observations are normalized once at this scoring boundary.
    Failure records remain explicit, while aliases and derivations sharing one
    root cannot multiply bucket scores or anomaly denominators.
    """
    bundle = (
        tags if type(tags) is TagEvidence
        else normalize_tag_evidence(
            tags,
            source_detector='behavior_bucket_validation',
            source_stage='bucket_scoring',
        )
    )
    roots = distinct_root_tag_evidence_records(
        bundle.records, allowed_evidence_kinds=_BEHAVIOR_EVIDENCE_KINDS,
    )
    values = [
        record.canonical_tag_id
        for record in roots
        if record.polarity == 'positive' and record.canonical_tag_id
    ]
    values.extend(
        record.canonical_tag_id
        for record in bundle.records
        if record.evidence_kind == 'failure' and record.canonical_tag_id
    )
    return ordered_unique_tags(values)


def _filetype_context_unavailable(reason: str) -> dict[str, BehaviorValue]:
    return {
        "global_bucket": "filetype_context_unavailable",
        "engine_bucket": "filetype_context_unavailable",
        "active_bucket": "filetype_context_unavailable",
        "extension": "",
        "execution_capability": "unknown",
        "normal_buckets": (),
        "rare_buckets": (),
        "high_risk_buckets": (),
        "degraded": True,
        "final_json_must_record": True,
        "replay_record_required": True,
        "unavailable_reason": reason,
    }


def _filetype_validation_context(engine: BehaviorValue, file_path: BehaviorValue) -> dict[str, BehaviorValue]:
    try:
        context = filetype_validation_context(engine, file_path)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _filetype_context_unavailable("filetype_validation_context_failed")
    if type(context) is dict:
        return context
    return _filetype_context_unavailable("filetype_validation_context_rejected")


def _behavior_bucket(tag: BehaviorValue) -> str:
    low = _behavior_token(tag)
    if not low:
        return "other_behavior"
    mapped = tag_behavior_bucket(low)
    if mapped and mapped not in {"other_behavior", low}:
        return mapped
    if low in {"process_exec", "cmd_exec", "powershell_exec", "script_execution", "dynamic_execution"} or "exec" in low:
        return "os_execution"
    for bucket, terms in (
        ("network", ("download", "http", "socket", "network", "exfil", "dns", "c2")),
        ("credential", ("credential", "mimikatz", "lsass", "keylog", "clipboard", "dpapi", "token")),
        ("persistence", ("persist", "schtask", "startup", "registry", "service_create")),
        ("injection", ("inject", "virtualalloc", "writeprocessmemory", "createremotethread", "apc")),
        ("evasion", ("defender_disable", "amsi", "etw", "evasion", "obfuscat", "packed")),
    ):
        if any(term in low for term in terms):
            return bucket
    if any(term in low for term in ("entropy", "encoded", "base64", "xor", "payload")):
        return "entropy_or_packing"
    if "renpy" in low:
        return "renpy_script_logic"
    if "unity" in low:
        return "unity_managed_code"
    if "rpgm" in low or "nwjs" in low or "node" in low:
        return "rpgm_node_runtime"
    return "other_behavior"


def _tag_effective_evidence_score(
    file_path: BehaviorValue,
    tag: BehaviorValue,
    *,
    strings_blob: BehaviorValue = "",
    api_calls: Iterable[BehaviorValue] | None = None,
    ordered_events: Iterable[BehaviorValue] | None = None,
) -> dict[str, BehaviorValue]:
    low = _behavior_token(tag, default=TAG_NORMALIZATION_FAILURE_EVIDENCE)
    bucket = _behavior_bucket(low)
    risk_raw = 2.0 if bucket == "other_behavior" else 4.0
    evidence, confidence = evidence_level_for_tag(
        low,
        strings_blob=strings_blob,
        path=file_path,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )
    if confidence >= PLR2004N0_75:
        risk_raw = max(risk_raw, 7.5)
    risk_probability = safe_clamp(risk_raw / 10.0)
    confidence_probability = safe_clamp(confidence)
    rarity_multiplier = 1.5 if confidence >= PLR2004N0_6 else 1.0
    raw = risk_raw * confidence * rarity_multiplier
    cap = 2.5 if confidence < PLR2004N0_3 else 5.0 if confidence < PLR2004N0_6 else 10.0
    return {
        "tag": low,
        "bucket": bucket,
        "risk": risk_probability,
        "risk_raw": risk_raw,
        "evidence": evidence,
        "confidence": confidence_probability,
        "probability": 0.0,
        "rarity_multiplier": rarity_multiplier,
        "effective_score": min(raw, cap),
        "score_cap": cap,
    }


def _filetype_bucket_model_signal(
    engine: BehaviorValue,
    file_path: BehaviorValue,
    tags: Iterable[BehaviorValue] | None,
    *,
    strings_blob: BehaviorValue = "",
    api_calls: Iterable[BehaviorValue] | None = None,
    ordered_events: Iterable[BehaviorValue] | None = None,
) -> dict[str, BehaviorValue]:
    context = _filetype_validation_context(engine, file_path)
    capability = _behavior_token(context.get("execution_capability"), default="unknown") or "unknown"
    high = norm_lower_set(context.get("high_risk_buckets", ()))
    rare = norm_lower_set(context.get("rare_buckets", ()))
    normal = norm_lower_set(context.get("normal_buckets", ()))
    records: list[dict[str, BehaviorValue]] = []
    score = 0.0
    tag_list = _normalized_behavior_tags(tags)
    for tag in tag_list:
        bucket = _behavior_bucket(tag)
        evidence, confidence = evidence_level_for_tag(
            tag,
            strings_blob=strings_blob,
            path=file_path,
            api_calls=api_calls,
            ordered_events=ordered_events,
        )
        nonexec_violation = capability in NON_EXECUTION_CAPABILITIES and bucket in HIGH_RISK_BUCKETS
        if nonexec_violation:
            severity = 1.0 * max(0.2, confidence)
            policy = "forbidden_for_nonexec_filetype"
        elif bucket in high:
            severity = 0.75 * confidence
            policy = "high_risk"
        elif bucket in rare:
            severity = 0.35 * confidence
            policy = "rare"
        elif bucket in normal:
            severity = 0.0
            policy = "normal"
        else:
            severity = 0.12 * confidence
            policy = "unknown"
        confidence_probability = safe_clamp(confidence)
        records.append(
            {
                "tag": _behavior_token(tag, default=TAG_NORMALIZATION_FAILURE_EVIDENCE),
                "bucket": bucket,
                "evidence": evidence,
                "confidence": confidence_probability,
                "nonexec_execution_violation": bool(nonexec_violation),
                "filetype_policy": policy,
            }
        )
        score += severity
    tag_count = len(tag_list)
    filetype_anomaly = _behavior_ratio(score, tag_count)
    return {
        "context": context,
        "filetype_anomaly": filetype_anomaly,
        "nonexec_execution_violation": any(record.get("nonexec_execution_violation") for record in records),
        "records": records[:80],
    }


def _bucket_validation_policy(
    *, bucket: str, high_risk: frozenset[str], rare_buckets: frozenset[str],
    normal_buckets: frozenset[str], nonexec_execution_violation: bool,
) -> str:
    if nonexec_execution_violation:
        return "forbidden_for_nonexec_filetype"
    if bucket in high_risk:
        return "high_risk"
    if bucket in rare_buckets:
        return "rare"
    if bucket in normal_buckets:
        return "normal"
    return "normal_or_unknown"


def _bucket_validation_policy_boost(
    *, bucket: str, high_risk: frozenset[str], rare_buckets: frozenset[str],
    normal_buckets: frozenset[str], nonexec_execution_violation: bool,
) -> float:
    if nonexec_execution_violation:
        return 1.75
    if bucket in high_risk:
        return 1.25
    if bucket in rare_buckets:
        return 0.9
    if bucket not in normal_buckets:
        return 0.4
    return 0.0


def _bucket_validation_records(
    *,
    engine: BehaviorValue,
    file_path: BehaviorValue,
    tags: Iterable[BehaviorValue] | None,
    strings_blob: BehaviorValue,
    api_calls: Iterable[BehaviorValue] | None,
    ordered_events: Iterable[BehaviorValue] | None,
    context: BehaviorRecord,
    bucket_probability_owner: object,
    high_risk: frozenset[str],
    rare_buckets: frozenset[str],
    normal_buckets: frozenset[str],
) -> tuple[list[dict[str, BehaviorValue]], list[float]]:
    records: list[dict[str, BehaviorValue]] = []
    bucket_scores: list[float] = []
    for tag in _normalized_behavior_tags(tags):
        record = _tag_effective_evidence_score(
            file_path, tag, strings_blob=strings_blob,
            api_calls=api_calls, ordered_events=ordered_events,
        )
        bucket = _behavior_record_text(record, "bucket", "other_behavior")
        bucket_probability_record = bucket_probability_owner(_behavior_token(engine, default="other") or "other", file_path, bucket)
        bucket_probability = safe_clamp(bucket_probability_record.get("probability", 0.0))
        record["bucket_probability"] = bucket_probability
        record["bucket_probability_ready"] = bucket_probability_record["ready"]
        record["bucket_probability_unavailable_reason"] = bucket_probability_record["reason"]
        record["bucket_probability_support"] = bucket_probability_record["support"]
        if bucket_probability_record.get("final_json_must_record") is True:
            record["degraded"] = True
            record["final_json_must_record"] = True
            record["replay_record_required"] = True
        record["filetype_context"] = {
            "global_bucket": _behavior_record_value(context, "global_bucket"),
            "engine_bucket": _behavior_record_value(context, "engine_bucket"),
            "active_bucket": _behavior_record_value(context, "active_bucket"),
            "execution_capability": _behavior_record_value(context, "execution_capability"),
        }
        nonexec_execution_violation = bool(_behavior_record_value(context, "execution_capability") in NON_EXECUTION_CAPABILITIES and bucket in HIGH_RISK_BUCKETS)
        confidence = _behavior_record_probability(record, "confidence")
        probability = _behavior_record_probability(record, "probability")
        record["nonexec_execution_violation"] = nonexec_execution_violation
        record["bucket_policy"] = _bucket_validation_policy(
            bucket=bucket, high_risk=high_risk, rare_buckets=rare_buckets,
            normal_buckets=normal_buckets, nonexec_execution_violation=nonexec_execution_violation,
        )
        record["single_indicator_allowed"] = bool((bucket in high_risk or nonexec_execution_violation) and confidence >= 0.6 and probability < 0.05)
        policy_boost = _bucket_validation_policy_boost(
            bucket=bucket, high_risk=high_risk, rare_buckets=rare_buckets,
            normal_buckets=normal_buckets, nonexec_execution_violation=nonexec_execution_violation,
        )
        bucket_scores.append((1.0 - bucket_probability) * confidence * policy_boost)
        records.append(record)
    return records, bucket_scores


def behavior_bucket_validation(
    engine: BehaviorValue,
    file_path: BehaviorValue,
    tags: Iterable[BehaviorValue] | None,
    strings_blob: BehaviorValue = "",
    api_calls: Iterable[BehaviorValue] | None = None,
    ordered_events: Iterable[BehaviorValue] | None = None,
) -> dict[str, BehaviorValue]:
    filetype_validation = _filetype_bucket_model_signal(
        engine,
        file_path,
        tags,
        strings_blob=strings_blob,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )
    context = _behavior_record(_behavior_record_value(filetype_validation, "context", {}))
    if not context:
        context = _filetype_context_unavailable("filetype_context_rejected")
    high_risk = norm_lower_set(_behavior_record_value(context, "high_risk_buckets", ())) | norm_lower_set(HIGH_RISK_BUCKETS)
    rare_buckets = norm_lower_set(_behavior_record_value(context, "rare_buckets", ()))
    normal_buckets = norm_lower_set(_behavior_record_value(context, "normal_buckets", ()))
    bucket_probability_owner = behavior_bucket_probability_record
    records, bucket_scores = _bucket_validation_records(
        engine=engine,
        file_path=file_path,
        tags=tags,
        strings_blob=strings_blob,
        api_calls=api_calls,
        ordered_events=ordered_events,
        context=context,
        bucket_probability_owner=bucket_probability_owner,
        high_risk=high_risk,
        rare_buckets=rare_buckets,
        normal_buckets=normal_buckets,
    )
    strongest = max((_behavior_record_probability(record, "effective_score") for record in records), default=0.0)
    single = any(
        _behavior_record_bool(record, "single_indicator_allowed")
        and _behavior_record_probability(record, "effective_score") >= 5.0
        for record in records
    )
    bucket_average = _behavior_ratio(sum(bucket_scores), len(bucket_scores))
    filetype_anomaly = _behavior_record_probability(filetype_validation, "filetype_anomaly")
    bucket_anomaly = safe_clamp(bucket_average * 0.75 + filetype_anomaly * 0.25)
    engine_extension = _engine_extension_value(engine, _behavior_record_value(context, "extension"))
    return {
        "version": BEHAVIOR_MODEL_VERSION,
        "engine_extension": engine_extension,
        "filetype_validation": filetype_validation,
        "bucket_anomaly": bucket_anomaly,
        "strongest_single_tag_score": strongest,
        "rare_high_conf_single_indicator": bool(single),
        "nonexec_execution_violation": _behavior_record_bool(filetype_validation, "nonexec_execution_violation"),
        "records": records[:80],
    }


def credential_family_boost(tags: Iterable[BehaviorValue] | None, strings_blob: BehaviorValue = "") -> dict[str, BehaviorValue]:
    normalized_tags = _normalized_behavior_tags(tags)
    tagset = frozenset(_behavior_token(tag) for tag in normalized_tags if _behavior_token(tag))
    blob, blob_reason = _behavior_text(
        strings_blob,
        missing_reason="credential_blob_missing",
        unsupported_reason="credential_blob_rejected",
    )
    score = 0.0
    reasons: list[str] = []
    degraded = bool(tagset & {TAG_NORMALIZATION_FAILURE_EVIDENCE, DETECTION_STAGE_DEGRADED_TAG, DETECTION_OBSERVATION_UNAVAILABLE_TAG}) or bool(blob_reason)
    if tagset & {TAG_NORMALIZATION_FAILURE_EVIDENCE, DETECTION_STAGE_DEGRADED_TAG, DETECTION_OBSERVATION_UNAVAILABLE_TAG}:
        reasons.append("credential_tag_input_rejected")
    if blob_reason:
        reasons.append("credential_blob_unavailable:" + blob_reason)
    hits = CREDENTIAL_TAGS & tagset
    if len(hits) >= 1:
        score += 0.3
        reasons.append("credential tags: " + repr(sorted(hits)))
    if len(hits) >= 2:
        score += 0.3
        reasons.append("multiple credential indicators")
    if "login data" in blob and ("cryptunprotectdata" in blob or "dpapi" in blob):
        score += 0.3
        reasons.append("browser credential DB plus DPAPI")
    if "lsass" in blob and ("minidumpwritedump" in blob or "readprocessmemory" in blob):
        score += 0.35
        reasons.append("LSASS dump/read pattern")
    output_tags = ["credential_stealer_behavior"] if score >= 0.3 else []
    if degraded:
        output_tags = sorted(set(output_tags) | {DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE})
    credential_score = safe_clamp(score)
    return {
        "score": credential_score,
        "reasons": reasons,
        "tags": output_tags,
        "degraded": bool(degraded),
        "input_unavailable_reason": "credential_input_rejected" if degraded else "",
    }


__all__ = ("behavior_bucket_validation", "credential_family_boost")
