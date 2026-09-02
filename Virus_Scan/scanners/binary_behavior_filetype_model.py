"""Scanner-owned binary behavior filetype model signals."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scanners.binary_behavior_semantics import evidence_level_for_tag, tag_behavior_bucket
from Virus_Scan.scanners.binary_filetype import filetype_validation_context
from Virus_Scan.scanners.filetype_policy import HIGH_RISK_BUCKETS, NON_EXECUTION_CAPABILITIES
from Virus_Scan.scanners.binary_numeric import scanner_clamped_ratio
from Virus_Scan.utils.tagging import normalize_tags


@dataclass(frozen=True, slots=True)
class FiletypePolicyContext:
    capability: str
    high: frozenset[str]
    rare: frozenset[str]
    normal: frozenset[str]


@dataclass(frozen=True, slots=True)
class FiletypeBucketModelRequest:
    engine: object
    file_path: object
    tags: object
    strings_blob: object = ""
    api_calls: object = None
    ordered_events: object = None


@dataclass(frozen=True, slots=True)
class FiletypeSignalScanRequest:
    context: object
    file_path: object
    tags: object
    strings_blob: object = ""
    api_calls: object = None
    ordered_events: object = None


def _filetype_record_policy(bucket: str, policy: FiletypePolicyContext) -> str:
    if bucket in policy.high:
        return "high_risk"
    if bucket in policy.rare:
        return "rare"
    if bucket in policy.normal:
        return "normal"
    return "unknown"


def _filetype_record_severity(
    bucket: str,
    ev_conf: float,
    policy: FiletypePolicyContext,
) -> tuple[float, bool]:
    nonexec_violation = policy.capability in NON_EXECUTION_CAPABILITIES and bucket in HIGH_RISK_BUCKETS
    if nonexec_violation:
        return 1.0 * max(0.2, ev_conf), True
    if bucket in policy.high:
        return 0.75 * ev_conf, False
    if bucket in policy.rare:
        return 0.35 * ev_conf, False
    if bucket in policy.normal:
        return 0.0, False
    return 0.12 * ev_conf, False


def _filetype_signal_record(
    tag: object,
    bucket: str,
    ev_name: str,
    ev_conf: float,
    policy: FiletypePolicyContext,
) -> tuple[dict, float]:
    severity, nonexec_violation = _filetype_record_severity(bucket, ev_conf, policy)
    record = {
        "tag": str(tag).lower(),
        "bucket": bucket,
        "evidence": ev_name,
        "confidence": ev_conf,
        "nonexec_execution_violation": bool(nonexec_violation),
        "filetype_policy": _filetype_record_policy(bucket, policy),
    }
    return record, severity


def _filetype_signal_records(request: FiletypeSignalScanRequest) -> object:
    ctx = request.context
    policy = FiletypePolicyContext(
        capability=ctx.get("execution_capability", "unknown"),
        high=frozenset(ctx.get("high_risk_buckets", set())),
        rare=frozenset(ctx.get("rare_buckets", set())),
        normal=frozenset(ctx.get("normal_buckets", set())),
    )
    records, score = [], 0.0
    for tag in normalize_tags(request.tags):
        bucket = tag_behavior_bucket(tag)
        ev_name, ev_conf = evidence_level_for_tag(
            tag,
            strings_blob=request.strings_blob,
            path=request.file_path,
            api_calls=request.api_calls,
            ordered_events=request.ordered_events,
        )
        record, severity = _filetype_signal_record(tag, bucket, ev_name, ev_conf, policy)
        records.append(record)
        score += severity
    return records, score


def filetype_bucket_model_signal(request: FiletypeBucketModelRequest) -> object:
    ctx = filetype_validation_context(request.engine, request.file_path)
    tag_list = normalize_tags(request.tags)
    records, score = _filetype_signal_records(
        FiletypeSignalScanRequest(
            context=ctx,
            file_path=request.file_path,
            tags=tag_list,
            strings_blob=request.strings_blob,
            api_calls=request.api_calls,
            ordered_events=request.ordered_events,
        )
    )
    anomaly = scanner_clamped_ratio(score, len(tag_list), field="filetype_anomaly")
    return {
        "context": ctx,
        "filetype_anomaly": anomaly,
        "nonexec_execution_violation": any(record.get("nonexec_execution_violation") for record in records),
        "records": records[:80],
    }




__all__ = (
    'FiletypeBucketModelRequest',
    'filetype_bucket_model_signal',
)
