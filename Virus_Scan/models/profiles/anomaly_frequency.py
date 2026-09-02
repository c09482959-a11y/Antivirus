"""Canonical profile empirical-frequency anomaly ownership."""
from __future__ import annotations

from Virus_Scan.contracts.tag_evidence_persistence import persisted_tag_observation_count
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.contracts.empirical_frequency import empirical_frequency_record
from Virus_Scan.models.profiles.baseline import get_extension_baseline
from Virus_Scan.models.profiles.chain_records import (
    profile_chain_frequency_key,
    profile_scoreable_chain_decisions,
)
from Virus_Scan.models.profiles.common import profile_int, profile_mapping_get
from Virus_Scan.models.profiles.maturity import (
    PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
    profile_maturity_evidence,
)
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection


def _baseline_frequency_context(engine: object, file_path: object) -> tuple[object, object]:
    baseline = get_extension_baseline(engine, file_path)
    maturity = profile_maturity_evidence(
        profile_mapping_get(baseline, "vector_baseline", {}),
    )
    return baseline, maturity


def _frequency_record(count: int, maturity: object) -> object:
    return empirical_frequency_record(
        count,
        maturity["trusted_count"],
        minimum_support=PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
        maturity=maturity["maturity"],
        suppression_authority=maturity["suppression_authority"],
    )


def extension_tag_frequency_evidence(
    engine: object, file_path: object, tag: object,
) -> object:
    """Return smoothed tag frequency with trusted-support provenance."""
    baseline, maturity = _baseline_frequency_context(engine, file_path)
    count = persisted_tag_observation_count(
        profile_mapping_get(baseline, "tag_evidence", {}), tag,
    )
    return _frequency_record(count, maturity)


def extension_chain_frequency_evidence(
    engine: object, file_path: object, frequency_key: object,
) -> object:
    """Return smoothed canonical-chain frequency evidence."""
    baseline, maturity = _baseline_frequency_context(engine, file_path)
    chain_state = profile_mapping_get(baseline, "chains", {})
    audit = profile_mapping_get(chain_state, "suspicious_audit", {})
    count = max(0, profile_int(profile_mapping_get(audit, frequency_key, 0), 0))
    return _frequency_record(count, maturity)


def behavior_bucket_frequency_evidence(
    engine: object, file_path: object, bucket: object,
) -> object:
    """Return smoothed observation-level bucket frequency evidence."""
    baseline, maturity = _baseline_frequency_context(engine, file_path)
    buckets = profile_mapping_get(baseline, "behavior_buckets", {})
    bucket_state = profile_mapping_get(buckets, bucket, {})
    count = max(0, profile_int(profile_mapping_get(bucket_state, "files", 0), 0))
    return _frequency_record(count, maturity)


def _rarity(record: object) -> float:
    if record["ready"] is not True:
        return 0.0
    return (1.0 - record["probability"]) * record["suppression_authority"]


def extension_profile_chain_anomalies(
    engine: object,
    file_path: object,
    tags: object,
    api_calls: object,
    ordered_events: object,
) -> tuple[float, float]:
    """Measure trusted-support tag and canonical-chain rarity."""
    bundle, root_records, _root_tags, _group_count, _reason = (
        profile_tag_evidence_projection(tags)
    )
    decisions = profile_scoreable_chain_decisions(evaluate_chain_evidence(
        tags=bundle,
        api_calls=api_calls,
        ordered_events=ordered_events,
    ))
    tag_scores = tuple(
        _rarity(extension_tag_frequency_evidence(
            engine, file_path, record.publication_name,
        ))
        for record in root_records
    )
    chain_scores = tuple(
        _rarity(extension_chain_frequency_evidence(
            engine, file_path, profile_chain_frequency_key(decision),
        ))
        for decision in decisions
    )
    return (
        sum(tag_scores) / max(1, len(tag_scores)),
        sum(chain_scores) / max(1, len(chain_scores)),
    )


__all__ = (
    "behavior_bucket_frequency_evidence",
    "extension_chain_frequency_evidence",
    "extension_profile_chain_anomalies",
    "extension_tag_frequency_evidence",
)
