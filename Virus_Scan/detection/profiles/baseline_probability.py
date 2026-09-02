"""Bounded helpers for behavior-bucket empirical probability records."""

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
    no_hook_text,
)
from Virus_Scan.models.contracts.empirical_frequency import (
    empirical_frequency_record,
    unavailable_empirical_frequency_record,
)
from Virus_Scan.models.profiles.maturity import PROFILE_WARMING_MIN_TRUSTED_SUPPORT


def unavailable_bucket_probability_record(
    reason: object,
    *,
    support: object = 0,
    record_required: object = True,
) -> object:
    """Return immutable unavailable profile-frequency evidence."""
    support_value = support if type(support) is int and type(support) is not bool and support >= 0 else 0
    record = dict(unavailable_empirical_frequency_record(
        reason if type(reason) is str and reason else "bucket_probability_unavailable",
        support=support_value,
        minimum_support=PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
    ))
    if record_required:
        record["final_json_must_record"] = True
        record["replay_record_required"] = True
    return record


def profile_frequency_context_or_failure_record(
    baseline: object,
) -> tuple[dict[str, object], object | None]:
    """Return validated trusted support, maturity, and authority."""
    baseline_reason = baseline.get("unavailable_reason") or baseline.get("reason")
    if type(baseline_reason) is str and baseline_reason != "":
        return {}, unavailable_bucket_probability_record(baseline_reason)
    vector_items = no_hook_mapping_items(baseline.get("vector_baseline"))
    if vector_items is None:
        return {}, unavailable_bucket_probability_record(
            "profile_vector_statistics_unavailable",
        )
    vector = {
        key: value for key, value in vector_items
        if type(key) is str
    }
    support, support_reason = no_hook_exact_nonnegative_int(
        vector.get("trusted_count", 0),
        default=0,
        reason="invalid_trusted_profile_support",
        non_finite_reason="invalid_trusted_profile_support",
        allow_exact_text=False,
    )
    if support_reason:
        return {}, unavailable_bucket_probability_record(support_reason)
    maturity = vector.get("maturity")
    authority = vector.get("suppression_authority")
    if type(maturity) is not str or maturity not in {"cold", "warming", "mature"}:
        return {}, unavailable_bucket_probability_record(
            "invalid_profile_maturity", support=support,
        )
    if type(authority) is not float or authority not in {0.0, 0.35, 1.0}:
        return {}, unavailable_bucket_probability_record(
            "invalid_profile_suppression_authority", support=support,
        )
    if support < PROFILE_WARMING_MIN_TRUSTED_SUPPORT:
        return {}, unavailable_bucket_probability_record(
            "insufficient_trusted_profile_support",
            support=support,
            record_required=False,
        )
    return {
        "support": support,
        "maturity": maturity,
        "suppression_authority": authority,
    }, None


def bucket_text_or_failure_record(bucket: object, support: object) -> tuple[str, object | None]:
    """Return a validated bucket text key or explicit failure evidence."""
    bucket_text, bucket_reason = no_hook_text(
        bucket,
        missing_reason="missing_behavior_bucket",
        unsupported_reason="unsafe_behavior_bucket_rejected",
    )
    if bucket_reason:
        return "", unavailable_bucket_probability_record(bucket_reason, support=support)
    return bucket_text, None


def behavior_bucket_record_or_failure(
    baseline: object,
    bucket_text: object,
    support: object,
) -> tuple[object, object | None]:
    """Return selected bucket state or explicit malformed evidence."""
    bucket_items = no_hook_mapping_items(baseline.get("behavior_buckets"))
    if bucket_items is None:
        return {}, unavailable_bucket_probability_record(
            "malformed_behavior_bucket_profile", support=support,
        )
    bucket_record: object = {}
    for raw_bucket, raw_record in bucket_items:
        if type(raw_bucket) is str and str.__str__(raw_bucket) == bucket_text:
            bucket_record = raw_record
            break
    record_items = no_hook_mapping_items(bucket_record)
    if record_items is None:
        return {}, unavailable_bucket_probability_record(
            "malformed_behavior_bucket_record", support=support,
        )
    return {
        key: value for key, value in record_items if type(key) is str
    }, None


def behavior_bucket_observation_count_or_failure(
    record_values: object, support: object,
) -> tuple[int, object | None]:
    """Return validated observation count for one behavior bucket."""
    count, count_reason = no_hook_exact_nonnegative_int(
        record_values.get("files", 0),
        default=0,
        reason="invalid_behavior_bucket_observation_count",
        non_finite_reason="invalid_behavior_bucket_observation_count",
        allow_exact_text=False,
    )
    if count_reason:
        return 0, unavailable_bucket_probability_record(count_reason, support=support)
    return count, None


def bucket_empirical_probability_record(
    count: object, context: dict[str, object],
) -> object:
    """Use the single neutral estimator for a validated bucket snapshot."""
    return empirical_frequency_record(
        count,
        context["support"],
        minimum_support=PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
        maturity=context["maturity"],
        suppression_authority=context["suppression_authority"],
    )


__all__ = (
    "behavior_bucket_observation_count_or_failure",
    "behavior_bucket_record_or_failure",
    "bucket_empirical_probability_record",
    "bucket_text_or_failure_record",
    "profile_frequency_context_or_failure_record",
    "unavailable_bucket_probability_record",
)
