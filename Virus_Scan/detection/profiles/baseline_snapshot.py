"""Detection-owned immutable profile baseline snapshot boundary.

Detection may consult the public profile-learning baseline contract for learned
context, but detection stages must not mutate model-owned baseline dictionaries
or depend on profile module internals.  This boundary converts the public model
read into a small immutable detection snapshot before scoring/correlation owners
consume it.
"""
from __future__ import annotations

from collections.abc import Mapping
import math

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_duplicate_key,
    no_hook_json_key,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.detection.contracts.profile_baselines import ensure_extension_model_fields
from Virus_Scan.detection.profiles.baseline_probability import (
    behavior_bucket_record_or_failure,
    behavior_bucket_observation_count_or_failure,
    bucket_text_or_failure_record,
    bucket_empirical_probability_record,
    profile_frequency_context_or_failure_record,
    unavailable_bucket_probability_record,
)
from Virus_Scan.detection.registries.immutability import freeze_registry_value
from Virus_Scan.models.api.profile_contracts import get_extension_baseline


def _profile_snapshot_unavailable(reason: str, value: object) -> dict[str, object]:
    return {
        "value": None,
        "unavailable_reason": reason,
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _profile_snapshot_key_order(value: object) -> str:
    """Return a deterministic order key without caller-owned hooks."""
    if type(value) is str:
        return "str:" + str.__str__(value)
    if isinstance(value, str):
        return "str:" + str.__str__(value)
    if type(value) is bool:
        return "bool:" + bool.__str__(value)
    if type(value) is int:
        return "int:" + int.__str__(value)
    if type(value) is float:
        return "float:" + (float.__str__(value) if math.isfinite(value) else "non_finite")
    if type(value) in (bytes, bytearray, memoryview):
        return "bytes:" + bytes(value).hex()
    return no_hook_type_name(value) + ":unavailable"


def _jsonish_copy(value: object) -> object:
    """Copy JSON-like profile data without caller-owned hooks or mutable aliases."""
    items = no_hook_mapping_items(value)
    if items is not None:
        out: dict[str, object] = {}
        keyed: list[tuple[str, int, str, object, object]] = []
        for index, (raw_key, raw_item) in enumerate(items):
            key_text, key_reason = no_hook_json_key(raw_key, index, prefix="profile_baseline_key")
            keyed.append((key_text, index, key_reason, raw_key, raw_item))
        for raw_key_text, index, key_reason, raw_key, raw_item in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = no_hook_duplicate_key(key_text, index)
            if key_reason:
                out[key_text] = _profile_snapshot_unavailable(key_reason, raw_key)
            else:
                out[key_text] = _jsonish_copy(raw_item)
        return out
    if isinstance(value, Mapping):
        return _profile_snapshot_unavailable("profile_baseline_mapping_unavailable", value)
    if type(value) in (set, frozenset):
        return [
            _jsonish_copy(item)
            for item in sorted(value, key=_profile_snapshot_key_order)
        ]
    if type(value) in (list, tuple):
        return [_jsonish_copy(item) for item in value]
    if value is None or type(value) in (bool, int, float, str, bytes):
        return value
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) in (bytearray, memoryview):
        return bytes(value)
    return _profile_snapshot_unavailable("profile_baseline_value_unavailable", value)


def read_extension_baseline_snapshot(engine: str, file_path: object, *, evidence_context: object | None = None, router_identity: object | None = None) -> object:
    """Return an immutable detection-owned view of the public profile baseline."""
    if evidence_context is None:
        baseline_value = (
            get_extension_baseline(engine, file_path)
            if router_identity is None
            else get_extension_baseline(
                engine,
                file_path,
                router_identity=router_identity,
            )
        )
    else:
        baseline_value = (
            get_extension_baseline(
                engine,
                file_path,
                evidence_context=evidence_context,
            )
            if router_identity is None
            else get_extension_baseline(
                engine,
                file_path,
                evidence_context=evidence_context,
                router_identity=router_identity,
            )
        )
    baseline = _jsonish_copy(baseline_value)
    if type(baseline) is not dict:
        path_text, path_reason = no_hook_text(
            file_path,
            missing_reason="missing_extension_profile_path",
            unsupported_reason="unsafe_extension_profile_path_rejected",
        )
        baseline = {"extension": path_text if not path_reason else "", "files": 0, "tags": {}}
        if path_reason:
            baseline["unavailable_reason"] = path_reason
            baseline["final_json_must_record"] = True
            baseline["replay_record_required"] = True
    ensure_extension_model_fields(baseline)
    return freeze_registry_value(baseline)


def behavior_bucket_probability_record(
    engine: str,
    file_path: object,
    bucket: object,
) -> Mapping[str, object]:
    """Return learned bucket probability with explicit profile availability.

    Detection scoring consumes profile-owned learned counts only after they have
    been copied into this detection-owned snapshot.  This keeps bucket scoring
    from importing or mutating the profile model module directly while
    distinguishing cold, corrupt, and malformed profile states from an observed
    bucket whose learned probability is legitimately zero.
    """
    try:
        baseline = read_extension_baseline_snapshot(engine, file_path)
    except (TypeError, ValueError, AttributeError):
        return unavailable_bucket_probability_record(
            "extension_baseline_snapshot_unavailable",
        )
    context, context_failure = profile_frequency_context_or_failure_record(baseline)
    if context_failure is not None:
        return context_failure
    support = context['support']
    bucket_text, bucket_failure = bucket_text_or_failure_record(bucket, support)
    if bucket_failure is not None:
        return bucket_failure
    bucket_record, record_failure = behavior_bucket_record_or_failure(
        baseline,
        bucket_text,
        support,
    )
    if record_failure is not None:
        return record_failure
    count, count_failure = behavior_bucket_observation_count_or_failure(
        bucket_record,
        support,
    )
    if count_failure is not None:
        return count_failure
    return bucket_empirical_probability_record(count, context)


__all__ = (
    "behavior_bucket_probability_record",
    "read_extension_baseline_snapshot",
)
