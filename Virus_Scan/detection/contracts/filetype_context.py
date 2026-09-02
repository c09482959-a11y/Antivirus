"""Detection-owned immutable filetype validation context.

This replaces detection imports from scanner binary helpers with a bounded
read-only contract consumed by scoring/correlation only. It does not mutate
scanner, runtime, model, or registry state.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_plain_instance_dict_status,
    no_hook_sequence_items,
    no_hook_type_name,
)
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.contracts.tag_evidence import safe_tag_evidence_text
from Virus_Scan.detection.registries.chain_registry import HIGH_RISK_BUCKETS
from Virus_Scan.utils.text_validation import text_boundary_value

if TYPE_CHECKING:
    from collections.abc import Mapping

NON_EXECUTION_CAPABILITIES = frozenset({"none"})
CONTAINER_EXECUTION_CAPABILITIES = frozenset(detection_registry_value("CONTAINER_EXECUTION_CAPABILITIES", frozenset({"container"})))
DEFAULT_DETECTION_ENGINES = frozenset({"renpy", "rpgm", "unity", "media", "other", "unknown"})


@dataclass(frozen=True)
class FiletypePolicyUnavailable:
    """Typed evidence for unavailable detection filetype policy materialization."""

    reason: str
    field_name: str
    value_type: str

    def as_evidence(self) -> dict[str, object]:
        return {
            "filetype_policy_unavailable": True,
            "reason": self.reason,
            "field_name": self.field_name,
            "value_type": self.value_type,
            "detection_contract": "filetype_validation_context",
            "replay_must_record": True,
        }


def _filetype_policy_unavailable(reason: str, field_name: str, value: object) -> FiletypePolicyUnavailable:
    return FiletypePolicyUnavailable(
        reason=reason,
        field_name=field_name,
        value_type=no_hook_type_name(value),
    )


def _is_policy_unavailable(value: object) -> bool:
    return isinstance(value, FiletypePolicyUnavailable)


def _extension_token(file_path: object) -> str:
    text = (text_boundary_value(file_path, unsupported="") or "").strip()
    lowered = text.replace("\\", "/").lower()
    for special in ("global-metadata.dat", "metadata.dat"):
        if lowered.endswith(special):
            return special
    return Path(text).suffix.lower().lstrip(".")


def _policy_mapping(value: object) -> Mapping[object, object] | FiletypePolicyUnavailable:
    items = _policy_mapping_items(value)
    if isinstance(items, FiletypePolicyUnavailable):
        return items
    return {key: item for key, item in items}


def _plain_instance_backing(value: object, field_name: str) -> object | FiletypePolicyUnavailable:
    fields, reason = no_hook_plain_instance_dict_status(value)
    if fields is None:
        evidence_reason = reason if reason == "custom_getattribute" else "plain_instance_backing_unavailable"
        return _filetype_policy_unavailable(evidence_reason, field_name, value)
    return dict.get(fields, field_name)


def _policy_mapping_items(value: object) -> tuple[tuple[object, object], ...] | FiletypePolicyUnavailable:
    items = no_hook_mapping_items(value)
    if items is not None:
        return items
    backing = _plain_instance_backing(value, "_data")
    if type(backing) is dict:
        try:
            return tuple(dict.items(backing))
        except RECOVERABLE_RUNTIME_ERRORS:
            return _filetype_policy_unavailable("policy_mapping_items_unavailable", "_data", value)
    if isinstance(backing, FiletypePolicyUnavailable):
        return backing
    return _filetype_policy_unavailable("policy_mapping_backing_missing", "_data", value)


def _policy_sequence_items(values: object) -> tuple[object, ...] | FiletypePolicyUnavailable:
    items = no_hook_sequence_items(values)
    if items or type(values) in (tuple, list, set, frozenset, str, bytes, bytearray, int, float, bool) or values is None:
        return items
    backing = _plain_instance_backing(values, "_values")
    if type(backing) is tuple:
        return backing
    if type(backing) is list:
        return tuple(backing)
    if type(backing) is set:
        return tuple(backing)
    if type(backing) is frozenset:
        try:
            return tuple(backing)
        except RECOVERABLE_RUNTIME_ERRORS:
            return _filetype_policy_unavailable("policy_sequence_items_unavailable", "_values", values)
    if isinstance(backing, FiletypePolicyUnavailable):
        return backing
    return _filetype_policy_unavailable("policy_sequence_backing_missing", "_values", values)


def _policy_get(mapping: object, key: object, default: object = None) -> object:
    items = _policy_mapping_items(mapping)
    if isinstance(items, FiletypePolicyUnavailable):
        return default
    for item_key, item_value in items:
        if type(item_key) is str and type(key) is str and str.__str__(item_key) == str.__str__(key):
            return item_value
    return default


def _policy_items(mapping: object) -> tuple[tuple[object, object], ...]:
    items = _policy_mapping_items(mapping)
    if isinstance(items, FiletypePolicyUnavailable):
        return ()
    return items


def _policy_record_dict(record: object) -> dict[str, object]:
    items = _policy_mapping_items(record)
    if isinstance(items, FiletypePolicyUnavailable):
        return {}
    out: dict[str, object] = {}
    for key, value in items:
        if type(key) is str:
            out[str.__str__(key)] = value
    return out


def _ordered_bucket_values(values: object) -> tuple[str, ...]:
    if values is None:
        return ()
    items = _policy_sequence_items(values)
    if isinstance(items, FiletypePolicyUnavailable):
        return ("filetype_bucket_unavailable",)
    out = set()
    for item in items:
        text = safe_tag_evidence_text(item).strip().lower()
        if text:
            out.add(text)
    return tuple(sorted(out))


def _copy_policy_record(record: object, *, bucket: str, extension: str) -> dict[str, object]:
    data = _policy_record_dict(record)
    return {
        "bucket": bucket,
        "extension": extension,
        "execution_capability": safe_tag_evidence_text(data.get("execution_capability", "unknown"), "unknown").lower(),
        "normal_buckets": _ordered_bucket_values(data.get("normal_buckets", ())),
        "rare_buckets": _ordered_bucket_values(data.get("rare_buckets", ())),
        "high_risk_buckets": _ordered_bucket_values(data.get("high_risk_buckets", ())),
    }


def _policy_extensions(info: object) -> frozenset[str] | FiletypePolicyUnavailable:
    values = _policy_get(info, "extensions", ())
    out: set[str] = set()
    if values is None:
        return frozenset()
    items = _policy_sequence_items(values)
    if isinstance(items, FiletypePolicyUnavailable):
        return items
    for item in items:
        text = safe_tag_evidence_text(item).lower().lstrip(".")
        if text:
            out.add(text)
    return frozenset(sorted(out))


def _unknown_filetype_info(
    bucket: str,
    extension: str,
    unavailable: FiletypePolicyUnavailable | None = None,
) -> dict[str, object]:
    info: dict[str, object] = {
        "bucket": bucket,
        "extension": extension,
        "execution_capability": "unknown",
        "normal_buckets": (),
        "rare_buckets": (),
        "high_risk_buckets": (),
    }
    if unavailable is not None:
        info.update(unavailable.as_evidence())
    return info


def get_engine_filetype_info(engine: object, file_path: object) -> dict[str, object]:
    engine_name = safe_tag_evidence_text(engine, "other").lower()
    if engine_name not in DEFAULT_DETECTION_ENGINES:
        engine_name = "other"
    ext = _extension_token(file_path)
    engine_policies = _policy_mapping(detection_registry_value("ENGINE_SPECIFIC_FILETYPE_BUCKETS", {}))
    if isinstance(engine_policies, FiletypePolicyUnavailable):
        return _unknown_filetype_info("unknown_engine", ext, engine_policies)
    engine_bucket_policies = _policy_get(engine_policies, engine_name, {})
    for bucket, info in _policy_items(engine_bucket_policies):
        extensions = _policy_extensions(info)
        if isinstance(extensions, FiletypePolicyUnavailable):
            return _unknown_filetype_info("unknown_engine", ext, extensions)
        if ext in extensions:
            return _copy_policy_record(info, bucket=safe_tag_evidence_text(bucket, "unknown").strip(), extension=ext)
    return _unknown_filetype_info("unknown_engine", ext)


def get_global_filetype_info(file_path: object) -> dict[str, object]:
    ext = _extension_token(file_path)
    global_policies = _policy_mapping(detection_registry_value("GLOBAL_COMMON_FILETYPE_BUCKETS", {}))
    if isinstance(global_policies, FiletypePolicyUnavailable):
        return _unknown_filetype_info("unknown_global", ext, global_policies)
    for bucket, info in _policy_items(global_policies):
        extensions = _policy_extensions(info)
        if isinstance(extensions, FiletypePolicyUnavailable):
            return _unknown_filetype_info("unknown_global", ext, extensions)
        if ext in extensions:
            return _copy_policy_record(info, bucket=safe_tag_evidence_text(bucket, "unknown").strip(), extension=ext)
    return _unknown_filetype_info("unknown_global", ext)


def filetype_validation_context(engine: object, file_path: object) -> dict[str, object]:
    global_info = get_global_filetype_info(file_path)
    engine_info = get_engine_filetype_info(engine, file_path)
    active = engine_info if engine_info.get("bucket") != "unknown_engine" else global_info
    capability = safe_tag_evidence_text(active.get("execution_capability", "unknown"), "unknown").lower()
    normal = set(global_info.get("normal_buckets", set())) | set(engine_info.get("normal_buckets", set()))
    rare = set(global_info.get("rare_buckets", set())) | set(engine_info.get("rare_buckets", set()))
    high = set(global_info.get("high_risk_buckets", set())) | set(engine_info.get("high_risk_buckets", set()))
    if capability in NON_EXECUTION_CAPABILITIES:
        high |= set(HIGH_RISK_BUCKETS)
    context = {
        "global_bucket": global_info.get("bucket"),
        "engine_bucket": engine_info.get("bucket"),
        "active_bucket": active.get("bucket"),
        "extension": active.get("extension"),
        "execution_capability": capability,
        "normal_buckets": _ordered_bucket_values(normal),
        "rare_buckets": _ordered_bucket_values(rare),
        "high_risk_buckets": _ordered_bucket_values(high),
    }
    for evidence_key in (
        "filetype_policy_unavailable",
        "reason",
        "field_name",
        "value_type",
        "detection_contract",
        "replay_must_record",
    ):
        if evidence_key in active:
            context[evidence_key] = active[evidence_key]
    return context


__all__ = (
    "CONTAINER_EXECUTION_CAPABILITIES",
    "NON_EXECUTION_CAPABILITIES",
    "FiletypePolicyUnavailable",
    "filetype_validation_context",
    "get_engine_filetype_info",
    "get_global_filetype_info",
)
