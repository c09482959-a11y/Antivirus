"""Shared analytical evidence contracts for runtime and detection calibration.

The runtime calibration bundle and pure detection calibration bundle have
different lineage ownership, but the format-oddity baselines, tag-family
projection, and correlation ceiling are one repository-wide analytical evidence
contract.  Keeping the computation here prevents duplicate calibration
authority while still allowing runtime and detection wrappers to own their
side-effect boundaries separately.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_finite_float, no_hook_mapping_items, no_hook_optional_sequence_items, no_hook_text, no_hook_type_name
from Virus_Scan.utils.probability import centered_sigmoid_probability


ANALYTICAL_EVIDENCE_SCHEMA_VERSION = "stage32_event_native_v1"
AnalyticalValue = object
AnalyticalRecord = dict[str, AnalyticalValue]
AnalyticalItems = tuple[tuple[AnalyticalValue, AnalyticalValue], ...]


def analytical_text_sequence(
    value: AnalyticalValue | None,
    *,
    missing_reason: str = "missing_analytical_sequence_text",
    unsupported_reason: str = "unsafe_analytical_sequence_text_rejected",
) -> tuple[str, ...]:
    """Return analytical sequence text without caller-owned conversions.

    Exact primitive values are preserved through the canonical no-hook text
    contract. Unsupported sequence members are represented by deterministic
    explicit evidence tokens so calibration counts and lineage do not silently
    collapse while hostile ``__str__``/``__repr__``/``__format__`` hooks remain
    unexecuted.
    """
    safe_missing_reason = str.__str__(missing_reason) if type(missing_reason) is str and missing_reason else "missing_analytical_sequence_text"
    safe_unsupported_reason = str.__str__(unsupported_reason) if type(unsupported_reason) is str and unsupported_reason else "unsafe_analytical_sequence_text_rejected"
    texts: list[str] = []
    for item in no_hook_optional_sequence_items(value):
        text, reason = no_hook_text(
            item,
            missing_reason=safe_missing_reason,
            unsupported_reason=safe_unsupported_reason,
        )
        if reason == "" and text:
            texts.append(text)
        elif reason:
            texts.append(reason + ":" + no_hook_type_name(item))
    return tuple(texts)


def _analytical_text_values(value: AnalyticalValue) -> tuple[str, ...]:
    return analytical_text_sequence(
        value,
        missing_reason="missing_analytical_text",
        unsupported_reason="unsafe_analytical_text_value_rejected",
    )


def _owned_mapping_items(value: AnalyticalValue) -> AnalyticalItems | None:
    """Return owned mapping items without delegating into caller mappings."""
    if value is None:
        return ()
    return no_hook_mapping_items(value, allow_dict_subclass=True)


def _owned_mapping_get(value: AnalyticalValue, key: str, default: AnalyticalValue) -> AnalyticalValue:
    """Read an exact string key from owned mapping items without mapping hooks."""
    items = _owned_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def analytical_optional_text(value: AnalyticalValue, *, default: str = "") -> str:
    """Return text for analytical evidence without caller-owned hooks."""
    if value is None:
        return default
    if isinstance(value, Path):
        try:
            return Path.__str__(value)
        except RECOVERABLE_RUNTIME_ERRORS:
            return default
    text, reason = no_hook_text(
        value,
        missing_reason="missing_analytical_text",
        unsupported_reason="unsafe_analytical_text_value_rejected",
    )
    return text if reason == "" else default


def analytical_optional_sequence(value: Iterable[AnalyticalValue] | None) -> tuple[AnalyticalValue, ...]:
    """Snapshot optional analytical sequences without caller-owned iteration."""
    return _analytical_optional_items(value)


def analytical_mapping_size(value: Mapping[AnalyticalValue, AnalyticalValue] | None) -> tuple[int, str | None]:
    """Return owned mapping size while preserving unreadable/unavailable evidence."""
    items = _owned_mapping_items(value)
    if items is None:
        if isinstance(value, Mapping):
            return 0, "unreadable_graph_features"
        return 0, "non_mapping_graph_features"
    return len(items), None


def analytical_count_value(value: AnalyticalValue) -> int:
    count, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason="unsafe_analytical_count_value_rejected",
        non_finite_reason="nonfinite_analytical_count_value",
        allow_exact_text=False,
    )
    if reason:
        return 0
    return count


def analytical_finite_float(value: AnalyticalValue, default: float = 0.0) -> float:
    """Return a finite analytical-model float without caller-owned conversion."""
    number, _reason = no_hook_finite_float(
        value,
        default=default,
        reason="unsafe_analytical_numeric_value_rejected",
        non_finite_reason="nonfinite_analytical_value",
        allow_exact_text=False,
    )
    return number


def analytical_numeric_readiness(value: AnalyticalValue) -> AnalyticalRecord:
    """Describe whether a numeric analytical input was finite and usable."""
    _number, reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="unsafe_analytical_numeric_value_rejected",
        non_finite_reason="nonfinite_analytical_value",
        allow_exact_text=False,
    )
    if reason:
        return {"ready": False, "reason": reason}
    return {"ready": True, "reason": "finite_analytical_value"}


def analytical_format_baseline(entropy_mean: float, entropy_std: float) -> Mapping[str, float]:
    return MappingProxyType({"entropy_mean": analytical_finite_float(entropy_mean), "entropy_std": analytical_finite_float(entropy_std, 1.0)})


FORMAT_ODDITY_BASELINES: Mapping[str, Mapping[str, float]] = MappingProxyType({
    "png": analytical_format_baseline(7.25, 0.45),
    "jpg": analytical_format_baseline(7.55, 0.35),
    "jpeg": analytical_format_baseline(7.55, 0.35),
    "webp": analytical_format_baseline(7.45, 0.40),
    "gif": analytical_format_baseline(6.60, 0.65),
    "ogg": analytical_format_baseline(7.35, 0.45),
    "mp3": analytical_format_baseline(7.40, 0.45),
    "wav": analytical_format_baseline(6.20, 0.90),
    "zip": analytical_format_baseline(7.70, 0.25),
    "7z": analytical_format_baseline(7.85, 0.15),
    "rar": analytical_format_baseline(7.80, 0.20),
    "exe": analytical_format_baseline(6.40, 0.95),
    "dll": analytical_format_baseline(6.35, 0.95),
    "rpyc": analytical_format_baseline(6.80, 0.75),
    "rpa": analytical_format_baseline(7.35, 0.55),
    "rpy": analytical_format_baseline(4.80, 1.10),
    "js": analytical_format_baseline(5.20, 1.10),
    "cs": analytical_format_baseline(5.00, 1.10),
    "txt": analytical_format_baseline(4.60, 1.10),
    "json": analytical_format_baseline(4.80, 1.00),
    "xml": analytical_format_baseline(4.70, 1.00),
    "default": analytical_format_baseline(6.20, 1.20),
})


ANALYTICAL_TAG_FAMILIES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "execution": ("exec", "process", "powershell", "cmd", "shell", "createprocess", "virtualalloc", "createremotethread", "dllimport"),
    "network": ("url", "http", "socket", "fetch", "xmlhttprequest", "c2", "download", "exfil"),
    "persistence": ("persist", "registry", "startup", "autorun", "scheduled_task"),
    "obfuscation": ("base64", "encoded", "obfus", "packed", "xor", "gzip"),
    "serialization": ("pickle", "reduce", "rpyc", "deserialize"),
})


def analytical_extension_from_path(path: AnalyticalValue) -> str:
    try:
        suffix = Path(analytical_optional_text(path, default="")).suffix
    except RECOVERABLE_RUNTIME_ERRORS:
        return "default"
    value = suffix[1:].casefold() if suffix.startswith(".") else suffix.casefold()
    return value or "default"


def analytical_family_counts(tags: Iterable[AnalyticalValue]) -> dict[str, int]:
    tag_text = " ".join(text.lower() for text in _analytical_text_values(tags))
    counts: dict[str, int] = {}
    for family, needles in _owned_mapping_items(ANALYTICAL_TAG_FAMILIES) or ():
        if type(family) is not str or type(needles) is not tuple:
            continue
        counts[str.__str__(family)] = sum(
            1 for needle in needles if type(needle) is str and needle in tag_text
        )
    return counts


def analytical_root_family_counts(tags: Iterable[AnalyticalValue]) -> dict[str, int]:
    """Count each canonical root tag at most once per analytical family."""
    tag_values = tuple(text.casefold() for text in _analytical_text_values(tags))
    counts: dict[str, int] = {}
    for family, needles in _owned_mapping_items(ANALYTICAL_TAG_FAMILIES) or ():
        if type(family) is not str or type(needles) is not tuple:
            continue
        counts[str.__str__(family)] = sum(
            1
            for tag_text in tag_values
            if any(
                type(needle) is str and needle in tag_text
                for needle in needles
            )
        )
    return counts


def analytical_correlation_ceiling(families: Mapping[str, int]) -> AnalyticalRecord:
    items = _owned_mapping_items(families)
    if items is None:
        return {
            "active_families": {},
            "capped_family_counts": {},
            "correlation_multiplier": 0.35,
            "unavailable_reason": "non_mapping_analytical_family_counts",
            "value_type": no_hook_type_name(families),
        }
    active_items = tuple(
        (key_text, count)
        for key, value in items
        if (key_text := analytical_optional_text(key))
        if (count := analytical_count_value(value)) > 0
    )
    capped_items = tuple((key, min(value, 3)) for key, value in active_items)
    active = dict(active_items)
    capped = dict(capped_items)
    total_active = sum(value for _key, value in active_items)
    amplification = sum(value for _key, value in capped_items) / max(1, total_active)
    return {
        "active_families": active,
        "capped_family_counts": capped,
        "correlation_multiplier": round(max(0.35, min(1.0, amplification)), 4),
    }


def analytical_format_oddity_snapshot(
    path: AnalyticalValue = None,
    entropy: AnalyticalValue = None,
    tags: Iterable[AnalyticalValue] | None = None,
) -> AnalyticalRecord:
    ext = analytical_extension_from_path(path)
    base = FORMAT_ODDITY_BASELINES.get(ext, FORMAT_ODDITY_BASELINES["default"])
    tag_text = " ".join(text.lower() for text in _analytical_text_values(tags))
    ent = None
    entropy_reason = None
    if entropy is not None:
        ent_value, reason = no_hook_finite_float(
            entropy,
            default=0.0,
            reason="unsafe_entropy_numeric_value_rejected",
            non_finite_reason="nonfinite_entropy",
            allow_exact_text=False,
        )
        if reason:
            entropy_reason = reason
        else:
            ent = ent_value
    if ent is None:
        inferred = any(term in tag_text for term in ("high_entropy", "packed", "obfus", "payload", "stego"))
        if entropy_reason:
            confidence_source = entropy_reason + "_unavailable"
        elif inferred:
            confidence_source = "tag_inferred_oddity"
        else:
            confidence_source = "no_oddity_signal"
        return {
            "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
            "evidence_type": "format_oddity",
            "format": ext,
            "entropy": None,
            "zscore": None,
            "confidence": 0.0 if entropy_reason else (0.30 if inferred else 0.0),
            "confidence_source": confidence_source,
            "ready": entropy_reason is None,
            "unavailable_reason": entropy_reason,
        }
    mean = analytical_finite_float(_owned_mapping_get(base, "entropy_mean", FORMAT_ODDITY_BASELINES["default"]["entropy_mean"]))
    std = max(0.05, analytical_finite_float(_owned_mapping_get(base, "entropy_std", FORMAT_ODDITY_BASELINES["default"]["entropy_std"]), 1.0))
    zscore = (ent - mean) / std
    return {
        "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        "evidence_type": "format_oddity",
        "format": ext,
        "entropy": round(ent, 4),
        "mean": mean,
        "std": std,
        "zscore": round(zscore, 4),
        "confidence": round(centered_sigmoid_probability(abs(zscore), midpoint=2.0, scale=0.8, min_scale=0.05), 4),
        "confidence_source": "per_format_zscore",
    }


__all__ = (
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "ANALYTICAL_TAG_FAMILIES",
    "FORMAT_ODDITY_BASELINES",
    "analytical_correlation_ceiling",
    "analytical_extension_from_path",
    "analytical_family_counts",
    "analytical_finite_float",
    "analytical_format_oddity_snapshot",
    "analytical_mapping_size",
    "analytical_numeric_readiness",
    "analytical_root_family_counts",
    "analytical_optional_sequence",
    "analytical_optional_text",
    "analytical_text_sequence",
)
