"""Strict value utilities shared by canonical microcluster owners."""
from __future__ import annotations

from types import MappingProxyType
import math

from Virus_Scan.models.clustering.policy import CLUSTER_POLICY

_MAPPING_PROXY_TYPE = type(MappingProxyType({}))


def microcluster_mapping(value: object) -> dict[str, object]:
    if type(value) is dict:
        return dict(value)
    if type(value) is _MAPPING_PROXY_TYPE:
        return dict(value)
    return {}


def microcluster_value(snapshot: object, key: str, default: object = None) -> object:
    if type(snapshot) is dict:
        return dict.get(snapshot, key, default)
    if type(snapshot) is _MAPPING_PROXY_TYPE:
        return snapshot.get(key, default)
    return default


def finite_microcluster_value(value: object, default: float = 0.0) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        return default
    number = float(value)
    return number if math.isfinite(number) else default


def nonnegative_microcluster_int(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def microcluster_text(value: object, default: str = "") -> str:
    return str.strip(value) if type(value) is str and str.strip(value) else default


def microcluster_member_set(value: object) -> frozenset[str]:
    if type(value) not in (tuple, list, set, frozenset):
        return frozenset()
    return frozenset(
        text for item in value if (text := microcluster_text(item)) != ""
    )


def microcluster_text_set(value: object) -> frozenset[str]:
    if type(value) not in (tuple, list, set, frozenset):
        return frozenset()
    return frozenset(
        text.lower()
        for item in value
        if (text := microcluster_text(item).lower()) != ""
    )


def microcluster_count_pairs(value: object) -> tuple[tuple[str, int], ...]:
    if type(value) is dict:
        items = tuple(dict.items(value))
    elif type(value) in (tuple, list):
        items = tuple(value)
    else:
        return ()
    counts: dict[str, int] = {}
    for row in items:
        if type(row) not in (tuple, list) or len(row) != 2:
            continue
        key = microcluster_text(row[0]).lower()
        count = nonnegative_microcluster_int(row[1])
        if key and count:
            counts[key] = count
    return tuple(sorted(counts.items()))


def increment_microcluster_counts(value: object, terms: object) -> tuple[tuple[str, int], ...]:
    counts = dict(microcluster_count_pairs(value))
    for term in microcluster_text_set(terms):
        counts[term] = min(1_000_000, counts.get(term, 0) + 1)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple(sorted(ranked[:CLUSTER_POLICY.maximum_signature_terms]))


def microcluster_signature_terms(primary: object, quarantine: object) -> frozenset[str]:
    trusted = frozenset(key for key, count in microcluster_count_pairs(primary) if count > 0)
    if trusted:
        return trusted
    return frozenset(key for key, count in microcluster_count_pairs(quarantine) if count > 0)


def finite_microcluster_vector(value: object, expected: int) -> tuple[float, ...]:
    if type(value) not in (tuple, list) or len(value) != expected:
        return ()
    out: list[float] = []
    for item in value:
        number = finite_microcluster_value(item, float("nan"))
        if not math.isfinite(number):
            return ()
        out.append(number)
    return tuple(out)


def microcluster_distance(
    vector: tuple[float, ...],
    mean: tuple[float, ...],
    variance: tuple[float, ...],
) -> tuple[float, float]:
    if not vector or len(vector) != len(mean) or len(mean) != len(variance):
        return math.inf, math.inf
    squared = [(a - b) ** 2 for a, b in zip(vector, mean, strict=True)]
    radius = math.sqrt(sum(squared) / max(1, len(squared)))
    standardized = [
        delta / max(var, 0.0025)
        for delta, var in zip(squared, variance, strict=True)
    ]
    return radius, math.sqrt(sum(standardized) / max(1, len(standardized)))


def freeze_microcluster_snapshot(values: dict[str, object]) -> object:
    """Recursively detach one canonical snapshot into immutable built-in values.

    Only exact built-in containers are accepted.  This prevents caller-owned
    iterator, mapping, equality, or conversion hooks from executing while a
    snapshot is being published.
    """
    if type(values) is not dict:
        raise ValueError("microcluster_snapshot_not_exact_dict")

    def freeze(value: object) -> object:
        if value is None or type(value) in (str, bytes, bool, int, float):
            return value
        if type(value) is dict:
            frozen: dict[object, object] = {}
            for key, item in dict.items(value):
                if type(key) not in (str, int, float, bool, bytes):
                    raise ValueError("microcluster_snapshot_key_invalid")
                frozen[key] = freeze(item)
            return MappingProxyType(frozen)
        if type(value) is _MAPPING_PROXY_TYPE:
            frozen_proxy: dict[object, object] = {}
            for key, item in value.items():
                if type(key) not in (str, int, float, bool, bytes):
                    raise ValueError("microcluster_snapshot_key_invalid")
                frozen_proxy[key] = freeze(item)
            return MappingProxyType(frozen_proxy)
        if type(value) in (tuple, list):
            return tuple(freeze(item) for item in value)
        if type(value) in (set, frozenset):
            return frozenset(freeze(item) for item in value)
        raise ValueError("microcluster_snapshot_value_invalid")

    return freeze(values)


__all__ = (
    "finite_microcluster_value",
    "finite_microcluster_vector",
    "freeze_microcluster_snapshot",
    "increment_microcluster_counts",
    "microcluster_count_pairs",
    "microcluster_distance",
    "microcluster_mapping",
    "microcluster_member_set",
    "microcluster_signature_terms",
    "microcluster_text",
    "microcluster_text_set",
    "microcluster_value",
    "nonnegative_microcluster_int",
)
