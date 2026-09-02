"""Support helpers for the canonical causal event stream.

This module owns no-hook text, numeric, mapping, and stable-payload helper
primitives used by :mod:`Virus_Scan.runtime.causal_event_stream`.  Keeping the
primitive helpers here leaves the public event stream module focused on event
contracts and append/replay orchestration while preserving the same executable
contracts.
"""
from __future__ import annotations

import hashlib
from types import MappingProxyType
from typing import Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import (
    exact_int_or_none,
    no_hook_failure,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)

from .causal_text import (
    causal_scalar_token,
    causal_sort_key,
    causal_text,
    causal_text_default,
)
from .governance_inputs import runtime_input_rejection

if TYPE_CHECKING:
    from .causal_event_stream import CausalEvent, WorkloadEventBudget


def _causal_failure(reason: str, value: object) -> Mapping[str, object]:
    return MappingProxyType(no_hook_failure(reason, value))

def _causal_int(value: object, default: int = 0) -> int:
    metric = exact_int_or_none(value)
    if metric is None:
        return default
    return metric

def _causal_optional_int(value: object) -> int | None:
    return exact_int_or_none(value)

def _causal_owned_text(*parts: str) -> str:
    return "".join(parts)

def _causal_indexed_text(prefix: str, index: int) -> str:
    return str.__add__(prefix, str(index))

def _causal_indexed_suffixed_text(prefix: str, index: int, suffix: str) -> str:
    return _causal_owned_text(prefix, str(index), suffix)

def _causal_suffixed_text(text: str, marker: str, number: int) -> str:
    return _causal_owned_text(text, marker, str(number))

def _causal_field_text(prefix: str, field_name: str) -> str:
    return str.__add__(prefix, field_name)

def _causal_field_reason(field_name: str, suffix: str) -> str:
    return str.__add__(field_name, suffix)

def _causal_invalid_payload_key(index: int) -> str:
    return _causal_indexed_text("invalid_payload_key_", index)

def _causal_checkpoint_event_field(index: int, suffix: str = "") -> str:
    return _causal_indexed_suffixed_text("causal_checkpoint_event_", index, suffix)

def _causal_invalid_key_part(key: str, reason: str) -> str:
    return _causal_owned_text(key, "=<invalid_key:", reason, ">")

def _causal_scalar_part(key: str, value: object) -> str:
    return _causal_owned_text(key, "=", causal_scalar_token(value))

def _causal_sequence_scalar_part(key: str, value: tuple[object, ...] | list[object]) -> str:
    return _causal_owned_text(
        key,
        "=(",
        ",".join(causal_scalar_token(item) for item in value),
        ")",
    )

def _causal_type_part(key: str, value: object) -> str:
    return _causal_owned_text(key, "=<", no_hook_type_name(value), ">")

def _causal_non_materializable_mapping_token(value: object) -> str:
    return _causal_owned_text(
        "non_materializable_causal_mapping:", no_hook_type_name(value)
    )

def _causal_event_key(domain: str, kind: str, version: int, payload_key: str) -> str:
    return _causal_owned_text(domain, ":", kind, ":v", str(version), ":", payload_key)

def _causal_lineage_seed(workload_text: str, domain_text: str, kind_text: str, seq: int) -> str:
    return _causal_owned_text(
        "umige:", workload_text, ":", domain_text, ":", kind_text, ":", str(seq)
    )

def _causal_digest_material(
    parent_digest: str, seq: int, domain: str, kind: str, event_key: str
) -> str:
    return _causal_owned_text(parent_digest, "|", str(seq), "|", domain, "|", kind, "|", event_key)

def _causal_event_row_without_timestamp(event: "CausalEvent") -> dict[str, object]:
    return {
        key: value
        for key, value in tuple(dict.items(event.as_dict()))
        if key != "timestamp"
    }

def _causal_payload_key_names(payload: Mapping[str, object]) -> tuple[str, ...]:
    items = no_hook_mapping_items(payload)
    if items is None:
        return ()
    return tuple(sorted(causal_text(key, empty="causal_text_empty") for key, _value in items))

def _causal_domain_edge(parent: "CausalEvent", event: "CausalEvent") -> str:
    return _causal_owned_text(parent.domain, "->", event.domain)

def _causal_counter_values(counter: dict[object, int]) -> tuple[int, ...]:
    return tuple(dict.values(counter))

def _causal_counter_items(counter: dict[object, int]) -> tuple[tuple[object, int], ...]:
    return tuple(dict.items(counter))

def _causal_event_cost(value: object) -> float:
    return _causal_finite_float(value, 0.0, minimum=0.0)

def _causal_max_counter_value(counter: dict[object, int]) -> int:
    values = _causal_counter_values(counter)
    if not values:
        return 0
    return max(values)

def _causal_positive_counter_keys(counter: dict[object, int]) -> tuple[object, ...]:
    return tuple(key for key, count in _causal_counter_items(counter) if count > 0)

def _causal_budget_suppressed_values(budgets: dict[str, "WorkloadEventBudget"]) -> tuple[int, ...]:
    return tuple(budget.suppressed for budget in tuple(dict.values(budgets)))

def _causal_sorted_counter(counter: dict[object, int]) -> dict[object, int]:
    return dict(sorted(_causal_counter_items(counter)))

def _causal_event_type_key(domain: str, kind: str) -> str:
    return _causal_owned_text(domain, ":", kind)

def _causal_dependency_edge(parent: "CausalEvent", event: "CausalEvent") -> str:
    return _causal_owned_text(parent.domain, ":", parent.kind, "->", event.domain, ":", event.kind)

def _causal_event_node(event: "CausalEvent") -> dict[str, object]:
    return {
        "id": event.seq,
        "label": _causal_event_type_key(event.domain, event.kind),
        "domain": event.domain,
        "kind": event.kind,
        "lineage_id": event.lineage_id,
        "depth": event.causal_depth,
        "digest": event.causal_digest,
    }

def _causal_text_token(value: object, *, empty: str = "causal_text_empty") -> str:
    if (
        isinstance(value, (str, bytes, bytearray))
        or type(value) is bool
        or type(value) is int
        or type(value) is float
        or value is None
    ):
        return causal_text(value, empty=empty)
    return _causal_owned_text("causal_text_unavailable:", no_hook_type_name(value))

def _causal_finite_float(
    value: object,
    default: float = 0.0,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    metric, _reason = no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        allow_exact_text=False,
    )
    return metric

def _causal_payload_items(value: object) -> tuple[tuple[object, object], ...] | None:
    return no_hook_mapping_items(value)

def _causal_payload_for_contract(value: object) -> dict[str, object]:
    if value is None:
        return {}
    items = _causal_payload_items(value)
    if items is None:
        return {
            "payload_unavailable": no_hook_failure(
                "non_materializable_causal_payload_mapping", value
            )
        }
    out: dict[str, object] = {}
    for index, (key, item) in enumerate(items):
        if type(key) is str:
            out[str.__str__(key)] = item
        else:
            out[_causal_invalid_payload_key(index)] = no_hook_failure(
                "invalid_causal_payload_key", key
            )
    return out

def _freeze_causal_value(value: object) -> object:
    items = _causal_payload_items(value)
    if items is not None:
        out: dict[str, object] = {}
        used: dict[str, int] = {}
        keyed: list[tuple[str, int, object, object, str]] = []
        for index, (raw_key, raw_value) in enumerate(items):
            key = _causal_text_token(raw_key, empty="causal_text_empty")
            keyed.append((key, index, raw_key, raw_value, ""))
        for key, _index, raw_key, raw_value, reason in sorted(
            keyed, key=lambda row: (row[0], row[1])
        ):
            duplicate = used.get(key, 0)
            used[key] = duplicate + 1
            output_key = _causal_suffixed_text(key, "#", duplicate) if duplicate else key
            if reason:
                out[output_key] = _causal_failure(reason, raw_key)
            else:
                out[output_key] = _freeze_causal_value(raw_value)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return _causal_failure("non_materializable_causal_mapping", value)
    if type(value) in (set, frozenset):
        return tuple(_freeze_causal_value(item) for item in sorted(value, key=causal_sort_key))
    if type(value) in (list, tuple):
        return tuple(_freeze_causal_value(item) for item in value)
    if isinstance(value, (str, bytes, bytearray)):
        return causal_text(value, empty="causal_text_empty")
    if type(value) is bool or type(value) is int or type(value) is float or value is None:
        return value
    return causal_text(value, empty="causal_text_empty")

def _causal_runtime_text(
    value: object, *, field_name: str, default: str
) -> tuple[str, tuple[Mapping[str, object], ...]]:
    projected = causal_text_default(value, default)
    _, reason = no_hook_text(
        value,
        missing_reason=_causal_field_reason(field_name, "_missing"),
        unsupported_reason=_causal_field_reason(field_name, "_rejected"),
    )
    if not reason:
        return projected, ()
    return projected, (runtime_input_rejection(field_name, value, reason),)

def _payload_with_input_evidence(
    payload: object, evidence: tuple[Mapping[str, object], ...]
) -> object:
    frozen = _freeze_causal_value({} if payload is None else payload)
    if not evidence:
        return frozen
    items = no_hook_mapping_items(frozen)
    out = dict(items) if items is not None else {"payload": frozen}
    out["input_evidence"] = evidence
    return _freeze_causal_value(out)

def _stable_payload_key(payload: Mapping[str, object] | None) -> str:
    if payload is None:
        return "empty"
    items = _causal_payload_items(payload)
    if items is None:
        if isinstance(payload, Mapping):
            token = _causal_non_materializable_mapping_token(payload)
        else:
            token = causal_text(payload, empty="causal_text_empty")
        return hashlib.sha1(
            token.encode("utf-8", "replace"), usedforsecurity=False
        ).hexdigest()[:16]
    if not items:
        return "empty"
    parts = []
    used: dict[str, int] = {}
    keyed: list[tuple[str, int, object, str]] = []
    for index, (raw_key, v) in enumerate(items):
        key = _causal_text_token(raw_key, empty="causal_text_empty")
        keyed.append((key, index, v, ""))
    for k, _index, v, reason in sorted(keyed, key=lambda row: (row[0], row[1])):
        dup = used.get(k, 0)
        used[k] = dup + 1
        part_key = _causal_suffixed_text(k, "#", dup) if dup else k
        if reason:
            parts.append(_causal_invalid_key_part(part_key, reason))
        elif type(v) in (str, bytes, bytearray, int, float, bool) or v is None:
            parts.append(_causal_scalar_part(part_key, v))
        elif (
            type(v) in (tuple, list)
            and len(v) <= 8
            and all(
                type(x) in (str, bytes, bytearray, int, float, bool) or x is None
                for x in v
            )
        ):
            parts.append(_causal_sequence_scalar_part(part_key, v))
        else:
            parts.append(_causal_type_part(part_key, v))
    return hashlib.sha1(
        "|".join(parts).encode("utf-8", "replace"), usedforsecurity=False
    ).hexdigest()[:16]
