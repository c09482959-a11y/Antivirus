"""Replayable materialization decisions for immutable scheduler outputs."""
from __future__ import annotations

from dataclasses import fields
import json
import math
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_decisions import (
    SchedulerMappingMaterializationDecision,
    scheduler_mapping_materialization_rejected,
    scheduler_mapping_materialized,
)
from Virus_Scan.scheduler.internal.immutable_output_support import (
    _materialize_scheduler_key,
    frozen_scheduler_items_decision,
    unsupported_scheduler_value_evidence,
)
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.immutable_dataclass_ownership import _internal_frozen_dataclass_decision



def materialize_scheduler_mapping_decision(value: object) -> SchedulerMappingMaterializationDecision:
    """Replayably convert immutable scheduler snapshots at serialization edges only."""
    value_type = no_hook_type_name(value)
    if value is None:
        evidence = unsupported_scheduler_value_evidence(value, field_name="scheduler_mapping")
        return scheduler_mapping_materialization_rejected(
            "scheduler_mapping_value_missing",
            value_type,
            value=None,
            evidence=evidence,
        )
    if type(value) is str:
        return scheduler_mapping_materialized(str.__str__(value), value_type)
    if type(value) is bool or type(value) is int:
        return scheduler_mapping_materialized(value, value_type)
    if type(value) is float:
        if math.isfinite(value):
            return scheduler_mapping_materialized(value, value_type)
        evidence = unsupported_scheduler_value_evidence(value)
        return scheduler_mapping_materialized(
            evidence,
            value_type,
            reason="scheduler_mapping_degraded_nonfinite_float",
            evidence=evidence,
        )

    frozen_decision = frozen_scheduler_items_decision(value)
    if frozen_decision.accepted:
        pairs = [
            (_materialize_scheduler_key(key, index), materialize_scheduler_mapping_decision(item).value)
            for index, (key, item) in enumerate(frozen_decision.items)
        ]
        return scheduler_mapping_materialized(dict(sorted(pairs, key=lambda pair: pair[0])), value_type)

    if type(value) is MappingProxyType or type(value) is dict:
        items = no_hook_mapping_items(value)
        if items is None:
            evidence = unsupported_scheduler_value_evidence(value)
            return scheduler_mapping_materialization_rejected(
                "scheduler_mapping_items_unavailable",
                value_type,
                value=evidence,
                evidence=evidence,
            )
        pairs = []
        for index, (key, item) in enumerate(items):
            materialized_key = _materialize_scheduler_key(key, index)
            materialized_value = materialize_scheduler_mapping_decision(item).value
            if materialized_key.startswith("unsupported_scheduler_key_"):
                materialized_value = unsupported_scheduler_value_evidence(
                    key,
                    field_name=materialized_key,
                )
            pairs.append((materialized_key, materialized_value))
        return scheduler_mapping_materialized(dict(sorted(pairs, key=lambda pair: pair[0])), value_type)

    if type(value) in {list, tuple}:
        return scheduler_mapping_materialized([materialize_scheduler_mapping_decision(item).value for item in value], value_type)
    if type(value) in {set, frozenset}:
        safe_items = [materialize_scheduler_mapping_decision(item).value for item in value]
        return scheduler_mapping_materialized(
            sorted(
                safe_items,
                key=lambda item: json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            ),
            value_type,
        )
    if _internal_frozen_dataclass_decision(value).accepted:
        out: dict[str, object] = {}
        for field in fields(value):
            item = scheduler_exact_attr(
                value,
                field.name,
                owner_type=type(value),
                default=unsupported_scheduler_value_evidence(value, field_name=field.name),
            )
            out[field.name] = materialize_scheduler_mapping_decision(item).value
        return scheduler_mapping_materialized(out, value_type)

    evidence = unsupported_scheduler_value_evidence(value)
    return scheduler_mapping_materialization_rejected(
        "scheduler_mapping_unsupported_value",
        value_type,
        value=evidence,
        evidence=evidence,
    )
