"""Test construction for exact-current complete runtime-model records."""
from __future__ import annotations

from Virus_Scan.contracts.markov_learning import MARKOV_STATE_SCHEMA_VERSION
from Virus_Scan.contracts.runtime_model_state import RUNTIME_MODEL_STATE_SCHEMA_VERSION
from Virus_Scan.runtime.temporal_state import TemporalStateOwner


def current_runtime_model_record(overrides: dict[str, object] | None = None, **fields: object) -> dict[str, object]:
    """Return one complete current envelope with caller-selected section values."""
    record: dict[str, object] = {
        "schema_version": RUNTIME_MODEL_STATE_SCHEMA_VERSION,
        "updated": 0,
        "markov_state_schema_version": MARKOV_STATE_SCHEMA_VERSION,
        "markov_state_migration_evidence": "canonical_initial_contextual_state",
        "transition_counts": [],
        "global_tag_baseline": {},
        "global_tag_pair_baseline": [],
        "filetype_baseline": {},
        "cluster_state": {},
        "temporal_state": TemporalStateOwner().to_record(),
        "learning_applied_keys": {"markov": [], "filetype": []},
    }
    if overrides is not None:
        if type(overrides) is not dict:
            raise TypeError("runtime_model_test_overrides_invalid")
        record.update(overrides)
    record.update(fields)
    return record


__all__ = ("current_runtime_model_record",)
