"""Strict current-schema replay-key ledger validation for clustering snapshots."""
from __future__ import annotations

from Virus_Scan.models.clustering.policy import CLUSTER_POLICY


def cluster_snapshot_learning_keys(value: object) -> tuple[dict[str, int], str]:
    if type(value) is not dict:
        return {}, "invalid_cluster_applied_learning_keys"
    if len(value) > CLUSTER_POLICY.maximum_learning_keys:
        return {}, "cluster_learning_replay_keys_unbounded"
    applied: dict[str, int] = {}
    for raw_key, raw_ordinal in tuple(value.items()):
        if type(raw_key) is not str:
            return {}, "invalid_cluster_learning_replay_key"
        key = str.strip(raw_key)
        if len(key) != 64 or any(char not in "0123456789abcdef" for char in key):
            return {}, "invalid_cluster_learning_replay_key"
        if type(raw_ordinal) is not int or raw_ordinal < 0:
            return {}, "invalid_cluster_learning_decision_ordinal"
        applied[key] = raw_ordinal
    return applied, ""


__all__ = ("cluster_snapshot_learning_keys",)
