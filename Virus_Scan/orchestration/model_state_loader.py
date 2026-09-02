"""Orchestration-owned hydration from the authoritative model database."""
from __future__ import annotations

from Virus_Scan.models.api.clustering_contracts import load_cluster_runtime_model_record
from Virus_Scan.models.profiles.persistence import resolved_profiles_dir
from Virus_Scan.runtime.api import load_runtime_model_baselines
from Virus_Scan.storage import authoritative_model_state


def load_runtime_model_state() -> object:
    """Hydrate every runtime model owner from one current-schema SQLite snapshot."""
    resolved_profiles_dir()
    payload = authoritative_model_state().read_runtime_snapshot()
    if payload is None:
        return False
    runtime_result = load_runtime_model_baselines(payload)
    if runtime_result.get("loaded") is not True:
        return False
    cluster_result = load_cluster_runtime_model_record(payload.get("cluster_state"))
    return cluster_result is True


__all__ = ("load_runtime_model_state",)
