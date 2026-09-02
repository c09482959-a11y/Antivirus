"""Public model bootstrap registration contract.

Orchestration owns the cross-domain bootstrap activation boundary, but it must
not import individual model implementation modules to build its startup
manifest. The model layer owns the deterministic module-name evidence here.
"""
from __future__ import annotations

MODEL_BOOTSTRAP_MODULE_NAMES = tuple(
    sorted(
        (
            "Virus_Scan.models.api.adaptive_signals",
            "Virus_Scan.models.clustering",
            "Virus_Scan.models.api.clustering_contracts",
            "Virus_Scan.models.graph",
            "Virus_Scan.models.graph.api",
            "Virus_Scan.models.api.graph_contracts",
            "Virus_Scan.models.api.init_contracts",
            "Virus_Scan.models.learning",
            "Virus_Scan.models.api.learning_context_contracts",
            "Virus_Scan.models.markov.api",
            "Virus_Scan.models.api.markov_contracts",
            "Virus_Scan.models.api.profile_contracts",
            "Virus_Scan.models.api.profile_learning_contracts",
            "Virus_Scan.models.api.profile_retention_contracts",
            "Virus_Scan.models.api.replay_economics_contracts",
            "Virus_Scan.models.api.replay_comparison_contracts",
            "Virus_Scan.models.profiles",
            "Virus_Scan.models.replay",
            "Virus_Scan.models.replay.api",
            "Virus_Scan.models.api.replay_learning",
            "Virus_Scan.models.retention",
            "Virus_Scan.models.temporal",
            "Virus_Scan.models.temporal.api",
            "Virus_Scan.models.api.temporal_contracts",
        )
    )
)

__all__ = ("MODEL_BOOTSTRAP_MODULE_NAMES",)
