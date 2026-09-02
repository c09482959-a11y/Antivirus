"""Public detection bootstrap registration contract.

Orchestration owns the cross-domain bootstrap boundary, but it must not import
private detection implementation modules to build its deterministic startup
manifest. Detection owns the immutable module-name evidence here.
"""
from __future__ import annotations

DETECTION_BOOTSTRAP_MODULE_NAMES = tuple(
    sorted(
        (
            "Virus_Scan.detection.scoring.adaptive.model_score",
            "Virus_Scan.detection.scoring.escalation.anchor_scores",
            "Virus_Scan.detection.evidence.behavioral.semantics",
            "Virus_Scan.detection.chains",
            "Virus_Scan.detection.evidence",
            "Virus_Scan.detection.attack.api",
            "Virus_Scan.detection.tags.heuristics.attack_phase_projection",
            "Virus_Scan.detection.profiles.renpy.updater",
            "Virus_Scan.detection.tags",
            "Virus_Scan.detection.scoring.yara.context_evidence",
        )
    )
)

__all__ = ("DETECTION_BOOTSTRAP_MODULE_NAMES",)
