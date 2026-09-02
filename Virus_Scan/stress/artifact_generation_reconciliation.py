"""Evaluation-only reconciliation of hidden generation intent with artifact truth.

This owner answers one question only: did the renderer physically implement the
challenge requested by hidden generation intent?  It never creates evidence or
ATT&CK authority; artifact truth must already have been independently derived
from bytes before this function is called.
"""
from __future__ import annotations

from Virus_Scan.stress.static_semantic_schema import (
    ArtifactEvidenceTruth,
    CorpusGenerationIntent,
    StaticFlowTruth,
    StaticReachabilityTruth,
)


def _reachability_count(
    truth: ArtifactEvidenceTruth,
    expected: StaticReachabilityTruth,
) -> int:
    return sum(
        item.minimum_count
        for item in truth.reachability
        if item.operation_kind == expected.operation_kind
        and item.reachability_state == expected.reachability_state
    )


def reconcile_generation_intent_with_artifact_truth(
    intent: CorpusGenerationIntent,
    truth: ArtifactEvidenceTruth,
    *,
    reason_prefix: str,
) -> None:
    """Fail the corpus build when requested behavior did not survive rendering."""
    if type(intent) is not CorpusGenerationIntent or type(truth) is not ArtifactEvidenceTruth:
        raise TypeError(reason_prefix + "_generation_reconciliation_input_invalid")
    if type(reason_prefix) is not str or not reason_prefix:
        raise TypeError("generation_reconciliation_reason_prefix_invalid")

    if truth.parser_status != intent.desired_parser_status:
        raise ValueError(reason_prefix + "_generation_parser_status_mismatch")

    physical_operations = set(truth.operation_kinds)
    if not set(intent.desired_operation_kinds).issubset(physical_operations):
        raise ValueError(reason_prefix + "_generation_behavior_missing")
    if set(intent.forbidden_operation_kinds) & physical_operations:
        raise ValueError(reason_prefix + "_generation_forbidden_behavior_present")

    for expected in intent.desired_reachability:
        if _reachability_count(truth, expected) < expected.minimum_count:
            raise ValueError(reason_prefix + "_generation_reachability_mismatch")

    physical_flow = set(truth.flow)
    for expected in intent.desired_flow:
        if expected not in physical_flow:
            raise ValueError(reason_prefix + "_generation_flow_mismatch")


__all__ = ("reconcile_generation_intent_with_artifact_truth",)
