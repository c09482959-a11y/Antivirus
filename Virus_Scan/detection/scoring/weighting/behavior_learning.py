"""Pure behavior rarity scoring signals."""

from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.detection.correlation.behavioral.behavior_flow import detection_behavior_flow
from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow

if TYPE_CHECKING:
    from collections.abc import Mapping

def tag_rarity_score(tags: object, baseline: Mapping[str, int] | None = None) -> object:
    """Score behavior-event rarity from an explicit immutable baseline snapshot.

    Scoring is pure: callers that want learned rarity must provide the baseline
    snapshot explicitly.  When no baseline is supplied, scoring returns the
    deterministic cold-start value instead of reading runtime model state.  The
    neutral behavior-rarity contract owns only the shared probability formula.
    """
    flow = detection_behavior_flow(() if tags is None else tags)
    return behavior_rarity_from_flow(flow, None if baseline is None else baseline)


__all__ = ("tag_rarity_score",)
