"""Scoring escalation public surface.

Concrete anchor floor rules and high-gate authority logic are decomposed into
bounded scoring/escalation owners.  This module exports the canonical public
functions used by existing scoring callers without owning mixed rule bodies.
"""
from __future__ import annotations

from Virus_Scan.detection.scoring.escalation.anchor_floors import apply_anchor_score_floors
from Virus_Scan.detection.scoring.escalation.high_gate import apply_anchor_chain_high_gate, high_gate_authority

__all__ = (
    "apply_anchor_chain_high_gate",
    "apply_anchor_score_floors",
    "high_gate_authority",
)
