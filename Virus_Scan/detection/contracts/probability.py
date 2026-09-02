"""Detection public probability contract aliases canonical probability helpers.

The repository-wide probability helpers are owned by :mod:`Virus_Scan.utils.probability`.
Detection keeps this module only as the public detection contract import surface;
it must not reimplement sigmoid/clamp semantics independently because that would
create a second probability authority for adaptive scoring, reporting, and model
evidence materialization.
"""
from __future__ import annotations

from Virus_Scan.utils.probability import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_STRENGTH_TO_LIKELIHOOD,
    PROBABILISTIC_SEMANTICS_VERSION,
    RELIABILITY_TO_NUMERIC,
    safe_clamp,
    score_to_probability,
)

__all__ = (
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "EVIDENCE_STRENGTH_TO_LIKELIHOOD",
    "PROBABILISTIC_SEMANTICS_VERSION",
    "RELIABILITY_TO_NUMERIC",
    "safe_clamp",
    "score_to_probability",
)
