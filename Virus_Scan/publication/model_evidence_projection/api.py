"""Public assembly API for publication model-evidence projection.

The implementation records evidence that already exists on result records; it
never computes model probabilities or calls model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .assembly import build_model_evidence_final_json_fields as assemble_model_evidence_final_json_fields

if TYPE_CHECKING:
    from collections.abc import Mapping

def build_model_evidence_final_json_fields(record: Mapping[str, object]) -> dict[str, object]:
    """Project existing model evidence into deterministic final-JSON fields."""
    return assemble_model_evidence_final_json_fields(record)


__all__ = ("build_model_evidence_final_json_fields",)
