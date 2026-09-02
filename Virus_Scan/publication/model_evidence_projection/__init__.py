"""Publication model-evidence projection package."""

from __future__ import annotations

from .api import build_model_evidence_final_json_fields
from .constants import MODEL_EVIDENCE_WRITER_VERSION

__all__ = ("MODEL_EVIDENCE_WRITER_VERSION", "build_model_evidence_final_json_fields")
