"""Model-evidence projection boundary for final JSON compaction."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.exception_contracts import TELEMETRY_FAILURE_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields

def safe_model_evidence_final_json_fields(record: Mapping[str, object]) -> dict[str, object]:
    """Return model-evidence projection or explicit projection-failure evidence.

    Final JSON compaction is itself a publication boundary. If malformed
    already-computed model evidence prevents normal projection, the boundary
    must emit explicit degraded evidence instead of silently dropping the model
    section or publishing a clean/default model result.
    """
    try:
        return build_model_evidence_final_json_fields(record)
    except TELEMETRY_FAILURE_ERRORS as exc:
        return {
            "model_evidence": {
                "writer_version": "model_evidence_projection_error_v1",
                "final_json_must_record": True,
                "replay_record_required": True,
                "model_failures": (
                    {
                        "model_name": "publication_model_evidence_writer",
                        "failure_type": "model_evidence_projection_failed",
                        "reason": no_hook_type_name(exc),
                        "details": {
                            "message": "model evidence projection raised a recoverable exception",
                            "exception_type": no_hook_type_name(exc),
                        },
                    },
                ),
            }
        }


__all__ = (
    'safe_model_evidence_final_json_fields',
)
