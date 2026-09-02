"""Public replay-learning persistence contract for model outputs.

Publication owns finalization timing, but replay/model learning logic belongs to
the model layer.  Publication callers use this bounded public API instead of
importing replay implementation internals directly.
"""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS

from Virus_Scan.models.replay import api as replay_model_api

if TYPE_CHECKING:
    from collections.abc import Mapping

def persist_parent_learning_from_results(results: Mapping[str, object]) -> object:
    """Persist parent-side replay/model learning through the canonical model API."""
    try:
        return replay_model_api.persist_parent_learning_from_results(results)
    except RECOVERABLE_RUNTIME_ERRORS:
        return {
            "checked": 0,
            "runtime": 0,
            "clean_checked": 0,
            "committed": 0,
            "promoted": 0,
            "errors": 1,
            "degraded": True,
            "unavailable_reason": "parent_replay_results_iteration_failed",
            "final_json_must_record": True,
            "replay_record_required": True,
        }


__all__ = ("persist_parent_learning_from_results",)
