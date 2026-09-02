"""Public model initialization contract.

Runtime owns initialization order, but model initialization details belong to the
model layer.  Runtime callers use this bounded public API instead of importing
``Virus_Scan.models`` package internals directly.
"""
from Virus_Scan.runtime.init_state import init_state_snapshot
from Virus_Scan.models.init_parts.model_defaults_init import init_model_defaults
from Virus_Scan.models.init_parts.profile_and_learning_store_init import init_profiles


def initialize_models() -> object:
    """Run model initialization in the canonical startup order."""
    init_profiles()
    init_model_defaults()
    return init_state_snapshot()


__all__ = ("initialize_models",)
