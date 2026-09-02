"""Immutable version registry for canonical profile persistence contracts."""
from typing import Final

PROFILE_SCHEMA_VERSION: Final[int] = 5
PROFILE_TAG_EVIDENCE_SCHEMA_VERSION: Final[str] = "profile_tag_evidence_v1"
PROFILE_STAGED_STORE_SCHEMA_VERSION: Final[str] = "profile_staged_benign_store_v1"
PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION: Final[str] = (
    "profile_learning_transaction_v3_authoritative_transaction_bound"
)

__all__ = (
    "PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION",
    "PROFILE_SCHEMA_VERSION",
    "PROFILE_STAGED_STORE_SCHEMA_VERSION",
    "PROFILE_TAG_EVIDENCE_SCHEMA_VERSION",
)
