"""Detection-owned behavior scoring surfaces."""
from __future__ import annotations

from Virus_Scan.detection.scoring.behavior.bucket_validation import (
    behavior_bucket_validation,
    credential_family_boost,
)

__all__ = ("behavior_bucket_validation", "credential_family_boost")
