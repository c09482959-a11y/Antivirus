"""Detection-owned chain sequence namespace.

Behavior-sequence admission constants and functions are model-owned by
``Virus_Scan.models.behavior_sequence_contract``.  This detection module is kept
as an empty namespace so imports cannot become a duplicate public path for
model-owned behavior-sequence policy.
"""
from __future__ import annotations

__all__ = ()
