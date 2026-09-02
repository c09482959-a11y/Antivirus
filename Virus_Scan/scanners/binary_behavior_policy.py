"""Scanner-owned binary behavior term policy accessors.

Binary behavior predicates must not import detection-owned scoring policy.
The terms below come from the schema-validated immutable binary policy snapshot.
"""
from __future__ import annotations

from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot

_BINARY_POLICY = load_binary_policy_snapshot()

BINARY_COMMAND_EXECUTION_TERMS = _BINARY_POLICY.binary_command_execution_terms
BINARY_C2_TASKING_TERMS = _BINARY_POLICY.binary_c2_tasking_terms

__all__ = ("BINARY_COMMAND_EXECUTION_TERMS", "BINARY_C2_TASKING_TERMS")
