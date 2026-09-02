"""Canonical lightweight IL-pattern analysis pipeline.

Stage211 makes the raw-queue IL collector import a real implementation instead
of relying on a deferred optional import that silently disabled .NET chunk
analysis when the module was absent.
"""
from __future__ import annotations

import re
from collections import Counter

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot
from Virus_Scan.scanners.contracts import scanner_contract_lower_token, scanner_contract_text

_BINARY_POLICY = load_binary_policy_snapshot()

_IL_OPCODE_PATTERNS: tuple[tuple[str, str], ...] = _BINARY_POLICY.il_opcode_patterns
_OBFUSCATION_MARKERS: tuple[str, ...] = _BINARY_POLICY.il_obfuscation_markers
_BEHAVIOR_TAG_WEIGHTS = _BINARY_POLICY.il_behavior_tag_weights

def _il_text(strings_blob: str | bytes | None) -> str:
    if type(strings_blob) is bytes:
        return strings_blob.decode("latin1", errors="ignore")
    return scanner_contract_text(strings_blob, replacement="")


def extract_il_patterns(strings_blob: str | bytes | None) -> list[str]:
    """Return observed IL/pseudo-IL operation families in deterministic order."""
    text = _il_text(strings_blob)
    if not text:
        return []
    found: list[str] = []
    for name, pattern in _IL_OPCODE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(name)
    return found


def analyze_il_pipeline(path: str, tags: list[str] | tuple[str, ...] | None = None, *, strings_blob: str | bytes | None = None, file_structure: object = None) -> dict[str, object]:
    """Analyze lightweight IL evidence and return deterministic scoring metadata."""
    text = _il_text(strings_blob)
    low = text.lower()
    tag_counter = Counter(
        scanner_contract_lower_token(t, replacement="")
        for t in no_hook_sequence_items(tags)
        if scanner_contract_lower_token(t, replacement="").strip()
    )
    ops = extract_il_patterns(text)
    op_set = set(ops)

    behavior_score = 0.0
    for tag, weight in no_hook_mapping_items(_BEHAVIOR_TAG_WEIGHTS) or ():
        tag_text = scanner_contract_text(tag, replacement="")
        if tag_text in tag_counter:
            behavior_score += weight

    if {"CALL", "LDSTR"} <= op_set:
        behavior_score += _BINARY_POLICY.il_score_call_ldstr_bonus
    if {"PROCESS", "CALL"} <= op_set:
        behavior_score += _BINARY_POLICY.il_score_process_call_bonus
    if {"NETWORK", "CALL"} <= op_set:
        behavior_score += _BINARY_POLICY.il_score_network_call_bonus
    if {"MEMORY", "PINVOKE"} & op_set:
        behavior_score += _BINARY_POLICY.il_score_memory_pinvoke_bonus

    obfuscation_hits = sorted(marker for marker in _OBFUSCATION_MARKERS if marker in low)
    obfuscation_score = min(1.0, len(obfuscation_hits) * _BINARY_POLICY.il_obfuscation_per_marker)
    if "packed_or_obfuscated" in tag_counter:
        obfuscation_score = min(1.0, obfuscation_score + _BINARY_POLICY.il_obfuscation_packed_bonus)
    if "CALLI" in op_set or "LDFTN" in op_set:
        obfuscation_score = min(1.0, obfuscation_score + _BINARY_POLICY.il_obfuscation_indirect_call_bonus)

    il_score = min(1.0, behavior_score + min(len(ops), _BINARY_POLICY.il_max_ops_for_score) * _BINARY_POLICY.il_op_score_weight)
    return {
        "path": scanner_contract_text(path, replacement=""),
        "il_ops": ops,
        "il_score": round(il_score, 6),
        "obfuscation_score": round(obfuscation_score, 6),
        "obfuscation_markers": obfuscation_hits[:_BINARY_POLICY.il_obfuscation_marker_result_limit],
        "file_structure_observed": file_structure is not None,
    }


__all__ = ("analyze_il_pipeline", "extract_il_patterns")
