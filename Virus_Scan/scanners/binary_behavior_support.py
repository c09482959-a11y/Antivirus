"""Small no-hook support helpers for binary behavior detectors."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float


def binary_behavior_score(value: object) -> float:
    score, reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="unsafe_binary_behavior_score_rejected",
        non_finite_reason="unsafe_binary_behavior_score_rejected",
        allow_exact_text=False,
    )
    return 0.0 if reason else score


def blob_has_any(blob: str, terms: tuple[str, ...]) -> bool:
    return any(term in blob for term in terms)


def ransomware_signal_flags(blob: str, policy: object) -> dict[str, bool]:
    return {
        "traversal": blob_has_any(blob, policy.binary_ransomware_terms["traversal"]),
        "write": blob_has_any(blob, policy.binary_ransomware_terms["write"]),
        "rename_delete": blob_has_any(blob, policy.binary_ransomware_terms["rename_delete"]),
        "crypto": blob_has_any(blob, policy.binary_ransomware_terms["crypto"]),
        "ransom": blob_has_any(blob, policy.binary_ransomware_terms["marker"]),
    }


def ransomware_tags(flags: dict[str, bool]) -> set[str]:
    if type(flags) is not dict:
        return set()
    mapped = {
        "traversal": "file_traversal",
        "write": "rapid_file_write",
        "rename_delete": "file_rename_delete",
        "crypto": "crypto_file_operation",
        "ransom": "ransom_note_indicator",
    }
    return {tag for key, tag in mapped.items() if dict.get(flags, key) is True}


def ransomware_score_hits(flags: dict[str, bool], tags: set[str]) -> tuple[float, list[str]]:
    score, hits = 0.0, []
    scoring_rules = (
        (flags["traversal"] and flags["write"], 0.25, "file traversal plus writes"),
        (flags["write"] and flags["rename_delete"], 0.3, "file write plus rename/delete chain"),
        (flags["crypto"] and flags["write"], 0.3, "crypto plus file write behavior"),
        (flags["ransom"], 0.25, "ransom marker found"),
        ("file_collection" in tags and flags["crypto"], 0.15, "existing file collection reinforced by crypto"),
    )
    for matched, amount, hit in scoring_rules:
        if matched:
            score += amount
            hits.append(hit)
    return score, hits


__all__ = (
    "binary_behavior_score",
    "ransomware_score_hits",
    "ransomware_signal_flags",
    "ransomware_tags",
)
