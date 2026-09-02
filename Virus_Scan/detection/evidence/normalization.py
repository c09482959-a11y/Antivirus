"""Evidence-cluster normalization and correlation ceilings.

Scanner tags remain intact for auditability, but scoring/reporting can consume
family summaries so correlated aliases do not recursively inflate confidence.
"""
from __future__ import annotations
from typing import Iterable, Mapping
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_text,
)

PLR2004N2 = 2
PLR2004N3 = 3

_EVIDENCE_FAMILY_ITEMS: tuple[tuple[str, frozenset[str]], ...] = (
    ("execution", frozenset(("powershell", "cmd", "process_launch", "process_launch_capability", "subprocess", "os_system", "shell_execute", "process_exec", "script_execution", "payload_execution"))),
    ("encoded_payload", frozenset(("base64", "encoded_payload", "encoded_data_context", "decoded_base64_blob", "payload_decode_candidate", "frombase64string"))),
    ("networking", frozenset(("url_present", "network_activity", "remote_payload_download", "http_download", "reference_url", "network_exfiltration", "http_upload", "network_c2"))),
    ("persistence", frozenset(("persistence", "startup_persistence", "autorun_persistence", "run_key", "runonce", "renpy_persistent_dropper_chain"))),
    ("serialization", frozenset(("pickle_opcode_graph_analyzed", "pickle_deserialization_context", "binary_deserialize", "pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode"))),
    ("injection", frozenset(("dll_load", "memory_allocate", "memory_write", "thread_execution", "process_injection", "shellcode_exec"))),
    ("credential", frozenset(("credential_access", "browser_credential_access", "browser_profile_access", "token_secret_access", "token_exfiltration", "high_confidence_credential_theft"))),
    ("obfuscation", frozenset(("packed_or_obfuscated", "obfuscated_javascript", "encoded_data_context", "payload_decode_candidate", "magic_binary_blob"))),
)
EVIDENCE_FAMILIES: Mapping[str, frozenset[str]] = MappingProxyType(dict(_EVIDENCE_FAMILY_ITEMS))
FAMILY_WEIGHTS: Mapping[str, float] = MappingProxyType({
    "execution": 1.0,
    "encoded_payload": 0.75,
    "networking": 0.95,
    "persistence": 0.9,
    "serialization": 0.85,
    "injection": 1.0,
    "credential": 1.0,
    "obfuscation": 0.55,
})


def _norm_tag(t: object) -> str:
    text, reason = no_hook_text(
        t,
        missing_reason="missing_evidence_tag",
        unsupported_reason="unsafe_evidence_tag_rejected",
    )
    if reason:
        return ""
    return str.lower(str.strip(text))


def summarize_evidence_families(tags: Iterable[str]) -> dict[str, list[str]]:
    tagset = {normalized for item in no_hook_sequence_items(tags) if (normalized := _norm_tag(item))}
    out: dict[str, list[str]] = {}
    for family, members in _EVIDENCE_FAMILY_ITEMS:
        matched = sorted(tagset.intersection({_norm_tag(m) for m in members}))
        if matched:
            out[family] = matched
    return out


def normalized_evidence_family_tags(tags: Iterable[str]) -> list[str]:
    return ["evidence_family:" + str.__str__(name) for name in sorted(summarize_evidence_families(tags))]


def _no_hook_nonnegative_metric(value: object, *, default: float = 0.0) -> float:
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        minimum=0.0,
        allow_exact_text=True,
        reason="unsafe_evidence_numeric_rejected",
    )
    return metric if not reason else default


def correlation_ceiling(tags: Iterable[str], *, base_score: float | None = None, lineage_depth: int = 0, replay_depth: int = 0) -> dict[str, object]:
    """Calculate an amplification ceiling for correlated heuristic families.

    The ceiling only caps weak, correlated amplification. Hard anchors like
    process injection + C2 + credential exfil keep a high ceiling.
    """
    families = summarize_evidence_families(tags)
    present = set(families)
    independent = len(present)
    high_anchor = bool(({"injection", "credential"} & present) or ({"execution", "networking", "persistence"} <= present) or ({"execution", "networking", "credential"} <= present))
    score = _no_hook_nonnegative_metric(base_score, default=100.0)
    if high_anchor:
        ceiling = 92.0 if independent >= PLR2004N2 else 78.0
    elif independent <= 1:
        ceiling = 46.0
    elif independent == 2:
        ceiling = 58.0
    elif independent == PLR2004N3:
        ceiling = 68.0
    else:
        ceiling = 74.0
    lineage = _no_hook_nonnegative_metric(lineage_depth, default=0.0)
    replay = _no_hook_nonnegative_metric(replay_depth, default=0.0)
    decay = min(18.0, lineage * 2.0 + replay * 1.5)
    ceiling = max(25.0, ceiling - decay)
    capped = min(score, ceiling)
    return {"score": capped, "ceiling": ceiling, "capped": capped < score, "families": families, "independent_families": independent, "high_anchor": high_anchor, "decay": decay}


def confidence_decay(value: float, *, lineage_distance: int = 0, replay_depth: int = 0, time_steps: int = 0) -> float:
    factor = 1.0
    lineage = _no_hook_nonnegative_metric(lineage_distance, default=0.0)
    replay = _no_hook_nonnegative_metric(replay_depth, default=0.0)
    steps = _no_hook_nonnegative_metric(time_steps, default=0.0)
    metric = _no_hook_nonnegative_metric(value, default=0.0)
    factor *= max(0.10, 1.0 - 0.08 * lineage)
    factor *= max(0.15, 1.0 - 0.06 * replay)
    factor *= max(0.20, 1.0 - 0.02 * steps)
    return max(0.0, min(1.0, metric * factor))


def _record_field_text(record: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = dict.get(record, key)
        text, reason = no_hook_text(
            value,
            missing_reason="missing_evidence_record_text",
            unsupported_reason="unsafe_evidence_record_text_rejected",
        )
        if not reason and text:
            return str.lower(text)
    return ""


def _materialized_record_dict(record: object) -> dict[str, object] | None:
    items = no_hook_mapping_items(record)
    if items is None:
        return None
    materialized = no_hook_materialize(
        dict(items),
        reason_prefix="detection_evidence_record",
    )
    return materialized if type(materialized) is dict else None


def dedupe_correlated_evidence(records: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, object]] = []
    for rec in no_hook_sequence_items(records):
        d = _materialized_record_dict(rec)
        if d is None:
            continue
        key = (
            _record_field_text(d, "family", "evidence_family", "tag", "name"),
            _record_field_text(d, "source", "path", "file"),
            _record_field_text(d, "origin"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out

__all__ = ("EVIDENCE_FAMILIES", "FAMILY_WEIGHTS", "confidence_decay", "correlation_ceiling", "dedupe_correlated_evidence", "normalized_evidence_family_tags", "summarize_evidence_families")
