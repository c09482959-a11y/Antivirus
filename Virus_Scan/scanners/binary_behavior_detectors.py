"""Binary scanner detector orchestration helpers."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.binary_graph_context import binary_node_edge_status
from Virus_Scan.scanners.binary_numeric import safe_clamp
from Virus_Scan.utils.tagging import norm_lower_set
from Virus_Scan.scanners.entropy import tag_entropy
from Virus_Scan.scanners.binary_behavior_chains import (
    binary_lolbin_chain,
    binary_scheduled_task_persistence,
)
from Virus_Scan.scanners.binary_behavior_support import (
    binary_behavior_score as _binary_behavior_score,
    ransomware_score_hits as _ransomware_score_hits,
    ransomware_signal_flags as _ransomware_signal_flags,
    ransomware_tags as _ransomware_tags,
)
from Virus_Scan.scanners.config import load_binary_policy_snapshot

PLR2004N3 = 3

_BINARY_POLICY = load_binary_policy_snapshot()


def call_detector(detector_fn: object, *args: object, context: object = None, **kwargs: object) -> object:
    """Run a detector without replacing detector failure with clean evidence."""
    del context  # Explicitly unused contract parameters.
    result = detector_fn(*args, **kwargs)
    if result is None:
        exc = ValueError('detector returned None')
        raise exc
    return result


def detect_attack_chain(tags: object) -> object:
    total_score = 0.0
    all_hits = []
    detector_calls = (
        binary_lolbin_chain,
        detect_env_var_abuse,
        binary_scheduled_task_persistence,
        detect_staged_execution,
    )
    for fn in detector_calls:
        s, h = call_detector(fn, tags, context={'stage': 'attack_chain'})
        total_score += _binary_behavior_score(s)
        if type(h) in (tuple, list):
            all_hits.extend(h)
    return (total_score, all_hits)


def _binary_behavior_text_values(values: object) -> tuple[str, ...]:
    """Return exact scanner text values without invoking caller-owned hooks."""
    if values is None:
        return ()
    if type(values) in (str, bytes, bytearray):
        text, reason = no_hook_text(
            values,
            missing_reason="missing_binary_behavior_text",
            unsupported_reason="unsafe_binary_behavior_text_rejected",
        )
        return (text,) if not reason and text else ()
    if type(values) not in (tuple, list, set, frozenset):
        return ()
    out: list[str] = []
    for value in tuple(values):
        text, reason = no_hook_text(
            value,
            missing_reason="missing_binary_behavior_text",
            unsupported_reason="unsafe_binary_behavior_text_rejected",
        )
        if not reason and text:
            out.append(text)
    return tuple(out)


def detect_env_var_abuse(tags: object) -> object:
    score = 0.0
    hits = []
    tags_lower = norm_lower_set(tags)
    if 'registry_mod' in tags_lower and 'process_exec' in tags_lower:
        score += 6.0
        hits.append('registry → execution coupling')
    if 'registry_env' in tags_lower:
        score += 5.0
        hits.append('environment variable persistence')
    return (score, hits)


def detect_evasion_signals(tags: object, node: object = None) -> object:
    signals = 0.0
    tag_values = _binary_behavior_text_values(tags)
    tags_lower = norm_lower_set(tag_values)
    if len(tag_values) > 20:
        signals += 0.3
    entropy_val = tag_entropy(tag_values)
    if entropy_val > 2.5:
        signals += 0.5
    if node is not None:
        edge_status, has_edges = binary_node_edge_status(node)
        if edge_status == "empty" and has_edges is False:
            signals += 0.4
    if len(tag_values) < PLR2004N3 and any((t in tags_lower for t in ['process_exec', 'cmd_exec'])):
        signals += 0.3
    return min(1.0, signals)

def detect_ransomware_file_rename_heuristic(strings_blob: object, tags: object = None) -> object:
    """Adds ransomware file-write / rename / delete behavior scoring."""
    existing_tags = norm_lower_set(tags)
    blob, reason = no_hook_text(
        strings_blob,
        missing_reason="missing_ransomware_strings_blob",
        unsupported_reason="unsafe_ransomware_strings_blob_rejected",
    )
    if reason:
        return {
            'score': 0.0,
            'tags': [],
            'hits': [],
            'failure_evidence_recorded': True,
            'reason': reason,
        }
    flags = _ransomware_signal_flags(str.lower(blob), _BINARY_POLICY)
    new_tags = _ransomware_tags(flags)
    score, hits = _ransomware_score_hits(flags, existing_tags)
    return {
        'score': safe_clamp(score),
        'tags': sorted(new_tags),
        'hits': hits,
        'failure_evidence_recorded': False,
        'reason': 'ok',
    }


def detect_staged_execution(tags: object) -> object:
    stages = ['network_download', 'file_write', 'registry_mod', 'env_var_injection', 'scheduled_task', 'process_exec']
    score = 0.0
    hits = []
    matched = [t for t in stages if t in tags]
    if len(matched) >= 3:
        score += len(matched) * 1.5
        hits.append(' -> '.join(matched))
    return (score, hits)


def engine_flow_contract_report() -> object:
    """Return the active one-way model contract for internal/self-test audits."""
    return {
        'order': ['scanner_evidence', 'raw_tags', 'canonical_tags', 'behavior_timeline', 'canonical_behavior_flow', 'temporal_read', 'markov_read', 'graph_read', 'clustering', 'scoring', 'clean_learning_commit', 'json_profile_flush', 'runtime_model_flush'],
        'mutation_points': {'graph': 'incremental_graph_update only', 'cluster': 'assign_cluster_with_context_tags from canonical model context', 'learning': 'commit_promoted_learning only', 'engine_json': 'commit_promoted_learning transaction only', 'runtime_model_state': 'authoritative SQLite learning transaction/flush_all_persistent_models'},
        'sequence_input_policy': 'Temporal/Markov use real ordered_events/behavior_flow first, raw tags only as filtered secondary input; normalize_tags mappings never create order.',
        'scoring_policy': 'Probability features and layer scoring are read-only; graph/learning mutations happen before/after scoring in explicit pipeline phases.',
    }


__all__ = (
    "call_detector",
    "detect_attack_chain",
    "detect_env_var_abuse",
    "detect_evasion_signals",
    "detect_ransomware_file_rename_heuristic",
    "detect_staged_execution",
    "engine_flow_contract_report",
)
