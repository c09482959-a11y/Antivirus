"""Public graph-model contracts for non-model consumers.

Graph implementation modules own C# graph extraction and archive-member graph
mutation.  Callers outside ``Virus_Scan.models`` use this bounded API instead
of importing ``Virus_Scan.models.graph`` implementation internals directly.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import math
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.models.api.text_boundary import (
    public_api_contract_text,
    public_duplicate_mapping_key_label,
    public_first_unavailable_reason,
    public_unavailable_contract_mapping,
    public_unreadable_mapping_key_label,
)
from Virus_Scan.models.graph.relationships import (
    compute_graph_relationship_layer as owner_compute_graph_relationship_layer,
)
from Virus_Scan.models.graph.risk import (
    get_graph_risk_enhanced_evidence as owner_get_graph_risk_enhanced_evidence,
)
from Virus_Scan.models.graph.links import (
    link_archive_members_to_graph as owner_link_archive_members_to_graph,
    link_temporal_to_graph as owner_link_temporal_to_graph,
)
from Virus_Scan.models.graph.influence import (
    explain_graph_influence as owner_explain_graph_influence,
)
from Virus_Scan.models.graph.scan import scan_cs as owner_scan_cs
from Virus_Scan.models.graph.state import get_graph_node as owner_get_graph_node


_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))


def _unreadable_graph_label(value: object) -> str:
    return "<unreadable_" + no_hook_type_name(value) + ">"


def _detached_graph_contract_text(value: object) -> str:
    """Return exact built-in public graph text without caller hooks."""
    text, _reason = public_api_contract_text(
        value,
        default_text=_unreadable_graph_label(value),
    )
    return text


def _graph_text_default_text(default_text: object, default: str) -> str:
    if default_text is None:
        return default
    try:
        text = _detached_graph_contract_text(default_text)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return default
    if text == "":
        return default
    return text


def _safe_public_graph_text(value: object, *, default_text: str | None = None) -> str:
    default = default_text if default_text is not None else _unreadable_graph_label(value)
    text, reason = public_api_contract_text(value, default_text=default)
    if reason is not None:
        return text
    if text == "":
        return _graph_text_default_text(default_text, "<blank>")
    return text


def _immutable_graph_value(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        out = {}
        keyed = []
        for index, (key, child) in enumerate(items):
            key_text = _safe_public_graph_text(key, default_text=public_unreadable_mapping_key_label(index))
            keyed.append((key_text, index, child))
        for raw_key_text, index, child in sorted(keyed, key=lambda row: (row[0], row[1])):
            key_text = raw_key_text
            if key_text in out:
                key_text = public_duplicate_mapping_key_label(key_text, index)
            out[key_text] = _immutable_graph_value(child)
        return MappingProxyType(out)
    if isinstance(value, Mapping):
        return public_unavailable_contract_mapping(
            "unsupported_public_mapping",
            evidence_type="graph_public_contract_value_unavailable",
        )
    if type(value) in (list, tuple):
        return tuple(_immutable_graph_value(item) for item in value)
    if type(value) in (set, frozenset):
        ordered = sorted(value, key=lambda item: (_safe_public_graph_text(no_hook_type_name(item)), _safe_public_graph_text(item)))
        return tuple(_immutable_graph_value(item) for item in ordered)
    if isinstance(value, str):
        return str.__str__(_safe_public_graph_text(value))
    if type(value) in (int, float, bool) or value is None:
        return value
    _text, _reason = public_api_contract_text(value, default_text=_unreadable_graph_label(value))
    if _reason is not None:
        return public_unavailable_contract_mapping(
            "unreadable_public_contract_text",
            evidence_type="graph_public_contract_value_unavailable",
        )
    return _text


def _public_graph_sequence(value: object) -> tuple[tuple[object, ...], str | None]:
    """Normalize public graph sequence inputs without caller-owned iteration."""
    if value is None:
        return (), None
    if isinstance(value, (str, bytes)):
        return (value,), None
    if no_hook_mapping_items(value) is not None:
        return (value,), None
    if isinstance(value, Mapping):
        return (), "unsupported_graph_public_mapping_sequence"
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value), None
    if isinstance(value, Iterable):
        return (), "unsupported_graph_public_iterable_sequence"
    return (), "non_iterable_graph_public_sequence"


def _graph_relationship_unavailable(reason: str) -> Mapping[str, object]:
    return _immutable_graph_value({
        "name": "Layer 3 Graph Score",
        "score": 0.0,
        "graph_features": {
            "risk": 0.0,
            "base_risk": 0.0,
            "anomaly": 0.0,
            "graph_features_ready": False,
            "graph_unavailable_reason": reason,
        },
        "graph_relationship_ready": False,
        "graph_unavailable_reason": reason,
        "phase_hits": (),
        "propagated_chains": (),
        "hits": ("graph_relationship_unavailable",),
        "summary": "relationships_unavailable",
        "degraded": True,
        "unavailable_reason": reason,
        "final_json_must_record": True,
        "replay_record_required": True,
    })


def compute_graph_relationship_layer(node: object, *, tags: object = None) -> Mapping[str, object]:
    """Read graph relationship evidence through the canonical graph model owner."""
    tag_values, tag_reason = _public_graph_sequence(tags)
    if tag_reason:
        return _graph_relationship_unavailable(tag_reason)
    try:
        result = owner_compute_graph_relationship_layer(node, tags=tag_values)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _graph_relationship_unavailable("graph_relationship_public_call_failed")
    return _immutable_graph_value(result)


def explain_graph_influence(node: object) -> tuple[object, ...]:
    """Return graph influence or explicit evidence for an unavailable node."""
    node_text, node_reason = public_api_contract_text(node, default_text="")
    if node_reason is not None or node_text == "":
        return (
            public_unavailable_contract_mapping(
                "graph_influence_public_input_invalid",
                evidence_type="graph_public_contract_value_unavailable",
            ),
        )
    try:
        result = owner_explain_graph_influence(node_text)
        node_snapshot = owner_get_graph_node(node_text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return (
            public_unavailable_contract_mapping(
                "graph_influence_public_call_failed",
                evidence_type="graph_public_contract_value_unavailable",
            ),
        )
    if type(result) not in (list, tuple):
        return (
            public_unavailable_contract_mapping(
                "invalid_graph_influence_output",
                evidence_type="graph_public_contract_value_unavailable",
            ),
        )
    if not result and node_snapshot is None:
        return (
            public_unavailable_contract_mapping(
                "graph_node_missing",
                evidence_type="graph_public_contract_value_unavailable",
            ),
        )
    return tuple(_immutable_graph_value(item) for item in result)


def get_graph_risk_enhanced_evidence(node: object) -> Mapping[str, object]:
    """Read graph enhanced-risk evidence without hiding failures as clean zero."""
    try:
        result = owner_get_graph_risk_enhanced_evidence(node)
    except (ArithmeticError, AttributeError, KeyError, LookupError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        result = {
            "risk": 0.0,
            "ready": False,
            "degraded": True,
            "unavailable_reason": "graph_risk_public_call_failed",
            "evidence_type": "graph_risk",
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    return _immutable_graph_value(result)


def _graph_public_risk_value(evidence: Mapping[str, object]) -> tuple[float, Mapping[str, object] | None]:
    if not isinstance(evidence, Mapping):
        return 0.0, public_unavailable_contract_mapping(
            "graph_risk_evidence_not_mapping",
            evidence_type="graph_public_contract_value_unavailable",
        )
    raw_risk = evidence.get("risk", 0.0)
    if raw_risk is None:
        return 0.0, public_unavailable_contract_mapping(
            "graph_risk_missing",
            evidence_type="graph_public_contract_value_unavailable",
        )
    if type(raw_risk) not in (int, float):
        return 0.0, public_unavailable_contract_mapping(
            "graph_risk_not_numeric",
            evidence_type="graph_public_contract_value_unavailable",
        )
    risk = float(raw_risk)
    if not math.isfinite(risk):
        return 0.0, public_unavailable_contract_mapping(
            "graph_risk_not_finite",
            evidence_type="graph_public_contract_value_unavailable",
        )
    if risk < 0.0:
        return 0.0, public_unavailable_contract_mapping(
            "graph_risk_below_minimum",
            evidence_type="graph_public_contract_value_unavailable",
        )
    if risk > 1.0:
        return 1.0, public_unavailable_contract_mapping(
            "graph_risk_above_maximum",
            evidence_type="graph_public_contract_value_unavailable",
        )
    return risk, None


def get_graph_risk_enhanced(node: object) -> float:
    """Read graph enhanced-risk evidence without mutating graph state."""
    risk, _issue = _graph_public_risk_value(get_graph_risk_enhanced_evidence(node))
    return risk


def _graph_public_link_count(value: object) -> tuple[int, str | None]:
    if type(value) is not int:
        return 0, "graph_archive_link_count_invalid"
    if value < 0:
        return 0, "graph_archive_link_count_negative"
    return value, None


def _graph_public_member_limit(value: object) -> tuple[int, str | None]:
    if type(value) is not int:
        return 0, "graph_archive_member_limit_invalid"
    if value < 1:
        return 0, "graph_archive_member_limit_invalid"
    return value, None


def _graph_archive_link_evidence(count: int, *, ready: bool, reason: str | None) -> Mapping[str, object]:
    degraded = reason is not None
    return _immutable_graph_value({
        "linked": count,
        "ready": ready,
        "degraded": degraded,
        "unavailable_reason": reason,
        "evidence_type": "graph_archive_member_link",
        "final_json_must_record": degraded,
        "replay_record_required": True,
    })


def link_archive_members_to_graph_evidence(path: object, *, max_members: int = 500) -> Mapping[str, object]:
    """Link archive members and expose unavailable evidence for failures."""
    path_text, path_reason = public_api_contract_text(path, default_text="")
    if path_reason is not None or path_text == "":
        return _graph_archive_link_evidence(
            0,
            ready=False,
            reason="graph_archive_path_public_input_invalid",
        )
    member_limit, limit_reason = _graph_public_member_limit(max_members)
    if limit_reason is not None:
        return _graph_archive_link_evidence(0, ready=False, reason=limit_reason)
    try:
        linked = owner_link_archive_members_to_graph(Path(path_text), max_members=member_limit)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _graph_archive_link_evidence(
            0,
            ready=False,
            reason="graph_archive_link_public_call_failed",
        )
    count, count_reason = _graph_public_link_count(linked)
    if count_reason is not None:
        return _graph_archive_link_evidence(0, ready=False, reason=count_reason)
    return _graph_archive_link_evidence(count, ready=True, reason=None)


def link_archive_members_to_graph(path: object, *, max_members: int = 500) -> int:
    """Link archive members through the canonical graph model owner."""
    evidence = link_archive_members_to_graph_evidence(path, max_members=max_members)
    linked = evidence.get("linked", 0)
    count, _reason = _graph_public_link_count(linked)
    return count


def scan_cs(path: object) -> list[str]:
    """Extract graph-owned C# source tags through the canonical graph model owner."""
    try:
        source_path = Path(path)
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError):
        return ["graph_cs_scan_unavailable"]
    if not source_path.exists() or not source_path.is_file():
        return ["graph_cs_scan_unavailable"]
    try:
        result = owner_scan_cs(source_path)
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError, UnicodeError):
        return ["graph_cs_scan_unavailable"]
    if isinstance(result, list):
        return [_safe_public_graph_text(_immutable_graph_value(tag), default_text="graph_cs_scan_unavailable") for tag in result]
    if isinstance(result, tuple):
        return [_safe_public_graph_text(_immutable_graph_value(tag), default_text="graph_cs_scan_unavailable") for tag in result]
    return ["graph_cs_scan_unavailable"]


def link_temporal_to_graph(node: object, prev_stage: object, tags: object, curr_stage: object) -> object:
    """Link temporal evidence through the canonical graph model owner."""
    tag_values, tag_reason = _public_graph_sequence(tags)
    if tag_reason:
        return _immutable_graph_value({
            "linked": False,
            "reason": tag_reason,
            "degraded": True,
            "unavailable_reason": tag_reason,
            "final_json_must_record": True,
            "replay_record_required": True,
        })
    node_text, node_reason = public_api_contract_text(node, default_text="", allow_path=False)
    prev_text, prev_reason = public_api_contract_text(prev_stage, default_text="", allow_path=False)
    curr_text, curr_reason = public_api_contract_text(curr_stage, default_text="", allow_path=False)
    if node_reason is not None or prev_reason is not None or curr_reason is not None or node_text == "" or prev_text == "" or curr_text == "":
        return _immutable_graph_value({
            "linked": False,
            "reason": "graph_temporal_link_public_call_failed",
            "degraded": True,
            "unavailable_reason": "graph_temporal_link_public_call_failed",
            "final_json_must_record": True,
            "replay_record_required": True,
        })
    try:
        result = owner_link_temporal_to_graph(node_text, prev_text, tag_values, curr_text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _immutable_graph_value({
            "linked": False,
            "reason": "graph_temporal_link_public_call_failed",
            "degraded": True,
            "unavailable_reason": "graph_temporal_link_public_call_failed",
            "final_json_must_record": True,
            "replay_record_required": True,
        })
    return _immutable_graph_value(result)


__all__ = (
    "compute_graph_relationship_layer",
    "explain_graph_influence",
    "get_graph_risk_enhanced",
    "get_graph_risk_enhanced_evidence",
    "link_archive_members_to_graph",
    "link_archive_members_to_graph_evidence",
    "link_temporal_to_graph",
    "scan_cs",
)
