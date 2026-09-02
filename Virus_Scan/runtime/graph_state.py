"""Canonical owned graph state for Phase C shared-state collapse.

This module owns mutation of the in-memory hybrid graph.  Scanner/model code must
use these APIs instead of reaching around the graph owner
or mutating imported module globals directly.  Snapshots are immutable enough for
read-side diagnostics while preserving the existing node schema internally.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import math
from threading import RLock
from types import MappingProxyType

from Virus_Scan.contracts.tag_evidence import (
    TagEvidenceRecord,
    tag_evidence_records,
    tag_evidence_string_projection,
)
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    no_hook_failure,
    no_hook_finite_float,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.runtime.cache_state import clear_runtime_caches
from Virus_Scan.runtime.governance_inputs import runtime_int


PLR2004N3 = 3

GRAPH_SNAPSHOT_SCHEMA_VERSION = "graph_snapshot_v2"
GRAPH_EDGE_RECORD_VERSION = "graph_edge_record_v1"
GRAPH_DIRECTION_VALUES = frozenset({"outbound", "inbound", "bidirectional"})
_GRAPH_CACHE_NAMES = (
    "GRAPH_RISK_CACHE",
    "GRAPH_PROPAGATION_CACHE",
    "GRAPH_ATTENTION_CACHE",
)

GRAPH_RUNTIME_TEXT_UNAVAILABLE = "graph_runtime_text_unavailable"

GraphRuntimeValue = object
GraphNodeRecord = dict[str, GraphRuntimeValue]
GraphValueMap = dict[GraphRuntimeValue, GraphRuntimeValue]
GraphValueSet = set[GraphRuntimeValue]


def _invalidate_graph_model_caches() -> None:
    clear_runtime_caches(*_GRAPH_CACHE_NAMES)


def _exact_graph_runtime_text(value: GraphRuntimeValue, *, default: str = "") -> str:
    """Detach graph runtime text without invoking caller-owned ``__str__``.

    Runtime graph snapshots are replay/final-JSON-facing model evidence.  They
    may receive caller-owned node ids, tag values, metadata keys, and edge ids.
    Only exact built-in scalar/text values are materialized as text here;
    unsupported objects become explicit unavailable evidence text instead of
    executing arbitrary object string hooks or disappearing as clean defaults.
    """
    if value is None:
        return default
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is bytes:
        return value.decode("utf-8", "replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", "replace")
    if type(value) is bool:
        return "True" if value else "False"
    if type(value) is int:
        return int.__repr__(value)
    if type(value) is float:
        if not math.isfinite(value):
            return "non_finite_float"
        return float.__repr__(value)
    return _graph_unavailable_text(value)


def _graph_unavailable_text(value: GraphRuntimeValue) -> str:
    return GRAPH_RUNTIME_TEXT_UNAVAILABLE + ":" + no_hook_type_name(value)


def _graph_duplicate_text(base: str, ordinal: int) -> str:
    if type(base) is not str or type(ordinal) is not int or type(ordinal) is bool:
        return GRAPH_RUNTIME_TEXT_UNAVAILABLE
    return str.__str__(base) + "#" + int.__str__(ordinal)


def _trim_graph_runtime_text(value: GraphRuntimeValue, *, default: str = "") -> str:
    return str.strip(_exact_graph_runtime_text(value, default=default))


def _freeze_graph_snapshot_key(key: GraphRuntimeValue) -> str:
    return graph_vector_node_key(key)


def _unique_graph_snapshot_key(base: str, seen: dict[str, int]) -> str:
    normalized = str.strip(base) or GRAPH_RUNTIME_TEXT_UNAVAILABLE
    count = seen.get(normalized, 0)
    seen[normalized] = count + 1
    if count == 0:
        return normalized
    return _graph_duplicate_text(normalized, count + 1)


def _finite_graph_float(value: GraphRuntimeValue, default: float = 0.0, *, minimum: float | None = None, maximum: float | None = None) -> float:
    """Project graph runtime scalars to finite numbers before model snapshots.

    The graph runtime is a final-JSON/replay-facing evidence boundary.  Numeric
    projection must therefore accept only primitive scalars and exact textual
    numbers; hostile caller-owned ``__float__`` / ``__int__`` hooks are never
    invoked.
    """
    number, _reason = no_hook_finite_float(
        value if value is not None else default,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason="unsafe_graph_numeric_value_rejected",
        non_finite_reason="non_finite_graph_number",
        allow_exact_text=True,
    )
    return number


def _nonfinite_graph_reason(value: GraphRuntimeValue, reason: str) -> str | None:
    if value is None:
        return reason
    _number, numeric_reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=None,
        maximum=None,
        reason=reason,
        non_finite_reason=reason,
        allow_exact_text=True,
    )
    return reason if numeric_reason else None


def _graph_failure(reason: str, value: GraphRuntimeValue) -> Mapping[str, GraphRuntimeValue]:
    return MappingProxyType(no_hook_failure(reason, value))


def _sanitize_graph_tags(tags: GraphRuntimeValue) -> tuple[set[str], str | None]:
    sanitized: set[str] = set()
    if tags is None:
        return sanitized, None
    if type(tags) is str or type(tags) is bytes or type(tags) is bytearray:
        sanitized.add(graph_vector_node_key(tags))
        return sanitized, None
    if type(tags) is set or type(tags) is frozenset or type(tags) is tuple or type(tags) is list:
        source = tuple(tags)
    else:
        return sanitized, "non_materializable_graph_tags"
    for tag in source:
        sanitized.add(graph_vector_node_key(tag))
    return sanitized, None


def _sanitize_graph_tag_evidence_records(
    records: GraphRuntimeValue,
) -> tuple[tuple[TagEvidenceRecord, ...], str | None]:
    """Materialize only exact immutable tag evidence records without hooks."""
    if records is None:
        return (), None
    if type(records) is TagEvidenceRecord:
        source = (records,)
    elif type(records) in (tuple, list):
        source = tuple(records)
    else:
        return (), "non_materializable_graph_tag_evidence_records"
    if any(type(record) is not TagEvidenceRecord for record in source):
        return (), "non_canonical_graph_tag_evidence_record"
    return tag_evidence_records(source), None


def _merge_graph_tag_evidence_records(
    existing: GraphRuntimeValue, incoming: tuple[TagEvidenceRecord, ...],
) -> tuple[TagEvidenceRecord, ...]:
    merged: list[TagEvidenceRecord] = []
    seen: set[str] = set()
    for record in (*tag_evidence_records(existing), *incoming):
        if record.evidence_id in seen:
            continue
        seen.add(record.evidence_id)
        merged.append(record)
    return tag_evidence_records(tuple(merged))


def _graph_has_canonical_tag_evidence(data: Mapping[str, GraphRuntimeValue]) -> bool:
    """Return whether score-bearing canonical tag evidence owns node tags."""
    return len(tag_evidence_records(data.get("tag_evidence_records", ()))) > 0


def _sanitize_graph_weights(weights: GraphRuntimeValue) -> tuple[dict[GraphRuntimeValue, float], dict[str, str]]:
    sanitized: dict[GraphRuntimeValue, float] = {}
    reasons: dict[str, str] = {}
    items = no_hook_mapping_items(weights)
    if items is None:
        if weights is not None:
            reasons["__weights__"] = "non_materializable_graph_weights"
        return sanitized, reasons
    for edge, value in items:
        reason = _nonfinite_graph_reason(value, "non_finite_graph_weight")
        sanitized[edge] = _finite_graph_float(value, 0.0, minimum=0.0)
        if reason:
            reasons[graph_vector_node_key(edge)] = reason
    return sanitized, reasons


def _freeze_graph_mapping_items(items: tuple[tuple[GraphRuntimeValue, GraphRuntimeValue], ...], *, reason_prefix: str = "graph") -> Mapping[str, GraphRuntimeValue]:
    del reason_prefix  # Explicitly unused contract parameters.
    seen: dict[str, int] = {}
    keyed: list[tuple[str, int, GraphRuntimeValue]] = []
    for index, (key, item) in enumerate(items):
        keyed.append((_freeze_graph_snapshot_key(key), index, item))
    out: dict[str, GraphRuntimeValue] = {}
    for key_text, _index, item in sorted(keyed, key=lambda row: (row[0], row[1])):
        frozen_key = _unique_graph_snapshot_key(key_text, seen)
        out[frozen_key] = _freeze_graph_snapshot_value(item)
    return MappingProxyType(out)


def _freeze_graph_snapshot_value(value: GraphRuntimeValue) -> GraphRuntimeValue:
    if type(value) is TagEvidenceRecord:
        return value
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return value if math.isfinite(value) else MappingProxyType({"non_finite_float": float.__repr__(value).lower()})
    items = no_hook_mapping_items(value)
    if items is not None:
        return _freeze_graph_mapping_items(items)
    if type(value) is MappingProxyType or isinstance(value, Mapping):
        return _graph_failure("non_materializable_graph_mapping", value)
    if isinstance(value, str):
        return _exact_graph_runtime_text(value)
    if type(value) is set or type(value) is frozenset:
        frozen = tuple(_freeze_graph_snapshot_value(item) for item in value)
        return frozenset(sorted(frozen, key=no_hook_json_sort_key))
    if type(value) is list or type(value) is tuple:
        return tuple(_freeze_graph_snapshot_value(v) for v in value)
    if type(value) in (bytes, bytearray):
        return _exact_graph_runtime_text(value)
    return _exact_graph_runtime_text(value)


def graph_vector_node_key(node: GraphRuntimeValue) -> str:
    """Canonical graph/vector runtime key materialization for model callers."""
    return _trim_graph_runtime_text(node)


def _node_default(now: float | None = None) -> dict[str, GraphRuntimeValue]:
    ts = 0.0 if now is None else float(now)
    ordinal = max(0, int(ts))
    return {
        "edges": set(),
        "edge_time": {},
        "weights": {},
        "types": {},
        "edge_evidence_ids": {},
        "edge_confidence": {},
        "edge_directions": {},
        "risk": 0.0,
        "last_seen": ts,
        "attention": 0.0,
        "tags": set(),
        "tag_evidence_records": (),
        "created_ordinal": ordinal,
        "update_ordinal": ordinal,
    }


def _graph_record_set(record: GraphNodeRecord, key: str) -> GraphValueSet:
    value = record.get(key)
    if type(value) is set:
        return value
    if type(value) is frozenset or type(value) is tuple or type(value) is list:
        materialized = set(value)
    else:
        materialized = set()
    record[key] = materialized
    return materialized


def _graph_record_map(record: GraphNodeRecord, key: str) -> GraphValueMap:
    value = record.get(key)
    if type(value) is dict:
        return value
    items = no_hook_mapping_items(value)
    materialized: GraphValueMap = {} if items is None else dict(items)
    record[key] = materialized
    return materialized


def _validated_graph_direction(value: GraphRuntimeValue) -> str:
    text = _trim_graph_runtime_text(value, default="outbound")
    return text if text in GRAPH_DIRECTION_VALUES else "outbound"


def _graph_edge_evidence_id(src: str, dst: str, edge_type: str, value: GraphRuntimeValue) -> str:
    supplied = _trim_graph_runtime_text(value)
    if supplied and not supplied.startswith(GRAPH_RUNTIME_TEXT_UNAVAILABLE):
        return supplied
    payload = "|".join((src, dst, edge_type)).encode("utf-8", "strict")
    return "graph-edge:" + hashlib.sha256(payload).hexdigest()[:24]


def _graph_node_type(node_id: str, data: Mapping[str, GraphRuntimeValue]) -> str:
    configured = _trim_graph_runtime_text(data.get("node_type"))
    if configured and not configured.startswith(GRAPH_RUNTIME_TEXT_UNAVAILABLE):
        return configured
    if ":" in node_id:
        prefix = node_id.split(":", 1)[0]
        return prefix or "node"
    return "file" if "." in node_id else "node"


def _digest_graph_value(digest: object, value: GraphRuntimeValue) -> None:
    if value is None:
        digest.update(b"N;")
        return
    if type(value) is bool:
        digest.update(b"B1;" if value else b"B0;")
        return
    if type(value) is int:
        digest.update(b"I" + int.__str__(value).encode() + b";")
        return
    if type(value) is float:
        digest.update(b"F" + float.__repr__(value).encode() + b";")
        return
    if isinstance(value, str):
        text = str.__str__(value).encode("utf-8", "replace")
        digest.update(b"S" + int.__str__(len(text)).encode() + b":" + text + b";")
        return
    if type(value) is TagEvidenceRecord:
        digest.update(b"T")
        for field_name in TagEvidenceRecord.__dataclass_fields__:
            _digest_graph_value(
                digest, no_hook_exact_owner_field(value, TagEvidenceRecord, field_name),
            )
        return
    items = no_hook_mapping_items(value)
    if items is not None:
        digest.update(b"M{")
        for key, item in sorted(items, key=lambda row: no_hook_json_sort_key(row[0])):
            _digest_graph_value(digest, graph_vector_node_key(key))
            _digest_graph_value(digest, item)
        digest.update(b"};")
        return
    if type(value) in (tuple, list, set, frozenset):
        source = tuple(value)
        if type(value) in (set, frozenset):
            source = tuple(sorted(source, key=no_hook_json_sort_key))
        digest.update(b"Q[")
        for item in source:
            _digest_graph_value(digest, item)
        digest.update(b"];")
        return
    _digest_graph_value(digest, _graph_unavailable_text(value))


def _graph_snapshot_digest(value: Mapping[str, GraphRuntimeValue]) -> str:
    digest = hashlib.sha256()
    _digest_graph_value(digest, value)
    return digest.hexdigest()


def graph_snapshot_digest_owned(value: GraphRuntimeValue) -> str | None:
    """Recompute a canonical snapshot digest without trusting its published digest."""
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    payload: dict[str, GraphRuntimeValue] = {}
    for key, item in items:
        key_text = graph_vector_node_key(key)
        if key_text != "snapshot_digest":
            payload[key_text] = item
    return _graph_snapshot_digest(MappingProxyType(payload))


class GraphStateOwner:
    """Single mutation authority for hybrid graph runtime state."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._graph: dict[GraphRuntimeValue, GraphNodeRecord] = {}
        self._logical_revision = 0.0
        self._external_node_keys: dict[int, tuple[str, str, int]] = {}
        self._external_node_refs: dict[int, GraphRuntimeValue] = {}
        self._external_node_counts: dict[str, int] = {}

    def _node_key(self, node: GraphRuntimeValue) -> GraphRuntimeValue:
        base = graph_vector_node_key(node)
        if isinstance(node, str):
            return base
        identity = id(node)
        existing = self._external_node_keys.get(identity)
        if (
            existing is not None
            and self._external_node_refs.get(identity) is node
        ):
            return existing
        ordinal = self._external_node_counts.get(base, 0) + 1
        self._external_node_counts[base] = ordinal
        key = ("external_graph_node", base, ordinal)
        self._external_node_keys[identity] = key
        self._external_node_refs[identity] = node
        return key

    @staticmethod
    def _display_node_key(node: GraphRuntimeValue) -> str:
        if (
            type(node) is tuple
            and len(node) == PLR2004N3
            and node[0] == "external_graph_node"
            and type(node[1]) is str
        ):
            if type(node[2]) is int and type(node[2]) is not bool:
                return node[1] if node[2] == 1 else _graph_duplicate_text(node[1], node[2])
            return node[1]
        return graph_vector_node_key(node)

    def _display_edge_mapping(self, value: GraphRuntimeValue) -> dict[str, GraphRuntimeValue]:
        items = no_hook_mapping_items(value)
        if items is None:
            return {}
        displayed: dict[str, GraphRuntimeValue] = {}
        seen: dict[str, int] = {}
        for edge, item in items:
            key = _unique_graph_snapshot_key(
                self._display_node_key(edge), seen
            )
            displayed[key] = item
        return displayed

    def _display_edges(self, value: GraphRuntimeValue) -> frozenset[str]:
        if type(value) is set or type(value) is frozenset or type(value) is tuple or type(value) is list:
            source = tuple(value)
        else:
            return frozenset((GRAPH_RUNTIME_TEXT_UNAVAILABLE,))
        seen: dict[str, int] = {}
        return frozenset(
            _unique_graph_snapshot_key(
                self._display_node_key(edge), seen
            )
            for edge in sorted(
                source,
                key=lambda item: (
                    self._display_node_key(item),
                    item[2]
                    if type(item) is tuple
                    and len(item) == PLR2004N3
                    and item[0] == "external_graph_node"
                    else 0,
                ),
            )
        )

    def _release_external_node_refs(self, removed_nodes: set[GraphRuntimeValue]) -> None:
        if not removed_nodes:
            return
        for identity, key in tuple(dict.items(self._external_node_keys)):
            if key in removed_nodes:
                self._external_node_keys.pop(identity, None)
                self._external_node_refs.pop(identity, None)

    def _next_logical_timestamp(self) -> float:
        self._logical_revision = _finite_graph_float(self._logical_revision, 0.0, minimum=0.0) + 1.0
        return self._logical_revision

    @property
    def lock(self) -> RLock:
        return self._lock

    @property
    def graph(self) -> dict[GraphRuntimeValue, GraphNodeRecord]:
        """Internal graph reference for owned read-only diagnostics.

        New code should not mutate this directly.  The reference remains stable so
        old imports do not create a second graph owner.
        """
        return self._graph

    def reset(self) -> None:
        with self._lock:
            self._graph.clear()
            self._logical_revision = 0.0
            self._external_node_keys.clear()
            self._external_node_refs.clear()
            self._external_node_counts.clear()

    def ensure_node(self, node: GraphRuntimeValue) -> GraphRuntimeValue:
        with self._lock:
            key = self._node_key(node)
            if key not in self._graph:
                self._graph[key] = _node_default(
                    self._next_logical_timestamp()
                )
        return node

    def add_edge(
        self,
        src: GraphRuntimeValue,
        dst: GraphRuntimeValue,
        edge_type: str | None = None,
        weight: float = 1.0,
        *,
        evidence_id: GraphRuntimeValue = None,
        confidence: GraphRuntimeValue = 1.0,
        direction: GraphRuntimeValue = "outbound",
    ) -> None:
        with self._lock:
            src_key = self._node_key(src)
            dst_key = self._node_key(dst)
            now = self._next_logical_timestamp()
            src_data = self._graph.setdefault(src_key, _node_default(now))
            dst_data = self._graph.setdefault(dst_key, _node_default(now))
            _graph_record_set(src_data, "edges").add(dst_key)
            _graph_record_map(src_data, "edge_time")[dst_key] = now
            weight_reason = _nonfinite_graph_reason(weight, "non_finite_graph_weight")
            _graph_record_map(src_data, "weights")[dst_key] = _finite_graph_float(weight, 1.0, minimum=0.0)
            reason_key = self._display_node_key(dst_key)
            weight_reason_map = _graph_record_map(src_data, "weight_unavailable_reasons")
            if weight_reason:
                weight_reason_map[reason_key] = weight_reason
            else:
                weight_reason_map.pop(reason_key, None)
            edge_type_text = "generic" if edge_type is None else _trim_graph_runtime_text(edge_type, default="generic")
            if edge_type_text == "":
                edge_type_text = "generic"
            _graph_record_map(src_data, "types")[dst_key] = edge_type_text
            src_text = self._display_node_key(src_key)
            dst_text = self._display_node_key(dst_key)
            _graph_record_map(src_data, "edge_evidence_ids")[dst_key] = _graph_edge_evidence_id(
                src_text, dst_text, edge_type_text, evidence_id,
            )
            _graph_record_map(src_data, "edge_confidence")[dst_key] = _finite_graph_float(
                confidence, 0.0, minimum=0.0, maximum=1.0,
            )
            _graph_record_map(src_data, "edge_directions")[dst_key] = _validated_graph_direction(direction)
            ordinal = max(0, int(now))
            src_data["last_seen"] = now
            src_data["update_ordinal"] = ordinal
            dst_data["last_seen"] = now
            dst_data["update_ordinal"] = ordinal
            if not _graph_has_canonical_tag_evidence(src_data):
                if dst_text.startswith("tag:"):
                    _graph_record_set(src_data, "tags").add(dst_text[4:])
                elif edge_type_text == "tag":
                    _graph_record_set(src_data, "tags").add(dst_text)
        _invalidate_graph_model_caches()

    def update_node(
        self,
        node: GraphRuntimeValue,
        *,
        risk: float | None = None,
        tags: Iterable[GraphRuntimeValue] | None = None,
        tag_evidence_records: GraphRuntimeValue = None,
        **metadata: GraphRuntimeValue,
    ) -> None:
        with self._lock:
            node_key = self._node_key(node)
            now = self._next_logical_timestamp()
            data = self._graph.setdefault(node_key, _node_default(now))
            if risk is not None:
                risk_reason = _nonfinite_graph_reason(risk, "non_finite_graph_risk")
                data["risk"] = _finite_graph_float(risk, 0.0, minimum=0.0)
                if risk_reason:
                    data["risk_unavailable_reason"] = risk_reason
            data["last_seen"] = now
            if tags is not None:
                sanitized_tags, tag_reason = _sanitize_graph_tags(tags)
                if tag_evidence_records is None:
                    _graph_record_set(data, "tags").update(sanitized_tags)
                if tag_reason:
                    data["tags_unavailable_reason"] = tag_reason
            if tag_evidence_records is not None:
                canonical_records, evidence_reason = _sanitize_graph_tag_evidence_records(
                    tag_evidence_records,
                )
                if evidence_reason:
                    data["tag_evidence_unavailable_reason"] = evidence_reason
                else:
                    merged_records = _merge_graph_tag_evidence_records(
                        data.get("tag_evidence_records", ()), canonical_records,
                    )
                    data["tag_evidence_records"] = merged_records
                    data["tags"] = set(tag_evidence_string_projection(merged_records))
            for key, value in dict.items(metadata):
                if key == "tags":
                    if value is not None:
                        sanitized_tags, tag_reason = _sanitize_graph_tags(value)
                        if not _graph_has_canonical_tag_evidence(data):
                            _graph_record_set(data, "tags").update(sanitized_tags)
                        if tag_reason:
                            data["tags_unavailable_reason"] = tag_reason
                elif key == "attention":
                    attention_reason = _nonfinite_graph_reason(value, "non_finite_graph_attention")
                    data["attention"] = _finite_graph_float(value, 0.0, minimum=0.0, maximum=1.0)
                    if attention_reason:
                        data["attention_unavailable_reason"] = attention_reason
                elif key == "weights":
                    sanitized_weights, weight_reasons = _sanitize_graph_weights(value)
                    data["weights"] = sanitized_weights
                    if weight_reasons:
                        data["weight_unavailable_reasons"] = weight_reasons
                else:
                    data[graph_vector_node_key(key)] = _freeze_graph_snapshot_value(value)
            data["update_ordinal"] = max(0, int(now))
        _invalidate_graph_model_caches()

    def decay_weights(self, *, decay: float = 0.995, min_weight: float = 0.01) -> None:
        """Apply deterministic graph-weight decay through the graph-state owner.

        The graph model previously referenced an undefined decay helper.  Decay is
        intentionally ordinal/call based here, not wall-clock based, so replayed
        evidence does not depend on elapsed runtime.
        """
        if _nonfinite_graph_reason(decay, "graph_decay_rejected"):
            raise ValueError("graph_decay_rejected")
        if _nonfinite_graph_reason(min_weight, "graph_min_weight_rejected"):
            raise ValueError("graph_min_weight_rejected")
        factor = _finite_graph_float(decay, 0.0, minimum=0.0, maximum=1.0)
        floor = _finite_graph_float(min_weight, 0.0, minimum=0.0)
        with self._lock:
            for data in dict.values(self._graph):
                weights = data.setdefault("weights", {})
                if type(weights) is not dict:
                    weights = {}
                    data["weights"] = weights
                for edge, weight in tuple(dict.items(weights)):
                    weights[edge] = max(floor, _finite_graph_float(weight, 0.0, minimum=0.0) * factor)
                if weights:
                    data["update_ordinal"] = max(0, int(self._next_logical_timestamp()))
        _invalidate_graph_model_caches()


    def has_node(self, node: GraphRuntimeValue) -> bool:
        with self._lock:
            return self._node_key(node) in self._graph

    def _freeze_snapshot_value(self, value: GraphRuntimeValue) -> GraphRuntimeValue:
        return _freeze_graph_snapshot_value(value)

    def _node_snapshot_from_data(
        self,
        node: GraphRuntimeValue,
        data: Mapping[str, GraphRuntimeValue],
    ) -> Mapping[str, GraphRuntimeValue]:
        items = no_hook_mapping_items(data)
        if items is None:
            return _graph_failure("non_materializable_graph_node_snapshot", data)
        owned_data = dict(items)
        if not owned_data:
            return MappingProxyType({})
        node_id = self._display_node_key(node)
        edges = owned_data.get("edges", frozenset())
        if type(edges) not in (set, frozenset, tuple, list):
            edges = (GRAPH_RUNTIME_TEXT_UNAVAILABLE,)
        displayed_edges = self._display_edges(edges)
        tags = owned_data.get("tags", frozenset())
        canonical_records = tag_evidence_records(owned_data.get("tag_evidence_records", ()))
        if canonical_records:
            tags = tag_evidence_string_projection(canonical_records)
        if type(tags) not in (set, frozenset, tuple, list):
            tags = (GRAPH_RUNTIME_TEXT_UNAVAILABLE,)
        sanitized_weights, weight_reasons = _sanitize_graph_weights(owned_data.get("weights", {}))
        displayed_weights = self._display_edge_mapping(sanitized_weights)
        displayed_times = self._display_edge_mapping(owned_data.get("edge_time", {}))
        displayed_types = self._display_edge_mapping(owned_data.get("types", {}))
        displayed_evidence_ids = self._display_edge_mapping(owned_data.get("edge_evidence_ids", {}))
        displayed_confidence = self._display_edge_mapping(owned_data.get("edge_confidence", {}))
        displayed_directions = self._display_edge_mapping(owned_data.get("edge_directions", {}))
        existing_weight_reasons = owned_data.get("weight_unavailable_reasons", {})
        merged_weight_reasons: dict[str, GraphRuntimeValue] = {}
        existing_reason_items = no_hook_mapping_items(existing_weight_reasons)
        if existing_reason_items is not None:
            for reason_key, reason_value in existing_reason_items:
                merged_weight_reasons[graph_vector_node_key(reason_key)] = _freeze_graph_snapshot_value(reason_value)
        for reason_key, reason_value in dict.items(weight_reasons):
            merged_weight_reasons[graph_vector_node_key(reason_key)] = _freeze_graph_snapshot_value(reason_value)
        edge_records = []
        for destination in sorted(displayed_edges):
            edge_records.append(MappingProxyType({
                "record_version": GRAPH_EDGE_RECORD_VERSION,
                "source": node_id,
                "destination": destination,
                "edge_type": _trim_graph_runtime_text(displayed_types.get(destination), default="generic") or "generic",
                "weight": _finite_graph_float(displayed_weights.get(destination, 1.0), 1.0, minimum=0.0),
                "confidence": _finite_graph_float(displayed_confidence.get(destination, 1.0), 0.0, minimum=0.0, maximum=1.0),
                "source_evidence_id": _graph_edge_evidence_id(
                    node_id,
                    destination,
                    _trim_graph_runtime_text(displayed_types.get(destination), default="generic") or "generic",
                    displayed_evidence_ids.get(destination),
                ),
                "timestamp_ordinal": max(0, int(_finite_graph_float(displayed_times.get(destination, 0.0), 0.0, minimum=0.0))),
                "direction": _validated_graph_direction(displayed_directions.get(destination, "outbound")),
            }))
        snapshot: dict[str, GraphRuntimeValue] = {
            "snapshot_version": GRAPH_SNAPSHOT_SCHEMA_VERSION,
            "node_id": node_id,
            "node_type": _graph_node_type(node_id, owned_data),
            "created_ordinal": max(0, int(_finite_graph_float(owned_data.get("created_ordinal", 0), 0.0, minimum=0.0))),
            "update_ordinal": max(0, int(_finite_graph_float(owned_data.get("update_ordinal", 0), 0.0, minimum=0.0))),
            "edge_records": tuple(edge_records),
            "edges": displayed_edges,
            "edge_time": self._freeze_snapshot_value(displayed_times),
            "weights": self._freeze_snapshot_value(displayed_weights),
            "types": self._freeze_snapshot_value(displayed_types),
            "edge_evidence_ids": self._freeze_snapshot_value(displayed_evidence_ids),
            "edge_confidence": self._freeze_snapshot_value(displayed_confidence),
            "edge_directions": self._freeze_snapshot_value(displayed_directions),
            "risk": _finite_graph_float(owned_data.get("risk", 0.0), 0.0, minimum=0.0),
            "last_seen": self._freeze_snapshot_value(owned_data.get("last_seen")),
            "attention": _finite_graph_float(owned_data.get("attention", 0.0), 0.0, minimum=0.0, maximum=1.0),
            "tags": frozenset(graph_vector_node_key(tag) for tag in tags),
            "tag_evidence_records": canonical_records,
            "tags_unavailable_reason": self._freeze_snapshot_value(owned_data.get("tags_unavailable_reason")),
            "tag_evidence_unavailable_reason": self._freeze_snapshot_value(owned_data.get("tag_evidence_unavailable_reason")),
            "risk_unavailable_reason": self._freeze_snapshot_value(owned_data.get("risk_unavailable_reason")),
            "attention_unavailable_reason": self._freeze_snapshot_value(owned_data.get("attention_unavailable_reason")),
            "weight_unavailable_reasons": self._freeze_snapshot_value(merged_weight_reasons),
        }
        known = {
            "edges", "edge_time", "weights", "types", "edge_evidence_ids",
            "edge_confidence", "edge_directions", "risk", "last_seen", "attention",
            "tags", "tag_evidence_records", "tags_unavailable_reason",
            "tag_evidence_unavailable_reason", "risk_unavailable_reason",
            "attention_unavailable_reason", "weight_unavailable_reasons",
            "created_ordinal", "update_ordinal",
        }
        for key, value in sorted(owned_data.items(), key=lambda item: graph_vector_node_key(item[0])):
            key_text = graph_vector_node_key(key)
            if key_text not in known and key_text not in snapshot:
                snapshot[key_text] = self._freeze_snapshot_value(value)
        digest_input = MappingProxyType(dict(snapshot))
        snapshot["snapshot_digest"] = _graph_snapshot_digest(digest_input)
        return MappingProxyType(snapshot)

    def get_node_snapshot(self, node: GraphRuntimeValue) -> Mapping[str, GraphRuntimeValue] | None:
        with self._lock:
            data = self._graph.get(self._node_key(node))
            if data is None:
                return None
            return self._node_snapshot_from_data(self._node_key(node), data)

    def iter_node_snapshots(self) -> tuple[tuple[GraphRuntimeValue, Mapping[str, GraphRuntimeValue]], ...]:
        with self._lock:
            seen: dict[str, int] = {}
            rows = []
            for node, data in sorted(dict.items(self._graph), key=lambda item: self._display_node_key(item[0])):
                node_key = _unique_graph_snapshot_key(self._display_node_key(node), seen)
                rows.append((node_key, self._node_snapshot_from_data(node, data)))
            return tuple(rows)

    def prune(self, max_nodes: int = 50000, max_edges_per_node: int = 200) -> None:
        node_limit, node_issues = runtime_int(
            max_nodes, field_name="graph_max_nodes", default=50000
        )
        edge_limit, edge_issues = runtime_int(
            max_edges_per_node,
            field_name="graph_max_edges_per_node",
            default=200,
        )
        if node_issues or edge_issues or node_limit < 1 or edge_limit < 1:
            raise ValueError("graph_prune_limit_rejected")
        with self._lock:
            if len(self._graph) > node_limit:
                sorted_nodes = sorted(
                    dict.items(self._graph),
                    key=lambda x: (_finite_graph_float(dict.get(x[1], "last_seen", 0.0), 0.0), self._display_node_key(x[0])),
                )
                remove_count = len(self._graph) - node_limit
                remove_set = {node for node, _ in sorted_nodes[:remove_count]}
                for node in remove_set:
                    self._graph.pop(node, None)
                self._release_external_node_refs(remove_set)
                for data in dict.values(self._graph):
                    _graph_record_set(data, "edges").difference_update(remove_set)
                    for removed in remove_set:
                        _graph_record_map(data, "edge_time").pop(removed, None)
                        _graph_record_map(data, "weights").pop(removed, None)
                        _graph_record_map(data, "types").pop(removed, None)
                        _graph_record_map(data, "edge_directions").pop(removed, None)
                        _graph_record_map(data, "edge_confidence").pop(removed, None)
                        _graph_record_map(data, "edge_evidence_ids").pop(removed, None)
            for _node, data in dict.items(self._graph):
                edges = sorted(_graph_record_set(data, "edges"), key=graph_vector_node_key)
                changed = False
                if len(edges) > edge_limit:
                    weights = _graph_record_map(data, "weights")
                    ranked = sorted(
                        edges,
                        key=lambda e, edge_weights=weights: (-_finite_graph_float(dict.get(edge_weights, e, 1.0), 0.0, minimum=0.0), self._display_node_key(e)),
                    )
                    keep = set(ranked[:edge_limit])
                    drop = set(edges) - keep
                    data["edges"] = keep
                    changed = bool(drop)
                    for removed in drop:
                        for field_name in (
                            "edge_time", "weights", "types", "edge_evidence_ids",
                            "edge_confidence", "edge_directions",
                        ):
                            _graph_record_map(data, field_name).pop(removed, None)
                if changed:
                    data["update_ordinal"] = max(0, int(self._next_logical_timestamp()))
        _invalidate_graph_model_caches()

    def node_has_edges(self, node: GraphRuntimeValue) -> bool:
        with self._lock:
            data = self._graph.get(self._node_key(node))
            if data is None:
                return False
            edges = data.get("edges", ())
            if type(edges) is set or type(edges) is frozenset or type(edges) is tuple or type(edges) is list:
                return len(edges) > 0
            return False

    def snapshot(self) -> Mapping[str, Mapping[str, GraphRuntimeValue]]:
        """Return the canonical immutable full-graph snapshot."""
        with self._lock:
            seen: dict[str, int] = {}
            out: dict[str, Mapping[str, GraphRuntimeValue]] = {}
            for node, data in sorted(dict.items(self._graph), key=lambda item: self._display_node_key(item[0])):
                node_key = _unique_graph_snapshot_key(self._display_node_key(node), seen)
                out[node_key] = self._node_snapshot_from_data(node, data)
            return MappingProxyType(out)


_GRAPH_STATE = GraphStateOwner()
GRAPH_LOCK = _GRAPH_STATE.lock
def graph_owner() -> GraphStateOwner:
    return _GRAPH_STATE


def reset_graph_state() -> None:
    _GRAPH_STATE.reset()
    _invalidate_graph_model_caches()


def ensure_graph_node_owned(node: GraphRuntimeValue) -> GraphRuntimeValue:
    return _GRAPH_STATE.ensure_node(node)


def add_graph_edge_owned(
    src: GraphRuntimeValue,
    dst: GraphRuntimeValue,
    edge_type: str | None = None,
    weight: float = 1.0,
    *,
    evidence_id: GraphRuntimeValue = None,
    confidence: GraphRuntimeValue = 1.0,
    direction: GraphRuntimeValue = "outbound",
) -> None:
    _GRAPH_STATE.add_edge(
        src,
        dst,
        edge_type=edge_type,
        weight=weight,
        evidence_id=evidence_id,
        confidence=confidence,
        direction=direction,
    )


def update_graph_node_owned(
    node: GraphRuntimeValue,
    *,
    risk: float | None = None,
    tags: Iterable[GraphRuntimeValue] | None = None,
    tag_evidence_records: GraphRuntimeValue = None,
    **metadata: GraphRuntimeValue,
) -> None:
    _GRAPH_STATE.update_node(
        node,
        risk=risk,
        tags=tags,
        tag_evidence_records=tag_evidence_records,
        **metadata,
    )


def graph_node_has_edges(node: GraphRuntimeValue) -> bool:
    return _GRAPH_STATE.node_has_edges(node)


def graph_has_node(node: GraphRuntimeValue) -> bool:
    return _GRAPH_STATE.has_node(node)


def graph_node_snapshot(node: GraphRuntimeValue) -> Mapping[str, GraphRuntimeValue] | None:
    return _GRAPH_STATE.get_node_snapshot(node)


def graph_node_snapshots() -> tuple[tuple[GraphRuntimeValue, Mapping[str, GraphRuntimeValue]], ...]:
    return _GRAPH_STATE.iter_node_snapshots()


def prune_graph_owned(max_nodes: int = 50000, max_edges_per_node: int = 200) -> None:
    _GRAPH_STATE.prune(max_nodes=max_nodes, max_edges_per_node=max_edges_per_node)


def decay_graph_weights_owned(*, decay: float = 0.995, min_weight: float = 0.01) -> None:
    _GRAPH_STATE.decay_weights(decay=decay, min_weight=min_weight)


def graph_snapshot() -> Mapping[str, Mapping[str, GraphRuntimeValue]]:
    return _GRAPH_STATE.snapshot()


__all__ = (
    "GRAPH_EDGE_RECORD_VERSION",
    "GRAPH_LOCK",
    "GRAPH_SNAPSHOT_SCHEMA_VERSION",
    "GraphStateOwner",
    "add_graph_edge_owned",
    "decay_graph_weights_owned",
    "ensure_graph_node_owned",
    "graph_has_node",
    "graph_node_has_edges",
    "graph_node_snapshot",
    "graph_snapshot_digest_owned",
    "graph_node_snapshots",
    "graph_owner",
    "graph_snapshot",
    "graph_vector_node_key",
    "prune_graph_owned",
    "reset_graph_state",
    "update_graph_node_owned",
)
