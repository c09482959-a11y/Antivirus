"""Canonical container/artifact context classification for scan records."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items

from Virus_Scan.routing.artifact_fingerprints import fingerprint_artifact
from Virus_Scan.routing.baseline_routing import (
    BaselineRoute,
    BaselineRouteRequest,
    build_baseline_route,
    effective_analysis_engine,
)
from Virus_Scan.routing.context_container_fingerprints import (
    direct_container_fingerprint as _direct_container_fingerprint,
    has_container_evidence,
)
from Virus_Scan.routing.context_evidence_context import RoutingEvidenceContext, container_fingerprint_from_context
from Virus_Scan.routing.context_identity_types import EngineContextIdentity
from Virus_Scan.routing.context_reporting_tags import routing_identity_reporting_tags
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.context_router_identity import file_identity_from_router_identity
from Virus_Scan.routing.file_identity import sniff_file_identity
from Virus_Scan.routing.path_boundaries import routing_optional_path, routing_path
from Virus_Scan.routing.static_analysis_summary import (
    STATIC_ANALYSIS_SUMMARY_FIELD,
    static_analysis_summary_record,
)


def classify_engine_context(
    file_path: object,
    *,
    container_root: object | None = None,
    tags: object = (),
    trusted_benign: bool = False,
    degraded: bool = False,
    evidence_context: RoutingEvidenceContext | None = None,
    router_identity: object | None = None,
) -> EngineContextIdentity:
    del tags  # Explicitly unused contract parameters.
    container_root_path, container_root_reason = routing_optional_path(container_root, unsupported_reason="unsafe_container_root_rejected")
    safe_container_root = container_root_path if not container_root_reason else None
    container = container_fingerprint_from_context(evidence_context, safe_container_root, file_path)
    identity = file_identity_from_router_identity(router_identity) or sniff_file_identity(file_path)
    artifact = fingerprint_artifact(file_path, identity, container_root=safe_container_root)
    if safe_container_root is not None:
        container = _maybe_use_direct_container(container, artifact.engine, identity.sniffed_type, file_path, safe_container_root, evidence_context)
    cross_engine = bool(container.engine not in {"other", "media"} and artifact.engine not in {"other", "media", container.engine})
    effective = _effective_engine(artifact.engine, identity.sniffed_type, identity.sniffed_embedded_types)
    route: BaselineRoute = build_baseline_route(
        BaselineRouteRequest(
            container_engine=container.engine,
            artifact_engine=artifact.engine,
            declared_extension=identity.declared_extension,
            sniffed_type=identity.sniffed_type,
            sniffed_embedded_types=identity.sniffed_embedded_types,
            extension_mismatch=identity.extension_mismatch,
            engine_mismatch=cross_engine,
            degraded=degraded,
            trusted_benign=trusted_benign,
        )
    )
    context_identity = _build_context_identity(container, artifact, identity, cross_engine, effective, route)
    context_identity.validate(context="classify_engine_context")
    return context_identity


def _maybe_use_direct_container(container: object, artifact_engine: str, sniffed_type: str, file_path: object, container_root: object, evidence_context: RoutingEvidenceContext | None) -> object:
    root_path, root_reason = routing_path(container_root, missing_reason="container_root_missing", unsupported_reason="unsafe_container_root_rejected")
    file_candidate, file_reason = routing_path(file_path, missing_reason="file_path_missing", unsupported_reason="unsafe_file_path_rejected")
    if root_reason or root_path is None or file_reason or file_candidate is None:
        return container
    file_parent = file_candidate.parent
    try:
        direct_child = file_parent.resolve() == root_path.resolve()
    except OSError:
        direct_child = file_parent == root_path
    if not direct_child:
        return container
    direct_container = evidence_context.fingerprint_for_root(root_path) if evidence_context is not None else _direct_container_fingerprint(root_path)
    if direct_container.engine != "other" and has_container_evidence(direct_container) and direct_container.confidence >= 0.5:
        return direct_container
    if direct_container.engine != "other" and (container.engine == "other" or direct_container.engine == container.engine or artifact_engine == "other"):
        return direct_container
    if artifact_engine == "other" and sniffed_type in {"unknown", "data", "json", "javascript", "python_source", "pe", "elf", "macho", "zip", "jar", "apk", "docx_zip", "wasm", "asar"}:
        return direct_container
    return container


def _effective_engine(artifact_engine: str, sniffed_type: str, embedded_types: tuple[str, ...]) -> str:
    if "pe" in embedded_types:
        return "embedded_pe_payload"
    if "zip" in embedded_types:
        return "embedded_zip_payload"
    return effective_analysis_engine(artifact_engine, sniffed_type)


def _build_context_identity(container: object, artifact: object, identity: object, cross_engine: bool, effective: str, route: BaselineRoute) -> EngineContextIdentity:
    evidence = tuple(dict.fromkeys(tuple(container.evidence) + tuple(artifact.evidence) + tuple(identity.evidence)))
    return EngineContextIdentity(
        container_engine=container.engine,
        container_engine_confidence=round(float(container.confidence), 4),
        artifact_engine=artifact.engine,
        artifact_engine_confidence=round(float(artifact.confidence), 4),
        declared_extension=identity.declared_extension,
        sniffed_type=identity.sniffed_type,
        sniffed_embedded_types=identity.sniffed_embedded_types,
        extension_mismatch=identity.extension_mismatch,
        cross_engine_artifact=cross_engine,
        engine_mismatch=cross_engine,
        effective_analysis_engine=effective,
        baseline_key=route.baseline_key,
        extension_baseline=route.extension_baseline,
        contextual_baseline=route.contextual_baseline,
        container_extension_baseline=route.container_extension_baseline,
        secondary_baseline_keys=tuple(dict.fromkeys(route.secondary_baseline_keys)),
        baseline_lookup_order=tuple(dict.fromkeys(route.baseline_lookup_order)),
        learning_baseline_key=route.learning_baseline_key,
        blocked_baseline_keys=tuple(key for key in dict.fromkeys(route.blocked_baseline_keys) if not (route.learning_allowed and key == route.learning_baseline_key)),
        learning_allowed=route.learning_allowed,
        learning_reason=route.learning_reason,
        fingerprint_evidence=evidence[:64],
    )


_ROUTING_EVIDENCE_RECORD_FIELDS = (
    "container_engine",
    "container_engine_confidence",
    "artifact_engine",
    "artifact_engine_confidence",
    "declared_extension",
    "sniffed_type",
    "sniffed_embedded_types",
    "extension_mismatch",
    "cross_engine_artifact",
    "engine_mismatch",
    "effective_analysis_engine",
    "baseline_key",
    "extension_baseline",
    "contextual_baseline",
    "container_extension_baseline",
    "secondary_baseline_keys",
    "baseline_lookup_order",
    "learning_baseline_key",
    "blocked_baseline_keys",
    "learning_allowed",
    "learning_reason",
    "fingerprint_evidence",
)


def attached_routing_evidence_identity(record: object) -> EngineContextIdentity | None:
    """Return a validated attached routing identity, or ``None`` when absent.

    A partial attached identity is corruption: callers must not recompute over it
    and thereby hide a process/IPC contract violation.
    """
    items = no_hook_mapping_items(record)
    if items is None:
        return None
    snapshot = dict(items)
    present = tuple(field for field in _ROUTING_EVIDENCE_RECORD_FIELDS if field in snapshot)
    if not present:
        return None
    if len(present) != len(_ROUTING_EVIDENCE_RECORD_FIELDS):
        raise ValueError("attached_routing_evidence_partial")

    def sequence(field: str) -> tuple[str, ...]:
        raw = dict.get(snapshot, field)
        values = no_hook_sequence_items(raw)
        if type(raw) not in (tuple, list) or len(values) != len(raw):
            raise ValueError("attached_routing_evidence_invalid:" + field)
        if any(type(item) is not str for item in values):
            raise ValueError("attached_routing_evidence_invalid:" + field)
        return tuple(values)

    identity = EngineContextIdentity(
        container_engine=dict.get(snapshot, "container_engine"),
        container_engine_confidence=dict.get(snapshot, "container_engine_confidence"),
        artifact_engine=dict.get(snapshot, "artifact_engine"),
        artifact_engine_confidence=dict.get(snapshot, "artifact_engine_confidence"),
        declared_extension=dict.get(snapshot, "declared_extension"),
        sniffed_type=dict.get(snapshot, "sniffed_type"),
        sniffed_embedded_types=sequence("sniffed_embedded_types"),
        extension_mismatch=dict.get(snapshot, "extension_mismatch"),
        cross_engine_artifact=dict.get(snapshot, "cross_engine_artifact"),
        engine_mismatch=dict.get(snapshot, "engine_mismatch"),
        effective_analysis_engine=dict.get(snapshot, "effective_analysis_engine"),
        baseline_key=dict.get(snapshot, "baseline_key"),
        extension_baseline=dict.get(snapshot, "extension_baseline"),
        contextual_baseline=dict.get(snapshot, "contextual_baseline"),
        container_extension_baseline=dict.get(snapshot, "container_extension_baseline"),
        secondary_baseline_keys=sequence("secondary_baseline_keys"),
        baseline_lookup_order=sequence("baseline_lookup_order"),
        learning_baseline_key=dict.get(snapshot, "learning_baseline_key"),
        blocked_baseline_keys=sequence("blocked_baseline_keys"),
        learning_allowed=dict.get(snapshot, "learning_allowed"),
        learning_reason=dict.get(snapshot, "learning_reason"),
        fingerprint_evidence=sequence("fingerprint_evidence"),
    )
    identity.validate(context="attached_routing_evidence")
    return identity



def attach_routing_evidence_to_record(
    record: dict[str, object],
    file_path: object,
    *,
    container_root: object | None = None,
    tags: object = (),
    trusted_benign: bool = False,
    degraded: bool = False,
    evidence_context: RoutingEvidenceContext | None = None,
    router_identity: object | None = None,
) -> dict[str, object]:
    """Attach canonical immutable routing evidence to one scanner result."""
    record_items = no_hook_mapping_items(record)
    if record_items is None:
        raise ValueError("routing evidence attachment requires a result record object")
    record_snapshot = dict(record_items)
    context_identity = classify_engine_context(
        file_path,
        container_root=container_root,
        tags=tags if tags is not None else (dict.get(record_snapshot, "tags") if dict.get(record_snapshot, "tags") is not None else ()),
        trusted_benign=trusted_benign,
        degraded=degraded,
        evidence_context=evidence_context,
        router_identity=router_identity,
    )
    annotated = dict(record_snapshot)
    annotated.update(context_identity.as_record_fields())
    identity_record = route_identity_record(router_identity)
    if identity_record is not None:
        static_summary = static_analysis_summary_record(
            dict.get(identity_record, STATIC_ANALYSIS_SUMMARY_FIELD)
        )
        if static_summary is not None:
            annotated[STATIC_ANALYSIS_SUMMARY_FIELD] = static_summary
    contextual_tags = routing_identity_reporting_tags(annotated)
    if contextual_tags:
        merged_tags = list(no_hook_sequence_items(dict.get(annotated, "tags", ())))
        seen_text_tags = {tag for tag in merged_tags if type(tag) is str}
        for tag in contextual_tags:
            if tag not in seen_text_tags:
                seen_text_tags.add(tag)
                merged_tags.append(tag)
        annotated["tags"] = merged_tags
    return annotated
