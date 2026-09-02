"""Scanner-owned archive publication request markers.

Archive scanners observe relationships between containers, members, and member
findings. They must not mutate graph/model/final JSON state directly. These
helpers preserve the observed relationship facts as deterministic scanner tags
so the publication owner can publish graph/final-JSON effects without scanner
side effects.
"""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text, no_hook_type_name
from Virus_Scan.scanners.archives.text_boundaries import archive_delimited_join, archive_prefixed, archive_type_diagnostic

PLR2004N4 = 4

ArchiveGraphEdgeRequest = tuple[str, str, str, float]


def _safe_tag_text_with_reason(
    value: object,
    *,
    limit: int = 120,
    missing_reason: str = "missing_archive_publication_text",
    unsupported_reason: str = "unsafe_archive_publication_text_rejected",
) -> tuple[str, str]:
    max_len = limit if type(limit) is int and type(limit) is not bool and limit > 0 else 120
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return archive_type_diagnostic(archive_prefixed(str.__add__(reason, ":"), ""), value)[:max_len], reason
    cleaned = str.replace(text, "\n", " ")
    cleaned = str.replace(cleaned, "\r", " ")
    cleaned = str.strip(cleaned)
    cleaned = "|".join(part for part in str.split(cleaned, "|") if part)
    return (cleaned[:max_len] or "unknown", "")


def _safe_tag_text(value: object, *, limit: int = 120) -> str:
    text, _reason = _safe_tag_text_with_reason(value, limit=limit)
    return text


def _archive_edge_request_items(edge_requests: object) -> tuple[object, ...]:
    if edge_requests is None:
        return ()
    if type(edge_requests) is tuple:
        return edge_requests
    if type(edge_requests) is list:
        return tuple(edge_requests)
    return (("archive_graph_edge_requests_rejected", no_hook_type_name(edge_requests), "archive_graph_input_rejected", 0.0),)


def _archive_edge_parts(edge_request: object, index: int) -> tuple[object, object, object, object]:
    if type(edge_request) is tuple:
        if len(edge_request) == PLR2004N4:
            return (
                tuple.__getitem__(edge_request, 0),
                tuple.__getitem__(edge_request, 1),
                tuple.__getitem__(edge_request, 2),
                tuple.__getitem__(edge_request, 3),
            )
    elif type(edge_request) is list:
        if len(edge_request) == PLR2004N4:
            return (
                list.__getitem__(edge_request, 0),
                list.__getitem__(edge_request, 1),
                list.__getitem__(edge_request, 2),
                list.__getitem__(edge_request, 3),
            )
    return (
        archive_delimited_join("_", "archive_graph_edge_request", index, "rejected"),
        no_hook_type_name(edge_request),
        "archive_graph_input_rejected",
        0.0,
    )


def _archive_edge_text(value: object, *, field: str, default: str = "unknown") -> str:
    text, reason = _safe_tag_text_with_reason(
        value,
        limit=240,
        missing_reason=archive_delimited_join("_", "missing_archive_graph", field),
        unsupported_reason=archive_delimited_join("_", "unsafe_archive_graph", field, "rejected"),
    )
    if reason:
        return text
    return text or default


def _archive_edge_weight(value: object) -> float:
    weight, _reason = no_hook_finite_float(
        value,
        default=1.0,
        reason="unsafe_archive_graph_weight_rejected",
        non_finite_reason="non_finite_archive_graph_weight_rejected",
        allow_exact_text=True,
    )
    return weight


def archive_graph_publication_edges(
    *,
    edge_requests: object,
) -> tuple[ArchiveGraphEdgeRequest, ...]:
    """Return immutable archive graph-publication edge requests."""
    edges: list[ArchiveGraphEdgeRequest] = []
    for index, edge_request in enumerate(_archive_edge_request_items(edge_requests)):
        src, dst, edge_type, weight = _archive_edge_parts(edge_request, index)
        safe_edge_type = _archive_edge_text(edge_type, field="edge_type", default="archive")
        edges.append(
            (
                _archive_edge_text(src, field="source"),
                _archive_edge_text(dst, field="destination"),
                safe_edge_type or "archive",
                _archive_edge_weight(weight),
            )
        )
    return tuple(edges)


def _member_tags_present(member_tags: object) -> tuple[bool, str]:
    if member_tags is None:
        return False, ""
    if type(member_tags) is tuple:
        return tuple.__len__(member_tags) > 0, ""
    if type(member_tags) is list:
        return list.__len__(member_tags) > 0, ""
    if type(member_tags) is set:
        return set.__len__(member_tags) > 0, ""
    if type(member_tags) is frozenset:
        return frozenset.__len__(member_tags) > 0, ""
    if type(member_tags) is dict:
        return dict.__len__(member_tags) > 0, ""
    return False, archive_type_diagnostic("unsafe_archive_member_tags_rejected:", member_tags)


def _append_unique_archive_markers(tags: list[str], markers: tuple[str, ...]) -> None:
    if type(tags) is not list:
        return
    existing = {item for item in tags if type(item) is str}
    for marker in markers:
        if marker not in existing:
            list.append(tags, marker)
            existing.add(marker)


def append_archive_graph_publication_request_tags(
    tags: list[str],
    *,
    parent_path: object,
    edge_requests: object,
    member_name: object | None = None,
    extracted_path: object | None = None,
    member_tags: object = (),
) -> tuple[ArchiveGraphEdgeRequest, ...]:
    """Append deterministic evidence that graph publication is requested.

    The returned tuple is immutable and side-effect free. The tag projection
    preserves downstream final-JSON visibility in the current archive scanner
    contract, which mutates a tag list and returns a suspicious flag.
    """
    edges = archive_graph_publication_edges(edge_requests=edge_requests)
    parent_text = _safe_tag_text(parent_path)
    markers: list[str] = [
        "archive_graph_publication_requested",
        "archive_final_json_must_record",
        archive_prefixed("archive_graph_publication_edge_count:", len(edges)),
        archive_prefixed("archive_graph_publication_parent:", parent_text),
    ]
    member_text, member_reason = _safe_tag_text_with_reason(
        member_name,
        missing_reason="missing_archive_graph_member_name",
        unsupported_reason="unsafe_archive_graph_member_name_rejected",
    )
    if member_name is not None and member_text:
        markers.append("archive_graph_publication_member")
        markers.append(archive_prefixed("archive_graph_publication_member_name:", member_text))
    if member_reason:
        markers.append(archive_prefixed("archive_graph_publication_member_name_rejected:", member_reason))
    extracted_text, extracted_reason = _safe_tag_text_with_reason(
        extracted_path,
        missing_reason="missing_archive_graph_extracted_path",
        unsupported_reason="unsafe_archive_graph_extracted_path_rejected",
    )
    if extracted_path is not None and extracted_text:
        markers.append("archive_graph_publication_extracted_path")
    if extracted_reason:
        markers.append(archive_prefixed("archive_graph_publication_extracted_path_rejected:", extracted_reason))
    tags_present, tags_reason = _member_tags_present(member_tags)
    if tags_present:
        markers.append("archive_graph_publication_member_tags")
    if tags_reason:
        markers.append(tags_reason)
    for _src, _dst, edge_type, _weight in edges[:20]:
        markers.append(archive_prefixed("archive_graph_publication_edge_type:", _safe_tag_text(edge_type, limit=60)))
    _append_unique_archive_markers(tags, tuple(markers))
    return edges


__all__ = ("ArchiveGraphEdgeRequest", "archive_graph_publication_edges", "append_archive_graph_publication_request_tags")
