"""Container fingerprint selection for contextual routing identity."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_type_name
from Virus_Scan.routing.path_boundaries import routing_optional_path, routing_path
from Virus_Scan.routing.engine_fingerprints import (
    ContainerSampleCache,
    EngineFingerprint,
    container_file_sample,
    fingerprint_container,
    score_direct_container_directory,
    score_engine_for_path,
)


PLR2004N0_5 = 0.5
PLR2004N0_6 = 0.6


def _routing_exception_token(prefix: str, exc: BaseException) -> str:
    return str.__add__(prefix, no_hook_type_name(exc))


def _fingerprint_mapping_items(value: object) -> tuple[tuple[str, EngineFingerprint], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    out: list[tuple[str, EngineFingerprint]] = []
    for engine, fingerprint in items:
        if type(engine) is str and type(fingerprint) is EngineFingerprint:
            out.append((engine, fingerprint))
    return tuple(out)


def direct_container_fingerprint(
    root: Path, *, sample_cache: ContainerSampleCache | None = None,
) -> EngineFingerprint:
    owned_sample_cache: ContainerSampleCache = {} if sample_cache is None else sample_cache
    scores: dict[str, float] = {"renpy": 0.0, "rpgm": 0.0, "unity": 0.0, "media": 0.0}
    evidence: dict[str, list[str]] = {"renpy": [], "rpgm": [], "unity": [], "media": []}
    unavailable_evidence: list[str] = []
    try:
        children = tuple(sorted(root.iterdir(), key=lambda item: item.as_posix().casefold()))
    except OSError as exc:
        return EngineFingerprint(
            "other",
            0.1,
            1.0,
            ("direct_container_fingerprint_unavailable", _routing_exception_token("direct_container_root_error:", exc)),
        )
    for child in children:
        _score_direct_child(root, child, scores, evidence, unavailable_evidence, owned_sample_cache)
    return _select_direct_container_fingerprint(scores, evidence, unavailable_evidence)


def _score_direct_child(
    root: Path,
    child: Path,
    scores: dict[str, float],
    evidence: dict[str, list[str]],
    unavailable_evidence: list[str],
    sample_cache: ContainerSampleCache,
) -> None:
    del root  # Explicitly unused contract parameters.
    name = child.name.lower()
    if child.is_dir():
        for engine, fp in _fingerprint_mapping_items(score_direct_container_directory(name)):
            if engine in scores:
                scores[engine] += fp.score
                evidence[engine].extend(fp.evidence[:8])
    sample = b""
    sample_unavailable_evidence = ""
    if child.is_file():
        sampled = container_file_sample(child, sample_cache)
        sample = sampled.data
        if sampled.unavailable_reason:
            sample_unavailable_evidence = ":".join((
                "direct_container_sample_unavailable", name, sampled.unavailable_reason,
            ))
            unavailable_evidence.append(sample_unavailable_evidence)
    for engine, fp in _fingerprint_mapping_items(score_engine_for_path(name, root=None, sample=sample)):
        if engine in scores:
            scores[engine] += fp.score
            evidence[engine].extend(fp.evidence[:8])
            if sample_unavailable_evidence:
                evidence[engine].append(sample_unavailable_evidence)


def _select_direct_container_fingerprint(
    scores: dict[str, float],
    evidence: dict[str, list[str]],
    unavailable_evidence: list[str],
) -> EngineFingerprint:
    total = sum(dict.get(scores, key, 0.0) for key in tuple(dict.keys(scores)))
    if total <= 0:
        merged = ('no_direct_container_engine_fingerprint', *tuple(unavailable_evidence))
        return EngineFingerprint("other", 0.1, 1.0, tuple(dict.fromkeys(merged)))
    best = max(tuple(dict.keys(scores)), key=lambda key: dict.get(scores, key, 0.0))
    confidence = min(1.0, scores[best] / total)
    if confidence < PLR2004N0_6:
        return EngineFingerprint("other", scores[best], confidence, ('weak_direct_container_engine_fingerprint', *tuple(evidence[best][:16])))
    return EngineFingerprint(best, scores[best], confidence, tuple(dict.fromkeys(evidence[best]))[:32])


def has_container_evidence(fingerprint: EngineFingerprint) -> bool:
    if fingerprint.engine not in {"renpy", "rpgm", "unity"}:
        return False
    return any(
        item.startswith(("filename:", "direct_dir:", "path_marker:", "path:"))
        for item in fingerprint.evidence
    )


def _container_root_is_scan_safe(root: Path) -> bool:
    """Avoid treating the process CWD as an implicit scan container.

    Model/adaptive scoring often passes synthetic node names rather than a real
    extracted archive root.  Walking ``Path('.')`` in that case lets one model
    scoring call fingerprint the entire repository and makes replay/test output
    depend on ambient process working directory contents.  Real scan callers can
    still provide an explicit ``container_root`` or an existing non-CWD parent.
    """
    if root in {Path(""), Path(".")}:
        return False
    result = False
    try:
        result = root.exists()
    except OSError:
        result = False
    return result


def _no_container_fingerprint(reason: str) -> EngineFingerprint:
    """Return explicit no-container evidence without scanning the process CWD."""
    text, text_reason = no_hook_text(reason, missing_reason="container_context_missing", unsupported_reason="container_context_rejected")
    return EngineFingerprint("other", 0.1, 1.0, ("container_context_unavailable" if text_reason or text == "" else text,))


def container_fingerprint(container_root: object | None, file_path: object) -> EngineFingerprint:
    roots = _candidate_container_roots(container_root, file_path)
    if not roots:
        return _no_container_fingerprint("container_root_not_provided")
    scored = tuple((root, fingerprint_container(root)) for root in roots)
    selected = _select_local_container(scored)
    if selected is not None:
        return selected
    return _no_container_fingerprint("container_root_unavailable")


def _candidate_container_roots(container_root: object | None, file_path: object) -> tuple[Path, ...]:
    file_candidate, file_reason = routing_path(file_path, missing_reason="file_path_missing", unsupported_reason="unsafe_file_path_rejected")
    if file_reason or file_candidate is None:
        return ()
    file_parent = file_candidate.parent
    root, root_reason = routing_optional_path(container_root, unsupported_reason="unsafe_container_root_rejected")
    if root_reason:
        return ()
    if root is None:
        if not _container_root_is_scan_safe(file_parent):
            return ()
        return (file_parent,)
    try:
        relative_parent = file_parent.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return (root,)
    candidates = [root]
    current = root
    for part in relative_parent.parts:
        current = current / part
        candidates.append(current)
    return tuple(reversed(candidates))


def _select_local_container(scored: tuple[tuple[Path, EngineFingerprint], ...]) -> EngineFingerprint | None:
    strong_containers = tuple(
        (index, fp)
        for index, (_root, fp) in enumerate(scored)
        if fp.confidence >= PLR2004N0_5 and has_container_evidence(fp)
    )
    local_strong = tuple(fp for index, fp in strong_containers if index < len(scored) - 1)
    if local_strong:
        return local_strong[0]
    local_media = tuple(
        fp
        for index, (_root, fp) in enumerate(scored)
        if fp.engine == "media" and fp.confidence >= PLR2004N0_5 and index < len(scored) - 1
    )
    if local_media:
        return _select_local_media(scored, strong_containers, local_media)
    if len(scored) > 1 and not strong_containers:
        nearest = scored[0][1]
        if nearest.engine in {"other", "media"} and not has_container_evidence(nearest):
            return nearest
    if strong_containers:
        return strong_containers[0][1]
    strong = tuple(fp for _root, fp in scored if fp.engine not in {"other", "media"} and fp.confidence >= PLR2004N0_5)
    if strong:
        return strong[0]
    if scored:
        return max((fp for _root, fp in scored), key=lambda item: (item.engine != "media", item.confidence, item.score, item.engine))
    return None


def _select_local_media(
    scored: tuple[tuple[Path, EngineFingerprint], ...],
    strong_containers: tuple[tuple[int, EngineFingerprint], ...],
    local_media: tuple[EngineFingerprint, ...],
) -> EngineFingerprint:
    if not strong_containers:
        return local_media[0]
    final_index = len(scored) - 1
    final_strong = tuple(fp for index, fp in strong_containers if index == final_index)
    non_final_strong = tuple(fp for index, fp in strong_containers if index != final_index)
    if non_final_strong:
        return non_final_strong[0]
    if final_strong:
        direct_root = direct_container_fingerprint(scored[-1][0])
        if direct_root.engine == final_strong[0].engine and has_container_evidence(direct_root):
            return final_strong[0]
    return local_media[0]
