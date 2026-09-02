"""Immutable routing evidence context for scan-root fingerprints."""
from __future__ import annotations
from typing import TYPE_CHECKING

from dataclasses import dataclass

from Virus_Scan.routing.context_container_fingerprints import container_fingerprint, direct_container_fingerprint
from Virus_Scan.routing.path_boundaries import routing_optional_path, routing_path
from Virus_Scan.routing.engine_fingerprints import ContainerSampleCache, EngineFingerprint, fingerprint_container

if TYPE_CHECKING:
    from pathlib import Path

@dataclass(frozen=True, slots=True)
class RoutingEvidenceContext:
    """Immutable scan-owned routing context."""

    container_root: Path | None
    root_fingerprint: EngineFingerprint | None
    direct_root_fingerprint: EngineFingerprint | None

    @classmethod
    def build(cls, container_root: object | None) -> "RoutingEvidenceContext":
        root, root_reason = routing_optional_path(container_root, unsupported_reason="unsafe_container_root_rejected")
        if root_reason or root is None:
            return cls(None, None, None)
        sample_cache: ContainerSampleCache = {}
        try:
            root_fingerprint = fingerprint_container(root, sample_cache=sample_cache)
        except OSError:
            root_fingerprint = EngineFingerprint("other", 0.1, 1.0, ("container_root_fingerprint_unavailable",))
        return cls(
            root, root_fingerprint,
            direct_container_fingerprint(root, sample_cache=sample_cache),
        )

    def fingerprint_for_root(self, root: Path) -> EngineFingerprint:
        del root  # Explicitly unused contract parameters.
        if self.container_root is None or self.root_fingerprint is None:
            exception_message = "routing evidence context has no scan-owned container root fingerprint"
            raise ValueError(exception_message)
        return self.root_fingerprint

    def direct_fingerprint_for_root(self, root: Path) -> EngineFingerprint:
        del root
        if self.container_root is None or self.direct_root_fingerprint is None:
            exception_message = "routing evidence context has no scan-owned direct container fingerprint"
            raise ValueError(exception_message)
        return self.direct_root_fingerprint


def container_fingerprint_from_context(
    context: RoutingEvidenceContext | None,
    container_root: object | None,
    file_path: object,
) -> EngineFingerprint:
    if context is None or context.container_root is None:
        return container_fingerprint(container_root, file_path)
    root_fp = context.root_fingerprint
    if not isinstance(root_fp, EngineFingerprint):
        exception_message = "scan-owned routing context missing root fingerprint"
        raise ValueError(exception_message)
    root_path, root_reason = routing_optional_path(container_root, unsupported_reason="unsafe_container_root_rejected")
    if root_reason or root_path is None:
        root_path = context.container_root
    file_candidate, file_reason = routing_path(file_path, missing_reason="file_path_missing", unsupported_reason="unsafe_file_path_rejected")
    if file_reason or file_candidate is None or root_path is None:
        return root_fp
    try:
        direct_child = file_candidate.parent.resolve() == root_path.resolve()
    except OSError:
        direct_child = file_candidate.parent == root_path
    if direct_child:
        direct_fp = context.direct_fingerprint_for_root(context.container_root)
        if direct_fp.engine != "other" and (root_fp.engine == "other" or direct_fp.engine == root_fp.engine):
            return direct_fp
    return root_fp
