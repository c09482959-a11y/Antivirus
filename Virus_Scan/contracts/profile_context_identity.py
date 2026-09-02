"""Public profile-learning context identity boundary.

Routing owns file/container context classification. Profile learning consumes the
immutable routing identity record through this repository-level contract without
depending on routing internals or duplicate model adapters.
"""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.routing.context_identity import classify_engine_context

if TYPE_CHECKING:
    from Virus_Scan.routing.context_identity_types import EngineContextIdentity

def profile_learning_context_identity(
    file_path: object,
    *,
    container_root: object | None = None,
    tags: object = (),
    trusted_benign: bool = False,
    degraded: bool = False,
    evidence_context: object | None = None,
    router_identity: object | None = None,
) -> EngineContextIdentity:
    """Return immutable routing context identity for profile learning.

    This contract is intentionally outside ``Virus_Scan.models`` so the model
    layer consumes a public immutable context boundary instead of importing
    routing implementation internals or maintaining a duplicate model adapter.
    """
    return classify_engine_context(
        file_path,
        container_root=container_root,
        tags=tags,
        trusted_benign=trusted_benign,
        degraded=degraded,
        evidence_context=evidence_context,
        router_identity=router_identity,
    )


__all__ = ("profile_learning_context_identity",)
