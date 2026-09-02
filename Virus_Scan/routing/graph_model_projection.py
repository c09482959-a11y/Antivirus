"""Routing-owned graph model projection boundary.

Routing decides which scan path branch needs graph-derived tags or archive
member relationship evidence. The graph model remains the canonical owner of
C# graph extraction and archive-member graph mutation; this module is the
single routing call surface so extension routers do not import graph model
internals directly.
"""
from __future__ import annotations


from Virus_Scan.models.api.graph_contracts import (
    link_archive_members_to_graph,
    scan_cs,
)


def route_archive_members_to_graph(path: object, *, max_members: int = 500) -> int:
    """Project archive-member graph linking through the routing boundary."""
    return link_archive_members_to_graph(path, max_members=max_members)


def route_cs_graph_tags(path: object) -> list[str]:
    """Project graph-owned C# source tags through the routing boundary."""
    return scan_cs(path)


__all__ = ("route_archive_members_to_graph", "route_cs_graph_tags")
