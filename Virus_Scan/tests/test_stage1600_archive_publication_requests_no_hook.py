"""Stage1600: archive graph publication requests reject hookable edge inputs."""
from __future__ import annotations

from Virus_Scan.scanners.archives.publication_requests import (
    append_archive_graph_publication_request_tags,
    archive_graph_publication_edges,
)


class HostileArchiveGraphValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __iter__")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __str__")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __repr__")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __float__")

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __int__")


class HostileArchiveGraphText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __str__")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __repr__")


class HostileArchiveMemberTags:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __iter__")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __len__")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not call __repr__")


def test_stage1600_archive_edges_reject_hookable_edge_values_without_hooks():
    HostileArchiveGraphValue.touched = 0
    hostile = HostileArchiveGraphValue()

    edges = archive_graph_publication_edges(edge_requests=((hostile, hostile, hostile, hostile),))

    assert HostileArchiveGraphValue.touched == 0
    assert len(edges) == 1
    src, dst, edge_type, weight = edges[0]
    assert src.startswith("unsafe_archive_graph_source_rejected:")
    assert dst.startswith("unsafe_archive_graph_destination_rejected:")
    assert edge_type.startswith("unsafe_archive_graph_edge_type_rejected:")
    assert weight == 1.0


def test_stage1600_archive_edges_reject_hookable_edge_request_iterable_without_iterating():
    HostileArchiveGraphValue.touched = 0
    hostile = HostileArchiveGraphValue()

    edges = archive_graph_publication_edges(edge_requests=hostile)

    assert HostileArchiveGraphValue.touched == 0
    assert edges == (("archive_graph_edge_requests_rejected", "HostileArchiveGraphValue", "archive_graph_input_rejected", 0.0),)


def test_stage1600_archive_request_tags_reject_hookable_text_and_member_tags_without_hooks():
    HostileArchiveGraphText.touched = 0
    HostileArchiveMemberTags.touched = 0
    parent = HostileArchiveGraphText()
    member = HostileArchiveGraphText()
    extracted = HostileArchiveGraphText()
    member_tags = HostileArchiveMemberTags()
    tags: list[str] = []

    edges = append_archive_graph_publication_request_tags(
        tags,
        parent_path=parent,
        edge_requests=(("parent.zip", "payload.py", "archive_member", "2.5"),),
        member_name=member,
        extracted_path=extracted,
        member_tags=member_tags,
    )

    assert HostileArchiveGraphText.touched == 0
    assert HostileArchiveMemberTags.touched == 0
    assert edges == (("parent.zip", "payload.py", "archive_member", 2.5),)
    assert any(tag.startswith("archive_graph_publication_parent:unsafe_archive_publication_text_rejected:") for tag in tags)
    assert "archive_graph_publication_member_name_rejected:unsafe_archive_graph_member_name_rejected" in tags
    assert "archive_graph_publication_extracted_path_rejected:unsafe_archive_graph_extracted_path_rejected" in tags
    assert "unsafe_archive_member_tags_rejected:HostileArchiveMemberTags" in tags
