from __future__ import annotations

from Virus_Scan.contracts.graph_publication import api_graph_publication_edges
from Virus_Scan.detection.tags.process.api_tags import infer_tags_from_api


def test_detection_api_reporting_projection_is_stable_for_unordered_inputs() -> None:
    calls = ("CreateProcess", "InternetOpenUrl", "ReadFile")

    first = infer_tags_from_api(calls, {"credential_access", "network_activity"})
    second = infer_tags_from_api(calls, {"network_activity", "credential_access"})

    assert first == second
    assert first == sorted(first)


def test_api_graph_publication_is_stable_after_tag_input_reordering() -> None:
    calls = ("OpenProcess", "WriteProcessMemory", "CreateRemoteThread")
    first_tags = infer_tags_from_api(calls, {"file_seen", "filetype_text"})
    second_tags = infer_tags_from_api(calls, {"filetype_text", "file_seen"})

    first_edges = api_graph_publication_edges("sample", calls, first_tags, {})
    second_edges = api_graph_publication_edges("sample", calls, second_tags, {})

    assert first_tags == second_tags
    assert first_edges == second_edges
