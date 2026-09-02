from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.contracts.graph_publication import api_graph_publication_edges



class HostileText:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned text hook was invoked")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("caller-owned format hook was invoked")


def test_stage2023_graph_publication_rejection_tokens_are_no_hook() -> None:
    HostileText.touched = 0

    edges = api_graph_publication_edges(HostileText(), (HostileText(),), (HostileText(),), {HostileText(): (HostileText(),)})

    assert edges
    assert all("HostileText" in edge[0] or "HostileText" in edge[1] for edge in edges)
    assert HostileText.touched == 0


def test_stage2023_graph_publication_source_removed_backlog_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/contracts/graph_publication.py"))

    forbidden = (
        'return f"{reason}:{no_hook_type_name(value)}"',
        'f"api:{_graph_publication_text(api)}"',
        'f"api_tag:{_graph_publication_text(tag)}"',
        'f"api:{source_text}"',
        'f"api:{_graph_publication_text(target)}"',
        "_MAPPING_PROXY_TYPE",
    )
    for snippet in forbidden:
        assert snippet not in source
