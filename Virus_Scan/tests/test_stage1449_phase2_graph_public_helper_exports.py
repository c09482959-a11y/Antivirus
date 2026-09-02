import Virus_Scan.models.graph as graph
import Virus_Scan.models.graph.relationships as relationships
import Virus_Scan.models.graph.chains as chains


def test_stage1449_graph_root_exports_public_helper_names_not_private_aliases() -> None:
    assert "phase_matches_from_tags" in graph.__all__
    assert "phase_hits_from_tags" in graph.__all__
    assert "score_attack_chain_presence_from_edges" in graph.__all__
    assert "_phase_matches_from_tags" not in graph.__all__
    assert "_phase_hits_from_tags" not in graph.__all__
    assert "_score_attack_chain_presence_from_edges" not in graph.__all__
    assert not hasattr(graph, "_phase_matches_from_tags")
    assert not hasattr(graph, "_phase_hits_from_tags")
    assert not hasattr(graph, "_score_attack_chain_presence_from_edges")


def test_stage1449_graph_owner_modules_export_public_helper_names() -> None:
    assert "phase_matches_from_tags" in relationships.__all__
    assert "phase_hits_from_tags" in relationships.__all__
    assert "score_attack_chain_presence_from_edges" in chains.__all__
    assert "_phase_matches_from_tags" not in relationships.__all__
    assert "_phase_hits_from_tags" not in relationships.__all__
    assert "_score_attack_chain_presence_from_edges" not in chains.__all__


def test_stage1449_graph_public_helpers_preserve_behavior() -> None:
    matches = graph.phase_matches_from_tags({"network", "file_write"})
    assert isinstance(matches, dict)
    assert graph.phase_hits_from_tags({"network", "file_write"}) == sorted(matches.keys())
    assert graph.score_attack_chain_presence_from_edges([("execution", "network")]) >= 0.0
