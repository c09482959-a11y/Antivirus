from Virus_Scan.detection.evidence.indicators.contextual_identity import contextual_identity_reporting_tags
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_context_identity_fields_become_detection_tags():
    record = {
        "container_engine": "renpy",
        "artifact_engine": "unity",
        "declared_extension": ".dll",
        "sniffed_type": "dotnet_assembly",
        "sniffed_embedded_types": [],
        "cross_engine_artifact": True,
        "engine_mismatch": True,
        "extension_mismatch": False,
        "effective_analysis_engine": "unity_dotnet",
        "learning_allowed": False,
        "learning_reason": "engine_mismatch_cross_engine_artifact",
    }
    tags = set(contextual_identity_reporting_tags(record))
    assert "cross_engine_artifact" in tags
    assert "engine_mismatch" in tags
    assert "cross_engine_renpy_contains_unity" in tags
    assert "unity_dotnet" in tags
    assert "contextual_learning_blocked" in tags


def test_embedded_payload_context_gets_chain_visibility():
    record = {
        "container_engine": "rpgm",
        "artifact_engine": "media",
        "declared_extension": ".png",
        "sniffed_type": "png",
        "sniffed_embedded_types": ["pe"],
        "cross_engine_artifact": False,
        "engine_mismatch": False,
        "extension_mismatch": False,
        "effective_analysis_engine": "embedded_pe_payload",
        "learning_allowed": False,
        "learning_reason": "embedded_payload_learning_blocked",
    }
    tags = contextual_identity_reporting_tags(record)
    assert "polyglot_artifact" in tags
    assert "embedded_pe_payload" in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(tags)), match_modes=("anchor", "unordered"))
    assert "contextual:embedded_payload_artifact_chain" in evidence.hits


def test_extension_mismatch_context_gets_learning_block_chain():
    tags = contextual_identity_reporting_tags(
        {
            "container_engine": "other",
            "artifact_engine": "unity",
            "declared_extension": ".dat",
            "sniffed_type": "dotnet_assembly",
            "sniffed_embedded_types": [],
            "cross_engine_artifact": False,
            "engine_mismatch": False,
            "extension_mismatch": True,
            "effective_analysis_engine": "unity_dotnet",
            "learning_allowed": False,
            "learning_reason": "extension_mismatch_learning_blocked",
        }
    )
    assert "declared_dat_sniffs_as_dotnet_assembly" in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(tags)), match_modes=("anchor", "unordered"))
    assert "contextual:learning_blocked_mismatch_chain" in evidence.hits
