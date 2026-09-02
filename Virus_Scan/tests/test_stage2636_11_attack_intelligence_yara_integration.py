"""Stage2636.11 integrity-bearing YARA execution-path regressions."""
from __future__ import annotations

from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture

from pathlib import Path
from types import SimpleNamespace

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.yara_hits import (
    YaraScanResult, normalize_yara_hits, normalize_yara_rule_name,
)
from Virus_Scan.detection.chains.composite.threat_intel import compute_threat_intel_layer
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.enrichment.full_analysis.input_stage import prepare_analysis_inputs
from Virus_Scan.detection.orchestration.full_analysis.pipeline_execution import (
    build_full_analysis_context,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    normalize_tag_evidence,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.tests.support.canonical_yara_fixtures import (
    canonical_test_yara_result,
    family_alignment,
)


class _HostileTruthValue:
    bool_calls = 0

    def __bool__(self) -> bool:
        type(self).bool_calls += 1
        raise AssertionError("caller-owned truth hook executed")


def test_stage2636_11_canonical_yara_identity_is_normalized_without_hooks() -> None:
    result = canonical_test_yara_result()
    record = result.hits[0]
    assert normalize_yara_rule_name(record) == "stage2636_exfiltration"
    assert normalize_yara_hits(result) == ["stage2636_exfiltration"]


def test_stage2636_11_input_stage_preserves_public_identity_and_integrity_evidence(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"")
    result = canonical_test_yara_result()
    facts = prepare_analysis_inputs(
        str(sample),
        yara_hits=result,
        strings_already_enriched=True,
        artifact_read_snapshot=artifact_read_snapshot_fixture(sample),
        attack_repository_digest=scan_session_snapshot_fixture().cache_execution_identity.attack_repository_digest,
    )
    assert facts.yara_hits == ("stage2636_exfiltration",)
    assert type(facts.yara_evidence) is YaraScanResult
    assert facts.yara_evidence == result

    tags = physical_tag_evidence(("collection", "http_upload"))
    baseline = compute_attack_intelligence(tags, ())
    corroborated = compute_attack_intelligence(
        tags,
        facts.yara_evidence,
        yara_family_alignments=(family_alignment(result.hits[0]),),
    )
    assert corroborated["yara_state"] == "verified"
    assert (
        corroborated["family_probabilities"]["exfiltration"]
        > baseline["family_probabilities"]["exfiltration"]
    )


def test_stage2636_11_full_analysis_context_receives_integrity_yara_evidence() -> None:
    captured: dict[str, object] = {}

    def build_detection_api_context(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return dict(kwargs)

    deps = SimpleNamespace(
        build_detection_api_context=build_detection_api_context,
        api_graph_enricher=None,
        model_context_builder=None,
        family_heuristics_builder=None,
    )
    inputs = SimpleNamespace(
        strings_blob="",
        strings_already_enriched=True,
        curr_stage="unknown",
        failure_evidence=(),
    )
    evidence = canonical_test_yara_result()
    result = build_full_analysis_context(
        deps,
        "sample.bin",
        "sample.bin",
        normalize_tag_evidence(()),
        evidence,
        scan_session_snapshot_fixture(),
        static_program_analyses=(),
        inputs=inputs,
        prev_stage=None,
    )
    assert "yara_hits" not in captured
    assert captured["yara_evidence"] is evidence
    assert captured["static_program_analyses"] == ()
    assert "yara_hits" not in result
    assert result["yara_evidence"] is evidence


def test_stage2636_11_composite_preserves_verified_yara_and_rejects_truth_hooks() -> None:
    tags = physical_tag_evidence(("collection", "http_upload"))
    chain_evidence = ChainEvidence("stage2636_11_empty", "empty-digest")
    evidence = canonical_test_yara_result()
    layer = compute_threat_intel_layer(tags, chain_evidence, evidence)
    assert layer["attack"]["yara_state"] == "verified"
    # The production family registry is intentionally empty; verified physical
    # evidence cannot invent a family interpretation.
    assert layer["attack"]["family_probabilities"]["exfiltration"] < 1.0

    _HostileTruthValue.bool_calls = 0
    rejected = compute_threat_intel_layer(tags, chain_evidence, _HostileTruthValue())
    assert _HostileTruthValue.bool_calls == 0
    assert rejected["attack"]["yara_state"] == "yara_input_rejected"

    source = Path(
        "Virus_Scan/detection/chains/composite/threat_intel.py"
    ).read_text(encoding="utf-8")
    assert "normalize_yara_hits" not in source
    assert "yara_hits or []" not in source
