"""Phase 37 inert cross-platform static-semantic corpus/oracle acceptance gates."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.scanners.static_program_analysis import (
    analyze_dotnet_il_snapshot,
    analyze_native_elf_x86_64_snapshot,
    analyze_python_renpy_snapshot,
)
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.stress.attack_synthetic_safety import validate_inert_artifact
from Virus_Scan.stress.static_semantic_binary_fixtures import (
    render_static_semantic_binary_fixture,
)
from Virus_Scan.stress.static_semantic_corpus import (
    STATIC_SEMANTIC_GENERATION_POLICY_DIGEST,
    build_static_semantic_corpus,
    materialize_static_semantic_corpus,
)
from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_safety import validate_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import (
    STATIC_SEMANTIC_PARTITION_SCHEDULE,
    CorpusGenerationRecord,
)
from Virus_Scan.stress.static_semantic_templates import STATIC_SEMANTIC_FIXTURES
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture

_REPOSITORY_DIGEST = "a" * 64
_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_BY_ID = {item.generation_intent.generation_id: item for item in STATIC_SEMANTIC_FIXTURES}


@contextmanager
def _isolated_runtime(tmp_path: Path):
    previous = os.environ.get("UMIGE_BASE_DIR")
    sqlite_lifecycle().close()
    runtime_root = tmp_path / "runtime"
    os.environ["UMIGE_BASE_DIR"] = str(runtime_root)
    try:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=True)
        yield runtime_root
    finally:
        scan_cache_repository().configure(runtime_root / "profiles", enabled=False)
        sqlite_lifecycle().close()
        if previous is None:
            os.environ.pop("UMIGE_BASE_DIR", None)
        else:
            os.environ["UMIGE_BASE_DIR"] = previous


def _generation(generation_id: str, partition_index: int = 0) -> CorpusGenerationRecord:
    partition, collected_at, seed = STATIC_SEMANTIC_PARTITION_SCHEDULE[partition_index]
    return CorpusGenerationRecord(
        sample_id=f"phase37-{partition}-{generation_id}",
        partition=partition,
        partition_seed=seed,
        collected_at=collected_at,
        fixture_definition=_FIXTURE_BY_ID[generation_id],
    )


def _analysis(path: Path, scanner_id: str):
    snapshot = build_artifact_read_snapshot(path)
    if scanner_id == "dotnet_il_static_analysis":
        return analyze_dotnet_il_snapshot(snapshot).analysis
    if scanner_id == "native_elf_x86_64_static_analysis":
        return analyze_native_elf_x86_64_snapshot(snapshot).analysis
    if scanner_id == "python_renpy_static_analysis":
        return analyze_python_renpy_snapshot(snapshot).analysis
    raise AssertionError(scanner_id)


def test_phase37_reviewed_generation_intent_matches_packaged_technique_scope() -> None:
    by_id = {
        item.generation_intent.generation_id: item.generation_intent
        for item in STATIC_SEMANTIC_FIXTURES
    }
    for generation_id in (
        "python_credential_flow",
        "python_called_alias_flow",
        "python_conditional_upload",
        "javascript_file_upload",
        "batch_file_upload",
        "shell_file_upload",
        "nested_archive_python_flow",
        "dotnet_managed_file_network_flow",
        "python_dynamic_eval",
        "malformed_python",
        "unsupported_ruby_upload",
    ):
        assert "T1003" not in by_id[generation_id].desired_technique_ids
        assert "T1105" not in by_id[generation_id].desired_technique_ids

    assert by_id["python_process_injection_sequence"].desired_technique_ids == ("T1055",)
    assert by_id["powershell_credential_flow"].desired_technique_ids == ()
    assert by_id["renpy_process_launch"].desired_technique_ids == ("T1059.001",)
    renderer = _FIXTURE_BY_ID["renpy_process_launch"].renderer_specification
    assert "-EncodedCommand" in renderer.source_text


def test_phase37_split_contracts_bind_renderer_inputs_without_label_authority() -> None:
    assert len(STATIC_SEMANTIC_FIXTURES) == 24
    intents = tuple(item.generation_intent for item in STATIC_SEMANTIC_FIXTURES)
    renderers = tuple(item.renderer_specification for item in STATIC_SEMANTIC_FIXTURES)
    assert sum(item.malware_class == "malware" for item in intents) == 12
    assert sum(item.malware_class == "control" for item in intents) == 12
    assert sum(item.renderer_kind == "managed_pe" for item in renderers) == 2
    assert sum(item.renderer_kind == "native_elf_x86_64" for item in renderers) == 2
    assert sum("decode" in item.desired_operation_kinds for item in intents) >= 1
    assert {"dotnet_il", "native_x86_64"}.issubset({item.language for item in renderers})

    for generation_id in (
        "nested_archive_python_flow",
        "nested_archive_javascript_documentation",
    ):
        intent = _FIXTURE_BY_ID[generation_id].generation_intent
        assert intent.desired_parser_status == "unavailable"
        assert intent.unresolved_states == (
            "archive_member_ir_not_published_at_container_boundary",
        )
    assert _FIXTURE_BY_ID["nested_archive_python_flow"].generation_intent.desired_operation_kinds
    assert _FIXTURE_BY_ID["nested_archive_python_flow"].generation_intent.desired_flow

    fixture = _FIXTURE_BY_ID["dotnet_managed_file_network_flow"]
    renderer = fixture.renderer_specification
    hidden_record = fixture.to_hidden_record()
    assert hidden_record["renderer_specification"]["extension"] == ".exe"
    assert hidden_record["renderer_specification"]["member_extension"] == ""
    assert hidden_record["renderer_specification"]["source_text"] == renderer.source_text
    assert hidden_record["renderer_specification"]["fixture_variant"] == "managed_behavior"

    changed_source = replace(renderer, source_text=renderer.source_text + "reviewed-marker\n")
    changed_extension = replace(renderer, extension=".dll")
    assert changed_source.to_record() != renderer.to_record()
    assert changed_extension.to_record() != renderer.to_record()
    assert not hasattr(renderer, "desired_technique_ids")
    assert not hasattr(renderer, "malware_class")
    assert len(STATIC_SEMANTIC_GENERATION_POLICY_DIGEST) == 64

def test_phase37_binary_safety_admits_only_exact_renderer_owned_fixtures() -> None:
    for generation_id in (
        "dotnet_managed_file_network_flow",
        "dotnet_managed_documentation_only",
        "native_elf_import_flow_positive",
        "native_elf_symbols_no_calls",
    ):
        generation = _generation(generation_id)
        payload = render_static_semantic_artifact(generation.sample_id, generation.fixture_definition.renderer_specification)
        exact = validate_static_semantic_artifact(
            generation.sample_id,
            payload,
            renderer_kind=generation.fixture_definition.renderer_specification.renderer_kind,
            fixture_variant=generation.fixture_definition.renderer_specification.fixture_variant,
        )
        assert exact.safe is True
        assert exact.reasons == ()
        assert validate_inert_artifact(generation.sample_id, payload).safe is False
        assert validate_static_semantic_artifact(generation.sample_id, payload).safe is False

        tampered = payload[:-1] + bytes((payload[-1] ^ 0x01,))
        rejected = validate_static_semantic_artifact(
            generation.sample_id,
            tampered,
            renderer_kind=generation.fixture_definition.renderer_specification.renderer_kind,
            fixture_variant=generation.fixture_definition.renderer_specification.fixture_variant,
        )
        assert rejected.safe is False
        assert "static_semantic_binary_fixture_identity_mismatch" in rejected.reasons

        wrong_identity = validate_static_semantic_artifact(
            generation.sample_id + "-wrong",
            payload,
            renderer_kind=generation.fixture_definition.renderer_specification.renderer_kind,
            fixture_variant=generation.fixture_definition.renderer_specification.fixture_variant,
        )
        assert wrong_identity.safe is False
        assert "static_semantic_binary_fixture_identity_mismatch" in wrong_identity.reasons


def test_phase37_binary_fixture_variants_are_content_distinct_and_semantically_bounded() -> None:
    variants = (
        ("managed_pe", "managed_behavior"),
        ("managed_pe", "managed_documentation_only"),
        ("native_elf_x86_64", "native_control_flow"),
        ("native_elf_x86_64", "native_return_control"),
        ("native_elf_x86_64", "import_flow_positive"),
        ("native_elf_x86_64", "symbols_no_calls"),
    )
    digests: set[str] = set()
    for renderer_kind, fixture_variant in variants:
        first = render_static_semantic_binary_fixture(
            renderer_kind, fixture_variant, "sample-a",
        )
        second = render_static_semantic_binary_fixture(
            renderer_kind, fixture_variant, "sample-b",
        )
        assert first != second
        assert b"UMIGE_STATIC_SEMANTIC:sample-a" in first
        assert b"UMIGE_STATIC_SEMANTIC:sample-b" in second
        digests.update((sha256(first).hexdigest(), sha256(second).hexdigest()))
        assert b"http://" not in first
        if b"https://" in first:
            assert b"https://example.invalid/" in first
        assert b"rm -rf /" not in first.lower()
        assert b"format c:" not in first.lower()
    assert len(digests) == len(variants) * 2

    native = render_static_semantic_binary_fixture(
        "native_elf_x86_64", "native_control_flow", "sample-native",
    )
    # The Phase-37 ELF carrier has no syscall instruction by construction.
    assert b"\x0f\x05" not in native[:0x180]


def test_phase37_raw_binary_and_decode_fixtures_use_existing_production_frontends(
    tmp_path: Path,
) -> None:
    root = tmp_path / "corpus"
    manifest = materialize_static_semantic_corpus(root, repository_digest=_REPOSITORY_DIGEST)
    selected_ids = {
        "dotnet_managed_file_network_flow": "dotnet_il_static_analysis",
        "dotnet_managed_documentation_only": "dotnet_il_static_analysis",
        "native_elf_import_flow_positive": "native_elf_x86_64_static_analysis",
        "native_elf_symbols_no_calls": "native_elf_x86_64_static_analysis",
        "python_conditional_upload": "python_renpy_static_analysis",
    }
    generation_payload = json.loads(
        (root / "static_semantic_generation_intent_manifest.json").read_text(encoding="utf-8")
    )
    template_by_sample = {
        record["sample_id"]: record["fixture_definition"]["generation_intent"]["generation_id"]
        for record in generation_payload["records"]
    }
    samples = {
        template_by_sample[sample.sample_id]: sample
        for sample in manifest.samples
        if sample.partition == "development"
        and template_by_sample[sample.sample_id] in selected_ids
    }
    assert set(samples) == set(selected_ids)

    with _isolated_runtime(tmp_path):
        for generation_id, expected_scanner in selected_ids.items():
            path = root / samples[generation_id].artifact_path
            outcome = scan_file_by_type(
                str(path),
                scan_session_snapshot=scan_session_snapshot_fixture(),
                artifact_read_snapshot=build_artifact_read_snapshot(path),
            )
            identity = route_identity_record(outcome.identity)
            assert identity is not None
            static_summary = identity["static_program_analysis"]
            assert static_summary["scanner_id"] == expected_scanner
            assert "oracle" not in repr(identity).casefold()

            analysis = _analysis(path, expected_scanner)
            assert analysis.parser_status == _FIXTURE_BY_ID[generation_id].generation_intent.desired_parser_status
            assert all(
                item.control_flow_provenance in {"static_control_flow", "syntactic_order"}
                for item in analysis.operations
            )
            observed = {item.operation_kind for item in analysis.operations}
            expected = set(_FIXTURE_BY_ID[generation_id].generation_intent.desired_operation_kinds)
            assert expected.issubset(observed)
            assert not (
                set(_FIXTURE_BY_ID[generation_id].generation_intent.forbidden_operation_kinds) & observed
            )

    decode_sample = samples["python_conditional_upload"]
    decode_analysis = _analysis(
        root / decode_sample.artifact_path,
        "python_renpy_static_analysis",
    )
    decode = next(item for item in decode_analysis.operations if item.operation_kind == "decode")
    network = next(item for item in decode_analysis.operations if item.operation_kind == "network_send")
    assert decode.reachability_state == "entrypoint_reachable"
    assert network.reachability_state == "conditionally_reachable"
    operation_kind = {item.operation_id: item.operation_kind for item in decode_analysis.operations}
    assert not any(
        edge.edge_kind == "source_to_sink"
        and operation_kind.get(edge.source_operation_id) == "decode"
        and operation_kind.get(edge.target_operation_id) == "network_send"
        for edge in decode_analysis.flow_edges
    )


def test_phase37_corpus_sidecars_prove_safety_traceability_and_group_isolation(tmp_path: Path) -> None:
    build = build_static_semantic_corpus(
        tmp_path / "artifacts",
        repository_digest=_REPOSITORY_DIGEST,
    )
    assert len(build.manifest.samples) == 96
    assert build.manifest.malware_sample_count == 48
    assert build.manifest.control_sample_count == 48
    assert len({sample.artifact_sha256 for sample in build.manifest.samples}) == 96
    assert all(
        count.malware_count == 12 and count.control_count == 12
        for count in build.manifest.partition_counts
    )
    sidecars = dict(build.sidecars)
    coverage = sidecars["static_semantic_coverage_report.json"]
    assert coverage["managed_pe_fixture_count"] == 2
    assert coverage["native_elf_fixture_count"] == 2
    assert coverage["bounded_decode_fixture_count"] == 1
    assert coverage["archive_fixture_count"] == 2
    assert sidecars["static_semantic_safety_report.json"]["safe_count"] == 96
    assert sidecars["static_semantic_safety_report.json"]["unsafe_count"] == 0
    assert sidecars["static_semantic_artifact_truth_validation.json"]["agreement_count"] == 96
    assert sidecars["static_semantic_artifact_truth_validation.json"]["disagreement_count"] == 0
    assert sidecars["static_semantic_leakage_report.json"]["violation_count"] == 0
    generation_by_sample = {
        record["sample_id"]: record
        for record in sidecars["static_semantic_generation_intent_manifest.json"]["records"]
    }
    for sample, (artifact_path, payload) in zip(
        build.manifest.samples, build.pending_artifacts, strict=True,
    ):
        generation_record = generation_by_sample[sample.sample_id]
        generation_id = generation_record["fixture_definition"]["generation_intent"]["generation_id"]
        lowered_path = artifact_path.as_posix().casefold()
        assert generation_id.casefold() not in lowered_path
        assert "/malware/" not in lowered_path and "/control/" not in lowered_path
        assert "malware" not in Path(sample.artifact_path).name.casefold()
        assert "control" not in Path(sample.artifact_path).name.casefold()
        assert b"generation_id=" not in payload
        assert b"malware_class=" not in payload
        assert b"partition=" not in payload
    assert coverage["runtime_occurrence_expected_count"] == 0


def test_phase37_superseded_test_fixture_owners_are_deleted_and_unreachable() -> None:
    old_paths = (
        _ROOT / "Virus_Scan/tests/support/dotnet_il_fixture.py",
        _ROOT / "Virus_Scan/tests/support/native_elf_x86_64_fixture.py",
    )
    assert all(not path.exists() for path in old_paths)
    forbidden_imports = (
        "Virus_Scan.tests.support.dotnet_il_fixture",
        "Virus_Scan.tests.support.native_elf_x86_64_fixture",
    )
    offenders: list[str] = []
    this_test = Path(__file__).resolve()
    for path in _ROOT.rglob("*.py"):
        if path.resolve() == this_test:
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        if any(token in text for token in forbidden_imports):
            offenders.append(path.relative_to(_ROOT).as_posix())
    assert offenders == []

    owner = (_ROOT / "Virus_Scan/stress/static_semantic_binary_fixtures.py").read_text(
        encoding="utf-8",
    )
    assert "Virus_Scan.scanners" not in owner
    assert "Virus_Scan.routing" not in owner
    assert "subprocess" not in owner
    assert "os.system" not in owner


def test_phase37_isolated_runtime_restores_scan_cache_policy(tmp_path: Path) -> None:
    assert scan_cache_repository().enabled() is False
    with _isolated_runtime(tmp_path):
        assert scan_cache_repository().enabled() is True
    assert scan_cache_repository().enabled() is False
