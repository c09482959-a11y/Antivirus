from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.detection.enrichment.full_analysis.input_stage import prepare_analysis_inputs
from Virus_Scan.routing.artifact_platform import (
    artifact_platform_from_router_identity,
    artifact_platform_from_static_text,
    canonical_artifact_platform,
)


def test_phase13_artifact_platform_uses_canonical_magic_and_static_evidence(tmp_path):
    pe = tmp_path / "sample.fixture"
    pe.write_bytes(b"MZ" + b"\x00" * 128)

    assert artifact_platform_from_router_identity({"magic_type": "pe_mz"}) == "windows"
    assert artifact_platform_from_router_identity({"magic_type": "elf"}) == "linux"
    assert artifact_platform_from_router_identity({"magic_type": "macho"}) == "macos"
    assert artifact_platform_from_static_text("WriteProcessMemory VirtualAllocEx") == "windows"
    assert canonical_artifact_platform(pe, strings_blob="") == "windows"


def test_phase13_artifact_platform_conflicts_fail_closed(tmp_path):
    sample = tmp_path / "mixed.txt"
    sample.write_text("PowerShell /bin/bash", encoding="utf-8")

    assert artifact_platform_from_static_text(sample.read_text()) == ""
    assert canonical_artifact_platform(
        sample,
        router_identity={"magic_type": "pe_mz"},
        strings_blob="/bin/bash",
    ) == ""


def test_phase13_normalized_inputs_publish_explicit_platform_for_windows_static_artifacts(tmp_path):
    ps1 = tmp_path / "fixture.txt"
    ps1.write_text("PowerShell -EncodedCommand AAA FromBase64String", encoding="utf-8")

    facts = prepare_analysis_inputs(
        str(ps1),
        artifact_read_snapshot=artifact_read_snapshot_fixture(ps1),
        attack_repository_digest=scan_session_snapshot_fixture().cache_execution_identity.attack_repository_digest,
    )

    assert facts.artifact_platform == "windows"
    assert {record.platform for record in facts.tag_evidence.records if record.platform} == {"windows"}
