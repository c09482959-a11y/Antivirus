from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture
from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
from Virus_Scan.scheduler.api.runtime import estimate_stage_file_cost, weighted_stage_tokens
from Virus_Scan.scheduler.runtime import stage_budget


def test_stage1096_stage_budget_estimates_cost_from_path_when_no_cost_supplied(tmp_path):
    target = tmp_path / "asset.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 128)

    cost = estimate_stage_file_cost(str(target))
    tokens, stage = weighted_stage_tokens(path=str(target), stage_name=None, cost=None)

    assert cost["stage"] == "image"
    assert cost["weight"] >= 3
    assert stage == "image"
    assert tokens >= 1


def test_stage1096_stage_budget_has_no_disabled_private_cost_gate():
    source = Path(stage_budget.__file__).read_text(encoding="utf-8")
    assert ("path and " + "False") not in source
    assert "_umige_estimate_file_cost" not in source
    assert "estimate_stage_file_cost(path)" in source

from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.models import temporal
from Virus_Scan.core import jsonio


def test_stage1096_rpa_router_uses_public_rpa_scanner_after_dead_gate_removal(tmp_path):
    target = tmp_path / "scripts.rpa"
    target.write_bytes(b"RPA-3.0 00000010 00000000\nrenpy pickle python exec(")

    outcome = scan_file_by_type(
        str(target),
        scan_session_snapshot=scan_session_snapshot_fixture(),
        artifact_read_snapshot=artifact_read_snapshot_fixture(target),
    )

    assert outcome.suspicious is True
    assert "rpa_archive" in outcome.tags
    assert any(str(tag).startswith("scanner_failure_evidence:archive") for tag in outcome.tags)


def test_stage1096_core_temporal_routing_dead_gates_removed():
    for module in (jsonio, temporal):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert (" and " + "False") not in source
        assert (" or " + "True") not in source
    routing_source = Path(scan_file_by_type.__code__.co_filename).read_text(encoding="utf-8")
    assert ("renpy_rpa') and " + "False") not in routing_source
    assert "scan_rpa_file(path)" in routing_source
