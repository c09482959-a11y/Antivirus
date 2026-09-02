
"""Stage 1399: continue model public API and graph/replay evidence hardening."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


from pathlib import Path

from Virus_Scan.models.api import graph_contracts, replay_comparison_contracts
from Virus_Scan.models.api.replay_comparison_contracts import materialize_model_evidence_comparison


def test_stage1399_scan_cs_entropy_is_real_model_signal_not_dead_zero_stub(tmp_path: Path) -> None:
    sample = tmp_path / "high_entropy.cs"
    sample.write_bytes(bytes(range(256)) * 32)

    tags = tuple(graph_contracts.scan_cs(sample))

    assert "high_entropy_code" in tags
    assert tags == tuple(sorted(tags))


def test_stage1399_scan_cs_source_no_longer_has_zero_entropy_placeholder() -> None:
    source = read_python_file(Path("Virus_Scan/models/graph/scan.py"))

    assert "    e = 0.0\n" not in source
    assert "shannon_entropy_bytes(raw_source)" in source
    assert "tags.add('medium_entropy_code')\n        tags.add('medium_entropy_code')" not in source


def test_stage1399_replay_comparison_preserves_non_mapping_expected_and_actual_evidence() -> None:
    comparison = replay_comparison_contracts.compare_model_evidence(
        model_name="temporal",
        expected=None,
        actual=None,
    )

    materialized = materialize_model_evidence_comparison(comparison)

    assert materialized["matched"] is False
    assert materialized["mismatch_fields"] == ("actual", "expected")
    assert materialized["expected"] == {}
    assert materialized["actual"] == {}
    assert materialized["expected_unavailable_reason"] == "non_mapping_replay_expected"
    assert materialized["actual_unavailable_reason"] == "non_mapping_replay_actual"
