from __future__ import annotations

import json

from Virus_Scan.publication.json_finalization.base_projection import bounded_dict
from Virus_Scan.publication.json_finalization.streaming import finalize_scan_results


def test_stage1715_bounded_dict_none_is_explicit_unavailable_mapping_evidence() -> None:
    projected = bounded_dict(None)

    assert projected == {
        "_unavailable_mapping": {
            "model_signal_projection_failed": True,
            "reason": "final_json_mapping_unavailable",
        }
    }
    assert bounded_dict({}) == {}
    json.dumps(projected, sort_keys=True)


def test_stage1715_final_json_missing_mapping_fields_publish_failure_evidence(tmp_path) -> None:
    output_path = tmp_path / "scan_results.json"
    results = {
        "sample.bin": {
            "file": "sample.bin",
            "classification": "clean",
            "score": 0.0,
            "tags": [],
        }
    }

    assert finalize_scan_results(str(output_path), results) is True
    published = json.loads(output_path.read_text(encoding="utf-8"))["sample.bin"]

    for field_name in ("profile_selection", "attack_intelligence", "heuristics"):
        unavailable = published[field_name]["_unavailable_mapping"]
        assert unavailable["model_signal_projection_failed"] is True
        assert unavailable["reason"] == "final_json_mapping_unavailable"

    json.dumps(published, sort_keys=True)
