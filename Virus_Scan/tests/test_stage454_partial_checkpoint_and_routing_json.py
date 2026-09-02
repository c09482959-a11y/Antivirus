import json
from pathlib import Path

from Virus_Scan.publication.json_writer import finalize_scan_results, write_partial_scan_results


def _record(path: str) -> dict:
    return {
        "file": path,
        "path": path,
        "node": path,
        "score": 0.0,
        "classification": "LOW",
        "class": "LOW",
        "tags": ["image_fast_triage_clean"],
        "routing_evidence": {
            "detected_engine": "media",
            "container_engine": "media",
            "artifact_engine": "media",
            "effective_analysis_engine": "media",
            "declared_extension": ".png",
            "sniffed_file_type": "png",
            "engine_baseline_key": "media::media::.png::png",
            "extension_baseline_key": "media/.png",
            "extension_mismatch": False,
            "cross_engine_artifact": False,
            "learning_allowed": False,
        },
    }


def test_final_json_preserves_canonical_routing_evidence(tmp_path: Path):
    output = tmp_path / "scan_results.json"
    sample = str(tmp_path / "main_menu.png")

    assert finalize_scan_results(str(output), {sample: _record(sample)})

    data = json.loads(output.read_text(encoding="utf-8"))
    compact = data[sample]
    assert compact["routing_evidence"]["container_engine"] == "media"
    assert compact["routing_evidence"]["artifact_engine"] == "media"
    assert compact["routing_evidence"]["declared_extension"] == ".png"


def test_partial_checkpoint_remains_valid_json_for_large_media_batches(tmp_path: Path):
    output = tmp_path / "scan_results.json.partial"
    records = {str(tmp_path / f"main_menu_{i}.png"): _record(str(tmp_path / f"main_menu_{i}.png")) for i in range(250)}

    assert write_partial_scan_results(str(output), records)

    data = json.loads(output.read_text(encoding="utf-8"))
    assert len(data) == 250
    assert all(record.get("routing_evidence") for record in data.values())
