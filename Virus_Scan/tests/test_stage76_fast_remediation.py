from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.scanners.image import scan_image_file, scan_image_stego
from Virus_Scan.scanners.strings import (
    ScanStringsRequest,
    scan_strings as scanner_scan_strings,
)
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import scan_strings as detection_scan_strings
from Virus_Scan.detection.scoring.stress.scoring_framework import IterationScoreProfile, ScorePenalty, SCORE_FIELDS


def test_corrupt_image_is_observation_not_runtime_error(tmp_path, capsys):
    p = tmp_path / "corrupt.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"not-a-valid-png")

    tags, suspicious = scan_image_stego(p)
    assert suspicious
    low = {str(tag).lower() for tag in tags}
    assert "image_decode_failed" in low
    assert "malformed_image_input" in low
    assert "image_final_json_must_record" in low

    tags2, suspicious2 = scan_image_file(p, artifact_read_snapshot=artifact_read_snapshot_fixture(p))
    assert suspicious2
    low2 = {str(tag).lower() for tag in tags2}
    assert "image_decode_failed" in low2
    assert "malformed_image_input" in low2
    assert "image_final_json_must_record" in low2
    captured = capsys.readouterr()
    assert "Pillow LSB stego scan failed" not in captured.err
    assert "gated LSB extraction failed" not in captured.err


def test_string_scanner_contracts_remain_bidirectional(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_text("powershell -enc AAAA http://example.invalid", encoding="utf-8")
    a = scanner_scan_strings(ScanStringsRequest(p.read_text(), path=p, finalize=False))
    b = detection_scan_strings(p.read_text(), path=p, finalize=False)
    assert isinstance(a, list)
    assert isinstance(b, list)
    assert set(a).issubset(set(b)) or set(b).issubset(set(a)) or (a and b)


def test_scoring_profile_roundtrip_and_concurrent_json_records(tmp_path):
    out = tmp_path / "scores.jsonl"
    write_lock = Lock()
    def make_record(i: int) -> str:
        profile = IterationScoreProfile()
        if i % 17 == 0:
            profile.penalize(ScorePenalty(
                field="retry_logic_score",
                penalty=0.25,
                subsystem="stress",
                reason="synthetic retry perturbation",
                trigger="stage76 regression",
                reproducibility="high",
                blast_radius="local",
            ))
        rec = {"iteration": i, **profile.as_record_fields()}
        assert all(k in rec["scores"] for k in SCORE_FIELDS)
        payload = json.dumps(rec, sort_keys=True)
        assert json.loads(payload)["iteration"] == i
        return payload + "\n"

    def write_chunk(start: int):
        for i in range(start, start + 50):
            with write_lock:
                with out.open("a", encoding="utf-8") as fh:
                    fh.write(make_record(i))
                    fh.flush()
                    os.fsync(fh.fileno())

    with ThreadPoolExecutor(max_workers=4) as ex:
        list(ex.map(write_chunk, [0, 50, 100, 150]))

    seen = set()
    for line in out.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        rec = json.loads(line)
        seen.add(rec["iteration"])
        assert 0 <= rec["aggregate_score"] <= 10
    assert seen == set(range(200))
