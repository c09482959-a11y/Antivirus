from __future__ import annotations

from pathlib import Path

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.scanners.archives.rpa import scan_rpa_file
from Virus_Scan.scanners.image import scan_image_file
from Virus_Scan.scanners.pickle.embedded_payloads import pickle_embedded_payload_tags


class _BadPayload:
    def __bool__(self) -> bool:
        return True

    def __getitem__(self, _item):
        raise ValueError("synthetic payload slice failure")


def test_rpa_pickle_failure_tags_make_rpa_scan_degraded_and_json_visible(tmp_path: Path) -> None:
    rpa_path = tmp_path / "corrupt.rpa"
    rpa_path.write_bytes(b"RPA-3.0 00000020 00000000\nnot-a-valid-rpa-index")

    tags, suspicious = scan_rpa_file(str(rpa_path))

    assert suspicious is True
    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags
    assert any(tag.startswith("scanner_failure_evidence:") for tag in tags)


def test_pickle_embedded_payload_recoverable_failure_emits_evidence_tags() -> None:
    tags = pickle_embedded_payload_tags(_BadPayload(), path="broken.rpa")

    assert "scanner_failure" in tags
    assert "scanner_degraded" in tags
    assert "pickle_failure_evidence_recorded" in tags
    assert "pickle_final_json_must_record" in tags
    assert "scanner_failure_evidence:pickle:embedded_payload_decode" in tags


def test_malformed_image_fast_triage_is_not_returned_as_clean(tmp_path: Path) -> None:
    image_path = tmp_path / "bad.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\nnot-valid-image-data")

    tags, suspicious = scan_image_file(str(image_path), artifact_read_snapshot=artifact_read_snapshot_fixture(image_path))

    assert suspicious is True
    assert "image_decode_failed" in tags
    assert "malformed_image_input" in tags
    assert "image_final_json_must_record" in tags
    assert "image_fast_triage_clean" not in tags
    assert any(tag.startswith("scanner_failure_evidence:image:") for tag in tags)
