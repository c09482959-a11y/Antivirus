from base64 import b64decode

from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.runtime.progress import clear_progress_callback, set_progress_callback
from Virus_Scan.runtime.scan_dependencies import report_scan_stage_progress
from Virus_Scan.scanners.image import scan_image_file


def test_runtime_stage_progress_uses_context_owned_callback():
    events = []

    def callback(stage, inc, bytes_delta):
        events.append((stage, inc, bytes_delta))
        return True

    set_progress_callback(callback)
    try:
        report_scan_stage_progress("unit_stage", inc=3, bytes_delta=7)
    finally:
        clear_progress_callback()

    assert events == [("unit_stage", 3, 7)]


def test_image_scanner_emits_progress_checkpoints(tmp_path):
    png = tmp_path / "tiny.png"
    png.write_bytes(b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="))
    stages = []

    def callback(stage, inc, bytes_delta):
        stages.append(stage)
        return True

    set_progress_callback(callback)
    try:
        tags, suspicious = scan_image_file(str(png), artifact_read_snapshot=artifact_read_snapshot_fixture(png))
    finally:
        clear_progress_callback()

    assert "image_scan_start" in stages
    assert any(stage.startswith("image_") for stage in stages)
    assert isinstance(tags, list)
    assert isinstance(suspicious, bool)
