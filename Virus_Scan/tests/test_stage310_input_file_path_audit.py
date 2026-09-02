from Virus_Scan.publication.json_writer import compact_result_record


def test_compact_record_persists_input_file_path_from_file_identity():
    compact = compact_result_record(
        {
            "file": "/samples/media/mislabel.bin",
            "path": "/samples/media/mislabel.bin",
            "score": 78,
            "classification": "MALICIOUS",
            "tags": ["magic_png", "embedded_command"],
            "detected_engine": "media",
            "scheduler_mode": "serial",
            "scan_duration_seconds": 0.25,
        }
    )

    assert compact["input_file_path"] == "/samples/media/mislabel.bin"
    assert compact["file"] == "/samples/media/mislabel.bin"
    assert compact["path"] == "/samples/media/mislabel.bin"
    assert compact["detected_engine"] == "media"


def test_compact_record_persists_input_file_path_from_node_only_records():
    compact = compact_result_record(
        {
            "node": "/samples/archive/inner.ps1",
            "score": 62,
            "classification": "HIGH",
            "tags": ["archive", "download_execute_chain"],
        }
    )

    assert compact["input_file_path"] == "/samples/archive/inner.ps1"
    assert compact["file"] == "/samples/archive/inner.ps1"
    assert compact["path"] == "/samples/archive/inner.ps1"
