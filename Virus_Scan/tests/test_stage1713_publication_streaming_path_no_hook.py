from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.publication.json_finalization.stream_file_io import finalizer_tmp_path
from Virus_Scan.publication.json_finalization.streaming import stream_json_mapping


class HostileOutputPath:
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("output path fspath hook executed")

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("output path str hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("output path repr hook executed")


def test_stage1713_stream_json_mapping_rejects_hostile_path_without_hooks() -> None:
    HostileOutputPath.touched = 0

    with pytest.raises(TypeError) as excinfo:
        stream_json_mapping(HostileOutputPath(), {"sample": {"classification": "clean"}}, fsync_file=False)

    assert HostileOutputPath.touched == 0
    assert "unsupported_final_json_output_path:HostileOutputPath" in str(excinfo.value)


def test_stage1713_finalizer_tmp_path_accepts_owned_pathlib_path(tmp_path: Path) -> None:
    output = tmp_path / "scan_results.json"
    temp_path = finalizer_tmp_path(output)

    assert Path(temp_path).parent == tmp_path
    assert Path(temp_path).name.startswith("scan_results.json.")
    Path(temp_path).unlink()
