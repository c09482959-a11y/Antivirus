from pathlib import Path, PurePosixPath

import pytest

from Virus_Scan.publication.json_finalization.partial_results import (
    PARTIAL_RECOVERY_EVIDENCE_KEY,
    recover_results_from_partial,
)
from Virus_Scan.publication.json_finalization.projection_text import (
    safe_projection_path_text,
)
from Virus_Scan.publication.json_finalization.stream_file_io import finalizer_tmp_path
from Virus_Scan.publication.json_finalization.streaming import (
    stream_json_mapping,
)


class HostilePublicationPath(PurePosixPath):
    __module__ = "pathlib"
    touched = 0

    def as_posix(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call as_posix")

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __fspath__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call fspath")


def test_stage1752_publication_path_boundary_rejects_path_subclass_without_hooks() -> None:
    HostilePublicationPath.touched = 0
    value = HostilePublicationPath("/tmp/hostile.json")

    assert safe_projection_path_text(value) == ("", "unsupported_final_json_path")
    assert HostilePublicationPath.touched == 0


def test_stage1752_streaming_rejects_path_subclass_without_hooks() -> None:
    HostilePublicationPath.touched = 0
    value = HostilePublicationPath("/tmp/hostile.json")

    with pytest.raises(TypeError, match="unsupported_final_json_output_path"):
        stream_json_mapping(value, {"sample": {"classification": "clean"}}, fsync_file=False)
    with pytest.raises(TypeError, match="unsupported_final_json_output_path"):
        finalizer_tmp_path(value)

    assert HostilePublicationPath.touched == 0


def test_stage1752_partial_recovery_records_rejected_path_without_hooks() -> None:
    HostilePublicationPath.touched = 0
    value = HostilePublicationPath("/tmp/hostile.json")

    recovered = recover_results_from_partial(value, {})

    evidence = recovered[PARTIAL_RECOVERY_EVIDENCE_KEY]
    assert evidence["partial_result_recovery_failed"] is True
    assert evidence["reason"] == "partial_result_path_rejected"
    assert evidence["path_type"] == "HostilePublicationPath"
    assert HostilePublicationPath.touched == 0


def test_stage1752_exact_stdlib_paths_remain_supported(tmp_path: Path) -> None:
    output = tmp_path / "results.json"

    assert safe_projection_path_text(output) == (output.as_posix(), "")
    temp_path = Path(finalizer_tmp_path(output))
    assert temp_path.parent == tmp_path
    temp_path.unlink()

    assert recover_results_from_partial(output, {"sample": {"classification": "clean"}}) == {
        "sample": {"classification": "clean"}
    }


def test_stage1752_old_instance_path_routes_are_removed() -> None:
    streaming_source = Path(
        "Virus_Scan/publication/json_finalization/streaming.py"
    ).read_text(encoding="utf-8")
    partial_source = Path(
        "Virus_Scan/publication/json_finalization/partial_results.py"
    ).read_text(encoding="utf-8")

    assert "_final_json_path_text" not in streaming_source
    assert "_partial_path_text" not in partial_source
    assert ".as_posix()" not in streaming_source
    assert ".as_posix()" not in partial_source
