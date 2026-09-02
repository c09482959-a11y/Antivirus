from pathlib import Path, PurePosixPath

from Virus_Scan.contracts import library_baseline
from Virus_Scan.contracts.file_fingerprint import source_fingerprint_snapshot
from Virus_Scan.detection.correlation.graph.temporal_graph import _temporal_graph_text
from Virus_Scan.models.api.text_boundary import public_api_contract_text
from Virus_Scan.models.profiles.corruption import profile_corruption_evidence
from Virus_Scan.models.temporal.text_boundary import temporal_boundary_text
from Virus_Scan.scheduler.queue.raw_accumulator_value_support import raw_text
from Virus_Scan.scanners.binary_path_identity import binary_path_text_with_reason


class HostileStdlibSpoofPath(PurePosixPath):
    __module__ = "pathlib"
    touched = 0

    def as_posix(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call as_posix")

    @property
    def parts(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call parts")

    @property
    def name(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call name")

    @property
    def stem(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call stem")

    @property
    def suffix(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call suffix")

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __fspath__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("do not call fspath")


def _hostile_path() -> HostileStdlibSpoofPath:
    HostileStdlibSpoofPath.touched = 0
    return HostileStdlibSpoofPath("/tmp/hostile-stage1753.py")


def test_stage1753_models_and_detection_path_boundaries_reject_path_subclass_without_hooks() -> None:
    value = _hostile_path()

    assert temporal_boundary_text(value) == "temporal_text_unavailable"
    assert profile_corruption_evidence(value, "renpy", "bad_profile").profile_path.endswith(
        "profile_corruption_text_unavailable:HostileStdlibSpoofPath"
    )
    assert _temporal_graph_text(value) == ("", "unsafe_temporal_graph_text_rejected")
    assert public_api_contract_text(value) == ("", "unreadable_public_contract_text")
    assert HostileStdlibSpoofPath.touched == 0


def test_stage1753_contract_scheduler_and_scanner_path_boundaries_reject_path_subclass_without_hooks() -> None:
    value = _hostile_path()

    assert binary_path_text_with_reason(value) == ("", "unsafe_binary_scan_path_rejected")
    assert source_fingerprint_snapshot(value).as_dict() == {"path": "", "size": 0, "mtime": 0, "sha256": ""}
    assert raw_text(value, field_name="path") == "<path unsafe_path_rejected>"
    assert library_baseline._path_parts(value) == ()
    assert library_baseline._path_name(value) == ""
    assert library_baseline._path_stem_suffix_parts(value) is None
    assert HostileStdlibSpoofPath.touched == 0


def test_stage1753_exact_stdlib_paths_still_materialize() -> None:
    path = Path("/tmp/stage1753-safe.txt")

    assert temporal_boundary_text(path).endswith("/tmp/stage1753-safe.txt")
    assert binary_path_text_with_reason(path)[0].endswith("/tmp/stage1753-safe.txt")
    assert public_api_contract_text(path)[0].endswith("/tmp/stage1753-safe.txt")
    assert raw_text(path, field_name="path").endswith("/tmp/stage1753-safe.txt")
    assert library_baseline._path_name(path) == "stage1753-safe.txt"
    assert library_baseline._path_stem_suffix_parts(path) == (
        "stage1753-safe",
        ".txt",
        frozenset(("/", "tmp", "stage1753-safe.txt")),
    )


def test_stage1753_path_subclass_source_guards() -> None:
    guarded_files = (
        Path("Virus_Scan/contracts/file_fingerprint.py"),
        Path("Virus_Scan/contracts/library_baseline.py"),
        Path("Virus_Scan/detection/correlation/graph/temporal_graph.py"),
        Path("Virus_Scan/models/api/text_boundary.py"),
        Path("Virus_Scan/models/profiles/corruption.py"),
        Path("Virus_Scan/models/temporal/text_boundary.py"),
        Path("Virus_Scan/scheduler/queue/raw_accumulator_value_support.py"),
        Path("Virus_Scan/scanners/binary_path_identity.py"),
    )
    offenders = []
    for source in guarded_files:
        text = source.read_text(encoding="utf-8")
        if 'type(' in text and '__module__.startswith("pathlib")' in text:
            offenders.append(source.as_posix())
        if "return value.as_posix()" in text or "return raw.as_posix()" in text or "return path.as_posix()" in text:
            offenders.append(source.as_posix())

    assert offenders == []
