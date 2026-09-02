from pathlib import Path

import pytest

from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.scan_cache_publication import (
    scan_cache_publication_identity_from_result,
)


def _result_for(path: Path, result_path: str) -> dict[str, object]:
    snapshot = build_artifact_read_snapshot(path)
    assert snapshot.complete is True
    return {
        "file": result_path,
        "artifact_read": snapshot.to_record(),
    }


def test_cache_publication_accepts_relative_result_path_for_same_artifact(
    tmp_path: Path,
) -> None:
    target = tmp_path / "sample.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    result_path = str(target.relative_to(Path.cwd())) if target.is_relative_to(Path.cwd()) else str(target)
    identity = scan_cache_publication_identity_from_result(
        _result_for(target, result_path)
    )
    assert identity is not None
    assert identity.canonical_path == str(target.resolve())
    assert identity.file_name == "sample.py"


def test_cache_publication_rejects_different_resolved_result_path(
    tmp_path: Path,
) -> None:
    target = tmp_path / "sample.py"
    other = tmp_path / "other" / "sample.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    other.parent.mkdir()
    other.write_text("print('other')\n", encoding="utf-8")
    wrong_path = str(other.relative_to(Path.cwd())) if other.is_relative_to(Path.cwd()) else str(other)
    with pytest.raises(ValueError, match="scan_cache_publication_result_path_mismatch"):
        scan_cache_publication_identity_from_result(
            _result_for(target, wrong_path)
        )
