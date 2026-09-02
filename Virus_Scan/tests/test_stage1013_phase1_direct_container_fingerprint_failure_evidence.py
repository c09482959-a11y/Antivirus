from pathlib import Path

from Virus_Scan.routing.context_identity import _direct_container_fingerprint


class _UnreadableUnityFile:
    name = "UnityPlayer.dll"

    def __str__(self) -> str:
        return "/fake/UnityPlayer.dll"

    def as_posix(self) -> str:
        return "/fake/UnityPlayer.dll"

    def is_dir(self) -> bool:
        return False

    def is_file(self) -> bool:
        return True

    def read_bytes(self) -> bytes:
        raise PermissionError("blocked sample")


class _FakeRoot:
    def __str__(self) -> str:
        return "/fake"

    def iterdir(self):
        return (_UnreadableUnityFile(),)


def test_direct_container_fingerprint_records_unreadable_root_as_failure_evidence(tmp_path: Path) -> None:
    missing_root = tmp_path / "missing-container-root"

    fingerprint = _direct_container_fingerprint(missing_root)

    assert fingerprint.engine == "other"
    assert "direct_container_fingerprint_unavailable" in fingerprint.evidence
    assert any(item.startswith("direct_container_root_error:") for item in fingerprint.evidence)
    assert "no_direct_container_engine_fingerprint" not in fingerprint.evidence


def test_direct_container_fingerprint_records_unreadable_child_sample_without_losing_path_signal() -> None:
    fingerprint = _direct_container_fingerprint(_FakeRoot())  # type: ignore[arg-type]

    assert fingerprint.engine == "unity"
    assert "filename:unityplayer.dll" in fingerprint.evidence
    assert any(item.startswith("direct_container_sample_unavailable:unityplayer.dll:") for item in fingerprint.evidence)
