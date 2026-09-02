"""Independent bounded safety validation for inert synthetic carriers."""
from __future__ import annotations

from dataclasses import dataclass
import io
import zipfile

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.stress.attack_synthetic_schema import SYNTHETIC_SAFETY_VERSION

_EXECUTABLE_MAGICS = (
    b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
)


@dataclass(frozen=True, slots=True)
class SyntheticSafetyResult:
    sample_id: str
    safe: bool
    reasons: tuple[str, ...]
    artifact_size: int
    archive_member_count: int
    version: str = SYNTHETIC_SAFETY_VERSION

    def to_record(self) -> dict[str, object]:
        return {
            "archive_member_count": self.archive_member_count,
            "artifact_size": self.artifact_size,
            "reasons": self.reasons,
            "safe": self.safe,
            "sample_id": self.sample_id,
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_record())


def _valid_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ") or len(data) < 64:
        return False
    offset = int.from_bytes(data[60:64], "little")
    return 0 <= offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00"


def _archive_safety(data: bytes) -> tuple[int, tuple[str, ...]]:
    if not data.startswith(b"PK\x03\x04"):
        return 0, ()
    reasons: list[str] = []
    count = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            count = len(infos)
            if count > 8:
                reasons.append("archive_member_limit_exceeded")
            total = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or "../" in ("/" + name):
                    reasons.append("archive_member_path_unsafe")
                    continue
                if info.file_size > 65_536:
                    reasons.append("archive_member_size_exceeded")
                    continue
                payload = archive.read(info)
                total += len(payload)
                if _valid_pe(payload) or payload.startswith(_EXECUTABLE_MAGICS):
                    reasons.append("archive_member_executable_rejected")
            if total > 131_072:
                reasons.append("archive_total_size_exceeded")
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        reasons.append("archive_parse_failed")
    return count, tuple(sorted(set(reasons)))


def validate_inert_artifact(sample_id: str, data: bytes) -> SyntheticSafetyResult:
    if type(sample_id) is not str or not sample_id or type(data) is not bytes:
        raise TypeError("synthetic_safety_input_invalid")
    reasons: list[str] = []
    if len(data) < 8 or len(data) > 262_144:
        reasons.append("artifact_size_out_of_bounds")
    if _valid_pe(data):
        reasons.append("valid_pe_rejected")
    if data.startswith(_EXECUTABLE_MAGICS):
        reasons.append("valid_native_magic_rejected")
    if data.startswith(b"#!"):
        reasons.append("executable_script_shebang_rejected")
    archive_count, archive_reasons = _archive_safety(data)
    reasons.extend(archive_reasons)
    result = SyntheticSafetyResult(
        sample_id=sample_id,
        safe=not reasons,
        reasons=tuple(sorted(set(reasons))),
        artifact_size=len(data),
        archive_member_count=archive_count,
    )
    return result


__all__ = ("SyntheticSafetyResult", "validate_inert_artifact")
