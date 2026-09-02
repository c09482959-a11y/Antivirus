"""Independent bounded safety validation for Phase 25 inert source carriers."""
from __future__ import annotations

from dataclasses import dataclass
import io
import re
import zipfile

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.stress.attack_synthetic_safety import validate_inert_artifact
from Virus_Scan.stress.static_semantic_binary_fixtures import (
    is_exact_static_semantic_binary_fixture,
)
from Virus_Scan.stress.static_semantic_schema import STATIC_SEMANTIC_SAFETY_VERSION

_URL_RE = re.compile(rb"https?://([^/\s'\"`]+)", re.IGNORECASE)
_EXECUTABLE_MAGICS = (
    b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
)
_DESTRUCTIVE_TOKENS = (
    b"rm -rf /", b"format c:", b"del /s /q c:\\", b"shutdown /s",
    b"mkfs.", b"diskpart /s", b"remove-item -recurse c:\\",
)


@dataclass(frozen=True, slots=True)
class StaticSemanticSafetyResult:
    sample_id: str
    safe: bool
    reasons: tuple[str, ...]
    artifact_size: int
    archive_member_count: int
    maximum_archive_depth: int
    expanded_bytes: int
    version: str = STATIC_SEMANTIC_SAFETY_VERSION

    def to_record(self) -> dict[str, object]:
        base = {
            "archive_member_count": self.archive_member_count,
            "artifact_size": self.artifact_size,
            "expanded_bytes": self.expanded_bytes,
            "maximum_archive_depth": self.maximum_archive_depth,
            "reasons": self.reasons,
            "safe": self.safe,
            "sample_id": self.sample_id,
            "version": self.version,
        }
        return {**base, "safety_digest": canonical_json_sha256(base)}


def _valid_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ") or len(data) < 64:
        return False
    offset = int.from_bytes(data[60:64], "little")
    return 0 <= offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00"


def _payload_reasons(data: bytes) -> tuple[str, ...]:
    reasons: set[str] = set()
    if _valid_pe(data) or data.startswith(_EXECUTABLE_MAGICS):
        reasons.add("executable_payload_rejected")
    if data.startswith(b"#!"):
        reasons.add("executable_shebang_rejected")
    lower = data.lower()
    if any(token in lower for token in _DESTRUCTIVE_TOKENS):
        reasons.add("destructive_command_rejected")
    for host in _URL_RE.findall(data):
        if host.lower().rstrip(b".") != b"example.invalid":
            reasons.add("non_reserved_network_target_rejected")
    return tuple(sorted(reasons))


def _archive_walk(
    data: bytes,
    *,
    depth: int,
    totals: dict[str, int],
    reasons: set[str],
) -> None:
    if not data.startswith(b"PK\x03\x04"):
        reasons.update(_payload_reasons(data))
        totals["expanded"] += len(data)
        return
    if depth > 2:
        reasons.add("archive_depth_exceeded")
        return
    totals["max_depth"] = max(totals["max_depth"], depth)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            totals["members"] += len(infos)
            if len(infos) > 8 or totals["members"] > 16:
                reasons.add("archive_member_limit_exceeded")
            for info in infos:
                name = info.filename.replace("\\", "/")
                if (
                    name.startswith("/")
                    or name.startswith("../")
                    or "/../" in "/" + name
                    or info.flag_bits & 0x1
                ):
                    reasons.add("archive_member_unsafe")
                    continue
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode & 0o170000 in {0o120000, 0o060000, 0o020000}:
                    reasons.add("archive_special_file_rejected")
                    continue
                if info.file_size > 262_144:
                    reasons.add("archive_member_size_exceeded")
                    continue
                payload = archive.read(info)
                _archive_walk(payload, depth=depth + 1, totals=totals, reasons=reasons)
                if totals["expanded"] > 524_288:
                    reasons.add("archive_expanded_size_exceeded")
                    return
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        reasons.add("archive_parse_failed")


def validate_static_semantic_artifact(
    sample_id: str,
    data: bytes,
    *,
    renderer_kind: str = "",
    fixture_variant: str = "",
) -> StaticSemanticSafetyResult:
    if type(sample_id) is not str or not sample_id or type(data) is not bytes:
        raise TypeError("static_semantic_safety_input_invalid")
    if type(renderer_kind) is not str or type(fixture_variant) is not str:
        raise TypeError("static_semantic_safety_fixture_identity_invalid")
    reasons: set[str] = set()
    if len(data) < 16 or len(data) > 524_288:
        reasons.add("artifact_size_out_of_bounds")
    exact_binary = False
    if renderer_kind in {"managed_pe", "native_elf_x86_64"}:
        exact_binary = is_exact_static_semantic_binary_fixture(
            renderer_kind, fixture_variant, sample_id, data,
        )
        if not exact_binary:
            reasons.add("static_semantic_binary_fixture_identity_mismatch")
    elif renderer_kind or fixture_variant:
        if renderer_kind not in {"text", "nested_zip"} or fixture_variant:
            reasons.add("static_semantic_fixture_identity_invalid")

    totals = {"members": 0, "max_depth": 0, "expanded": 0}
    if exact_binary:
        # The generic inert-artifact owner must keep rejecting arbitrary PE/ELF.
        # Only exact bytes from the canonical deterministic fixture renderer are
        # admitted here; all non-executable safety checks remain active.
        reasons.update(
            reason for reason in _payload_reasons(data)
            if reason != "executable_payload_rejected"
        )
        totals["expanded"] = len(data)
    else:
        base = validate_inert_artifact(sample_id, data)
        reasons.update(base.reasons)
        _archive_walk(data, depth=1, totals=totals, reasons=reasons)
    return StaticSemanticSafetyResult(
        sample_id=sample_id,
        safe=not reasons,
        reasons=tuple(sorted(reasons)),
        artifact_size=len(data),
        archive_member_count=totals["members"],
        maximum_archive_depth=totals["max_depth"],
        expanded_bytes=totals["expanded"],
    )


__all__ = ("StaticSemanticSafetyResult", "validate_static_semantic_artifact")
