"""Archive member scanning boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.runtime.api import scan_strings
from Virus_Scan.scanners.archives.evidence import (
    append_archive_member_finding_publication_evidence,
    append_archive_member_policy_evidence,
)
from Virus_Scan.scanners.archives.malformed import ARCHIVE_SCAN_EXCEPTIONS, append_archive_failure_evidence
from Virus_Scan.scanners.archives.member_view import (
    ArchiveContainerKind,
    ArchiveMemberView,
    inspect_archive_member,
)
from Virus_Scan.scanners.archives.payloads import archive_member_payload_tags
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.scanners.archives.text_boundaries import (
    archive_lower_text,
    archive_owned_text,
    archive_prefixed,
    archive_type_diagnostic,
)

PLR2004N64 = 64

ArchiveScanner = Callable[[str, int, ArchiveContainerKind], tuple[list[str], bool]]

_ARCHIVE_POLICY = load_archive_policy_snapshot()
_EXACT_MEMBER_PATH_TYPE = type(Path("."))
_SUSPICIOUS_STRING_TAGS = frozenset({"process_exec", "network_download", "encoded_payload", "powershell_encoded", "pickle_exec"})


def scan_archive_member(path: str, archive_depth: int, archive_scanner: ArchiveScanner) -> tuple[list[str], bool]:
    """Scan one extracted archive member with explicit archive-owned failure evidence."""
    path_text, path_reason = _archive_member_path(path)
    tags = ["archive_member"]
    if path_reason:
        tags = append_archive_member_policy_evidence(
            tags,
            path="",
            member_name=None,
            evidence_tag="archive_member_path_unsafe",
            reason=path_reason,
        )
        return (normalize_tags(tags), True)
    ext = get_scan_extension(path_text)
    ext_text = archive_owned_text(ext, default_text="none") or "none"
    tags.append(archive_prefixed("archive_member_ext:", ext_text))
    try:
        view = inspect_archive_member(
            path_text,
            probe_bytes=_ARCHIVE_POLICY.member_probe_bytes,
            text_max_size=_ARCHIVE_POLICY.member_text_max_size,
        )
    except ARCHIVE_SCAN_EXCEPTIONS as exc:
        tags = append_archive_failure_evidence(
            tags,
            "scan_extracted_archive_member.identity",
            exc,
            path_text,
            "archive_member_identity_error",
        )
        return (normalize_tags(tags), True)
    if view.container_kind != "unknown":
        inner_tags, inner_suspicious = archive_scanner(
            path_text, archive_depth, view.container_kind,
        )
        return (normalize_tags(tags + list(inner_tags)), bool(inner_suspicious))
    return _scan_regular_archive_member(path_text, view, tags)


def _scan_regular_archive_member(
    path_text: str,
    view: ArchiveMemberView,
    tags: list[str],
) -> tuple[list[str], bool]:
    lower_name = archive_lower_text(path_text)
    magic_finding_tags = _append_magic_tags(tags, view.prefix, view.suffix, lower_name)
    for finding_tag in magic_finding_tags:
        tags[:] = append_archive_member_finding_publication_evidence(
            tags,
            path=path_text,
            member_name=lower_name,
            finding_tag=finding_tag,
        )
    if _is_malformed_binary_member(view.prefix, lower_name):
        tags[:] = append_archive_member_policy_evidence(
            tags,
            path=path_text,
            member_name=lower_name,
            evidence_tag="archive_member_malformed_binary",
            reason="archive member has binary magic but is too short to be a valid binary payload",
        )
        tags.append("malformed_binary_archive_member")
    suspicious = _magic_tags_are_suspicious(tags)
    string_tags = list(scan_strings(view.text, path=path_text, finalize=False) or [])
    if string_tags:
        tags.extend(string_tags)
        string_suspicious = _string_tags_are_suspicious(string_tags)
        if string_suspicious:
            tags[:] = append_archive_member_finding_publication_evidence(
                tags,
                path=path_text,
                member_name=lower_name,
                finding_tag="archive_member_string_finding",
            )
        suspicious = suspicious or string_suspicious
    payload_tags, payload_suspicious = archive_member_payload_tags(
        path_text, view.raw, view.text,
    )
    if payload_tags:
        tags.extend(payload_tags)
        suspicious = suspicious or payload_suspicious
    return (normalize_tags(tags), suspicious)


def _magic_tags_are_suspicious(tags: list[str]) -> bool:
    return any(tag in tags for tag in (
        "embedded_pe_payload",
        "appended_pe_payload",
        "embedded_renpy_payload",
        "embedded_dotnet_payload",
        "archive_member_malformed_binary",
    ))

def _archive_member_path(path: object) -> tuple[str, str]:
    if type(path) is str:
        text = str.__str__(path)
        if str.strip(text):
            return text, ""
        return "", "archive_member_path_missing"
    if type(path) is _EXACT_MEMBER_PATH_TYPE:
        text = str(path)
        if str.strip(text):
            return text, ""
        return "", "archive_member_path_missing"
    if path is None:
        return "", "archive_member_path_missing"
    return "", archive_type_diagnostic("unsafe_archive_member_path_rejected:", path)



def _append_magic_tags(tags: list[str], prefix: bytes, suffix: bytes, lower_name: str) -> list[str]:
    findings: list[str] = []
    if prefix.startswith(b"MZ"):
        tags.extend(["embedded_pe_payload", "archive_member_magic_pe", "cross_engine_embedded_payload"])
        findings.append("archive_member_magic_pe_finding")
    if b"MZ" in suffix and not prefix.startswith(b"MZ"):
        tags.extend(["appended_pe_payload", "embedded_pe_payload", "polyglot_artifact", "cross_engine_embedded_payload"])
        findings.append("archive_member_appended_pe_finding")
    if prefix.startswith(b"RPA-3.0") or lower_name.endswith((".rpa", ".rpyc")):
        tags.extend(["embedded_renpy_payload", "cross_engine_embedded_payload"])
        findings.append("archive_member_renpy_payload_finding")
    if b"BSJB" in prefix or b"#~" in prefix or b"Assembly-CSharp" in prefix:
        tags.extend(["embedded_dotnet_payload", "archive_member_dotnet_metadata", "cross_engine_embedded_payload"])
        findings.append("archive_member_dotnet_payload_finding")
    return findings


def _is_malformed_binary_member(prefix: bytes, lower_name: str) -> bool:
    if not prefix.startswith(b"MZ"):
        return False
    binary_named = lower_name.endswith((".exe", ".dll", ".scr", ".sys", ".bin"))
    return binary_named and len(prefix) < PLR2004N64


def _string_tags_are_suspicious(string_tags: list[str]) -> bool:
    lowered = {tag.lower() for tag in normalize_tags(string_tags)}
    return any(
        tag in _SUSPICIOUS_STRING_TAGS or "exec" in tag or "payload" in tag
        for tag in lowered
    )


__all__ = ("scan_archive_member",)
