from __future__ import annotations

from unittest.mock import patch

from Virus_Scan.models.profiles.context import contextual_profile_bucket_key
from Virus_Scan.routing.artifact_platform import canonical_artifact_platform
from Virus_Scan.routing.context_router_identity import file_identity_from_router_identity
from Virus_Scan.routing.extension_outcome import RouteScanOutcome, route_identity_record


class _HostilePath:
    touched = 0

    def __fspath__(self) -> str:
        type(self).touched += 1
        raise AssertionError("owned route identity must avoid path re-sniff")

    def __str__(self) -> str:
        type(self).touched += 1
        raise AssertionError("owned route identity must avoid path text hooks")


def _owned_identity(magic_type: str = "pe_mz") -> object:
    return RouteScanOutcome(
        tags=("file_seen",),
        suspicious=False,
        identity={
            "ext": ".exe",
            "ext_stage": "binary",
            "magic_stage": "binary",
            "magic_type": magic_type,
            "tags": ("pe_file", "magic_type_pe_mz"),
        },
    ).identity


def test_phase9_owned_route_identity_has_one_exact_projection() -> None:
    identity = _owned_identity()
    record = route_identity_record(identity)

    assert type(record) is dict
    assert record["magic_type"] == "pe_mz"
    assert record["tags"] == ("pe_file", "magic_type_pe_mz")


def test_phase9_context_identity_consumes_owned_route_identity_without_resniff() -> None:
    identity = file_identity_from_router_identity(_owned_identity())

    assert identity is not None
    assert identity.declared_extension == ".exe"
    assert identity.sniffed_type == "pe"
    assert "magic:pe_mz" in identity.evidence


def test_phase9_platform_consumes_owned_route_identity_without_touching_path() -> None:
    _HostilePath.touched = 0

    platform = canonical_artifact_platform(
        _HostilePath(),
        router_identity=_owned_identity(),
        strings_blob="",
    )

    assert platform == "windows"
    assert _HostilePath.touched == 0


def test_phase9_unresolved_owned_identity_does_not_resniff_path() -> None:
    _HostilePath.touched = 0

    platform = canonical_artifact_platform(
        _HostilePath(),
        router_identity=_owned_identity("script_text"),
        strings_blob="",
    )

    assert platform == ""
    assert _HostilePath.touched == 0


def test_phase9_contextual_profile_bucket_reuses_route_identity_without_resniff(tmp_path) -> None:
    sample = tmp_path / "owned_identity.exe"
    sample.write_bytes(b"MZ" + (b"\x00" * 64))

    with patch(
        "Virus_Scan.routing.context_identity.sniff_file_identity",
        side_effect=AssertionError("profile baseline must reuse the owned route identity"),
    ):
        key, context = contextual_profile_bucket_key(
            sample,
            trusted_benign=True,
            router_identity=_owned_identity(),
        )

    assert type(key) is str
    assert key != ""
    assert context.sniffed_type == "pe"
    assert context.effective_analysis_engine == "pe"
    assert "magic:pe_mz" in context.fingerprint_evidence
