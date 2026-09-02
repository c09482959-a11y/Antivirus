"""Deterministic inert raw-artifact renderer for static-semantic evaluation corpora."""
from __future__ import annotations

import io
import zipfile

from Virus_Scan.stress.static_semantic_binary_fixtures import (
    render_static_semantic_binary_fixture,
)
from Virus_Scan.stress.static_semantic_schema import (
    STATIC_SEMANTIC_RENDERER_VERSION,
    ArtifactRendererSpecification,
)


def _comment_prefix(extension: str) -> str:
    if extension in {".py", ".rpy", ".rb", ".ps1", ".sh"}:
        return "# "
    if extension in {".js", ".ts"}:
        return "// "
    if extension in {".bat", ".cmd"}:
        return "REM "
    return "# "


def _source_bytes(
    sample_id: str,
    specification: ArtifactRendererSpecification,
    extension: str,
) -> bytes:
    prefix = _comment_prefix(extension)
    header = (
        prefix + "UMIGE STATIC-SEMANTIC INERT FIXTURE - NEVER EXECUTE\n"
        + prefix + "sample_id=" + sample_id + "\n"
        + prefix + "renderer_version=" + STATIC_SEMANTIC_RENDERER_VERSION + "\n"
    )
    return (header + specification.source_text).encode("utf-8")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o444 << 16
    info.create_system = 3
    return info


def _nested_zip(sample_id: str, specification: ArtifactRendererSpecification) -> bytes:
    member = "artifact" + specification.member_extension
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(
        inner_buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6,
    ) as inner:
        inner.writestr(
            _zip_info(member),
            _source_bytes(sample_id, specification, specification.member_extension),
        )
    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(
        outer_buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6,
    ) as outer:
        outer.writestr(_zip_info("nested/inner.zip"), inner_buffer.getvalue())
        outer.writestr(
            _zip_info("README.txt"),
            (
                "UMIGE inert nested static-semantic fixture\n"
                "sample_id=" + sample_id + "\n"
            ).encode("utf-8"),
        )
    return outer_buffer.getvalue()


def render_static_semantic_artifact(
    sample_id: str,
    specification: ArtifactRendererSpecification,
) -> bytes:
    """Render from artifact-production instructions only; generator intent is not accepted."""
    if type(sample_id) is not str or not sample_id or len(sample_id) > 128:
        raise TypeError("static_semantic_renderer_sample_id_invalid")
    if type(specification) is not ArtifactRendererSpecification:
        raise TypeError("static_semantic_renderer_specification_invalid")
    if specification.renderer_kind == "text":
        return _source_bytes(sample_id, specification, specification.extension)
    if specification.renderer_kind == "nested_zip":
        return _nested_zip(sample_id, specification)
    if specification.renderer_kind in {"managed_pe", "native_elf_x86_64"}:
        return render_static_semantic_binary_fixture(
            specification.renderer_kind,
            specification.fixture_variant,
            sample_id,
        )
    raise ValueError("static_semantic_renderer_kind_invalid")


__all__ = ("render_static_semantic_artifact",)
