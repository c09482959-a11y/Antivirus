"""IL2CPP binary enrichment scanner owner."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.utils.entropy import strict_fast_entropy
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.unity_behavior import detect_unity_runtime_behavior
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.evidence.static_bytes import stage_read_bytes
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty

_DEFAULT_IL_SIGNATURES = MappingProxyType({
    "IL_REFLECTION": b"GetMethod",
    "IL_INVOKE": b"Invoke",
    "IL_BASE64": b"FromBase64String",
    "IL_PROCESS": b"Process.Start",
    "IL_ASSEMBLY": b"Assembly.Load",
})


@dataclass(frozen=True)
class ILSignatureRegistryUnavailable:
    """Typed evidence that IL signature registry materialization failed."""

    reason: str
    value_type: str

    def as_tag(self) -> str:
        return "il2cpp_signature_registry_unavailable"


def _il_signature_unavailable(reason: str, value: object) -> ILSignatureRegistryUnavailable:
    return ILSignatureRegistryUnavailable(reason=reason, value_type=no_hook_type_name(value))


def _il_signature_items(value: object) -> tuple[tuple[object, object], ...] | ILSignatureRegistryUnavailable:
    try:
        if isinstance(value, dict):
            return tuple(dict.items(value))
        if type(value) is MappingProxyType:
            return tuple(value.items())
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        return _il_signature_unavailable("il_signature_items_unavailable", value)
    return _il_signature_unavailable("il_signature_registry_unsupported", value)


def _il_signature_bytes(value: object) -> object:
    if type(value) is bytes:
        return bytes(value)
    if type(value) is bytearray:
        return bytes(value)
    if type(value) is memoryview:
        return bytes(value)
    return b""


def scan_il2cpp_binary(file: object, *, finalize: object=True) -> object:
    """IL2CPP binary collector. finalize=False returns raw tags only."""
    tags: set[str] = set()
    try:
        data = stage_read_bytes(file, max_size=5_000_000)
        low = data.lower()
        if b"global-metadata.dat" in low:
            tags.add("il2cpp_metadata_ref")
        if b"il2cpp" in low:
            tags.add("il2cpp_binary")
        if b"assembly-csharp" in low:
            tags.add("il2cpp_strings")
        il_sigs = detection_registry_value("IL_SIGNATURES", _DEFAULT_IL_SIGNATURES)
        signature_items = _il_signature_items(il_sigs)
        if isinstance(signature_items, ILSignatureRegistryUnavailable):
            tags.add(signature_items.as_tag())
        else:
            for key, sig in signature_items:
                signature = _il_signature_bytes(sig).lower()
                tag_text = detection_enrichment_text_or_empty(key)
                if signature and tag_text and signature in low:
                    tags.add(tag_text)
        text = data.decode("latin1", errors="ignore")
        tags.update(detect_unity_runtime_behavior(text))
        if b"MZ" in data:
            tags.add("pe_file")
        if strict_fast_entropy(data) > 7.5 and any(tag in tags for tag in ("IL_REFLECTION", "IL_INVOKE", "IL_ASSEMBLY")):
            tags.add("likely_packed")
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        tags.update(failure_tags_for_stage("il2cpp_static_scan", exc, context=file))
    if finalize:
        return normalize_tags(tags)
    return list(tags or [])
