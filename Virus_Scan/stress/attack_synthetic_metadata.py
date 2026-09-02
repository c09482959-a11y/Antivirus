"""Label-opaque challenge metadata derived from hidden corpus generation records."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.stress.attack_synthetic_schema import SYNTHETIC_METADATA_VERSION
from Virus_Scan.stress.static_semantic_schema import CorpusGenerationRecord


def _placeholder(label: str, generation: CorpusGenerationRecord, length: int) -> str:
    value = sha256(
        (label + ":" + generation.sample_id + ":" + generation.partition_seed).encode("utf-8")
    ).hexdigest()
    return value[:length]


def _file_type(generation: CorpusGenerationRecord) -> str:
    renderer = generation.fixture_definition.renderer_specification
    if renderer.renderer_kind == "text":
        return renderer.language
    return renderer.renderer_kind + ":" + renderer.language


@dataclass(frozen=True, slots=True)
class SyntheticMalwareBazaarMetadata:
    sample_id: str
    file_type: str
    signature: str
    tags: tuple[str, ...]
    reporter: str
    tlsh_placeholder: str
    import_hash_placeholder: str
    telfhash_placeholder: str
    gimphash_placeholder: str
    icon_dhash_placeholder: str
    code_signing_state: str
    certificate_group: str
    parent_group: str
    unpacked_child_group: str
    campaign_group: str
    delivery_method: str
    version: str = SYNTHETIC_METADATA_VERSION

    def to_record(self) -> dict[str, object]:
        return {
            "campaign_group": self.campaign_group,
            "certificate_group": self.certificate_group,
            "code_signing_state": self.code_signing_state,
            "delivery_method": self.delivery_method,
            "file_type": self.file_type,
            "gimphash_placeholder": self.gimphash_placeholder,
            "icon_dhash_placeholder": self.icon_dhash_placeholder,
            "import_hash_placeholder": self.import_hash_placeholder,
            "parent_group": self.parent_group,
            "reporter": self.reporter,
            "sample_id": self.sample_id,
            "signature": self.signature,
            "tags": self.tags,
            "telfhash_placeholder": self.telfhash_placeholder,
            "tlsh_placeholder": self.tlsh_placeholder,
            "unpacked_child_group": self.unpacked_child_group,
            "version": self.version,
        }

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_record())


def synthetic_metadata(generation: CorpusGenerationRecord) -> SyntheticMalwareBazaarMetadata:
    """Project hidden generation context into non-authoritative, label-opaque metadata."""
    if type(generation) is not CorpusGenerationRecord:
        raise TypeError("synthetic_metadata_generation_invalid")
    renderer = generation.fixture_definition.renderer_specification
    file_type = _file_type(generation)
    group = _placeholder("group", generation, 16)
    renderer_tag = "carrier_" + renderer.renderer_kind
    language_tag = "language_" + renderer.language
    return SyntheticMalwareBazaarMetadata(
        sample_id=generation.sample_id,
        file_type=file_type,
        signature="synthetic_challenge_" + renderer.renderer_kind,
        tags=tuple(sorted(("challenge", "synthetic", renderer_tag, language_tag))),
        reporter="synthetic-reporter-" + _placeholder("reporter", generation, 8),
        tlsh_placeholder="T1" + _placeholder("tlsh", generation, 68),
        import_hash_placeholder=_placeholder("imphash", generation, 32),
        telfhash_placeholder=_placeholder("telfhash", generation, 64),
        gimphash_placeholder=_placeholder("gimphash", generation, 32),
        icon_dhash_placeholder=_placeholder("icon", generation, 16),
        code_signing_state=(
            "synthetic_signed"
            if int(_placeholder("signed", generation, 2), 16) % 3 == 0
            else "synthetic_unsigned"
        ),
        certificate_group="cert-" + _placeholder("cert", generation, 12),
        parent_group="parent-" + group,
        unpacked_child_group="child-" + group,
        campaign_group="campaign-" + group,
        delivery_method=(
            "web_download", "email_attachment", "software_bundle", "remote_share"
        )[int(_placeholder("delivery", generation, 2), 16) % 4],
    )


__all__ = ("SyntheticMalwareBazaarMetadata", "synthetic_metadata")
