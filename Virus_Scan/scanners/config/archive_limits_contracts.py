"""Immutable scanner archive and limits policy snapshot contracts."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scanners.config.immutable_policy import (
    freeze_policy_contract_value,
    policy_float,
    policy_int,
    policy_text,
    policy_text_frozenset,
    policy_text_tuple,
)


@dataclass(frozen=True, slots=True)
class ArchivePolicySnapshot:
    default_max_depth: int
    default_max_members: int
    default_max_member_size: int
    member_probe_bytes: int
    member_text_max_size: int
    ecosystem_score_limit: int
    ecosystem_score_warn: int
    rpa_read_max_bytes: int
    rpa_index_max_bytes: int
    rpa_member_max_bytes: int
    rpa_member_max_count: int
    rpa_zip_max_depth: int
    rpa_zip_max_members: int
    rpa_zip_max_member_size: int
    nested_archive_suffixes: tuple[str, ...]
    rarity_high_risk_probability: float
    rarity_high_risk_min_score: float
    rarity_high_risk_multiplier: float
    rarity_rare_probability: float
    rarity_rare_multiplier: float
    rarity_uncommon_probability: float
    rarity_uncommon_multiplier: float
    rarity_common_probability: float
    rarity_common_multiplier: float
    rarity_default_multiplier: float
    source: str
    schema: str = "archive_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "default_max_depth", policy_int(self.default_max_depth))
        object.__setattr__(self, "default_max_members", policy_int(self.default_max_members))
        object.__setattr__(self, "default_max_member_size", policy_int(self.default_max_member_size))
        object.__setattr__(self, "member_probe_bytes", policy_int(self.member_probe_bytes))
        object.__setattr__(self, "member_text_max_size", policy_int(self.member_text_max_size))
        object.__setattr__(self, "ecosystem_score_limit", policy_int(self.ecosystem_score_limit))
        object.__setattr__(self, "ecosystem_score_warn", policy_int(self.ecosystem_score_warn))
        object.__setattr__(self, "rpa_read_max_bytes", policy_int(self.rpa_read_max_bytes))
        object.__setattr__(self, "rpa_index_max_bytes", policy_int(self.rpa_index_max_bytes))
        object.__setattr__(self, "rpa_member_max_bytes", policy_int(self.rpa_member_max_bytes))
        object.__setattr__(self, "rpa_member_max_count", policy_int(self.rpa_member_max_count))
        object.__setattr__(self, "rpa_zip_max_depth", policy_int(self.rpa_zip_max_depth))
        object.__setattr__(self, "rpa_zip_max_members", policy_int(self.rpa_zip_max_members))
        object.__setattr__(self, "rpa_zip_max_member_size", policy_int(self.rpa_zip_max_member_size))
        object.__setattr__(self, "nested_archive_suffixes", policy_text_tuple(self.nested_archive_suffixes))
        object.__setattr__(self, "rarity_high_risk_probability", policy_float(self.rarity_high_risk_probability))
        object.__setattr__(self, "rarity_high_risk_min_score", policy_float(self.rarity_high_risk_min_score))
        object.__setattr__(self, "rarity_high_risk_multiplier", policy_float(self.rarity_high_risk_multiplier))
        object.__setattr__(self, "rarity_rare_probability", policy_float(self.rarity_rare_probability))
        object.__setattr__(self, "rarity_rare_multiplier", policy_float(self.rarity_rare_multiplier))
        object.__setattr__(self, "rarity_uncommon_probability", policy_float(self.rarity_uncommon_probability))
        object.__setattr__(self, "rarity_uncommon_multiplier", policy_float(self.rarity_uncommon_multiplier))
        object.__setattr__(self, "rarity_common_probability", policy_float(self.rarity_common_probability))
        object.__setattr__(self, "rarity_common_multiplier", policy_float(self.rarity_common_multiplier))
        object.__setattr__(self, "rarity_default_multiplier", policy_float(self.rarity_default_multiplier))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="archive_policy.v1"))


@dataclass(frozen=True, slots=True)
class ScannerLimitsPolicySnapshot:
    image_stego_max_file_bytes: int
    image_stego_max_pixels: int
    image_stego_sample_pixels: int
    image_stego_resize_sample_max_side: int
    image_enrichment_thorough_bytes: int
    image_enrichment_auto_escalated_bytes: int
    image_enrichment_fast_bytes: int
    image_payload_magic_prefixes: tuple[str, ...]
    image_payload_needles: tuple[str, ...]
    image_lsb_trigger_tags: tuple[str, ...]
    image_jpeg_lsb_weak_tags: frozenset[str]
    image_stego_tag_rewrite_map: object
    image_suspicious_png_text_needles: tuple[str, ...]
    image_suspicious_binary_needles: tuple[str, ...]
    image_confirmed_tags: tuple[str, ...]
    image_magic_prefixes_by_extension: object
    strings_intrastage_min_text_chars: int
    strings_intrastage_chunk_chars: int
    strings_intrastage_chunk_overlap: int
    strings_intrastage_max_chunks: int
    strings_ast_max_literal_chars: int
    strings_ast_max_text_chars: int
    strings_ast_max_items: int
    raw_queue_strings_blob_max_chars: int
    raw_chunk_default_read_size: int
    raw_chunk_strings_blob_max_chars: int
    raw_chunk_text_probe_bytes: int
    raw_chunk_mz_probe_bytes: int
    source: str
    schema: str = "scanner_limits_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "image_stego_max_file_bytes", policy_int(self.image_stego_max_file_bytes))
        object.__setattr__(self, "image_stego_max_pixels", policy_int(self.image_stego_max_pixels))
        object.__setattr__(self, "image_stego_sample_pixels", policy_int(self.image_stego_sample_pixels))
        object.__setattr__(self, "image_stego_resize_sample_max_side", policy_int(self.image_stego_resize_sample_max_side))
        object.__setattr__(self, "image_enrichment_thorough_bytes", policy_int(self.image_enrichment_thorough_bytes))
        object.__setattr__(self, "image_enrichment_auto_escalated_bytes", policy_int(self.image_enrichment_auto_escalated_bytes))
        object.__setattr__(self, "image_enrichment_fast_bytes", policy_int(self.image_enrichment_fast_bytes))
        object.__setattr__(self, "image_payload_magic_prefixes", policy_text_tuple(self.image_payload_magic_prefixes))
        object.__setattr__(self, "image_payload_needles", policy_text_tuple(self.image_payload_needles))
        object.__setattr__(self, "image_lsb_trigger_tags", policy_text_tuple(self.image_lsb_trigger_tags))
        object.__setattr__(self, "image_jpeg_lsb_weak_tags", policy_text_frozenset(self.image_jpeg_lsb_weak_tags))
        object.__setattr__(self, "image_stego_tag_rewrite_map", freeze_policy_contract_value(self.image_stego_tag_rewrite_map))
        object.__setattr__(self, "image_suspicious_png_text_needles", policy_text_tuple(self.image_suspicious_png_text_needles))
        object.__setattr__(self, "image_suspicious_binary_needles", policy_text_tuple(self.image_suspicious_binary_needles))
        object.__setattr__(self, "image_confirmed_tags", policy_text_tuple(self.image_confirmed_tags))
        object.__setattr__(self, "image_magic_prefixes_by_extension", freeze_policy_contract_value(self.image_magic_prefixes_by_extension))
        object.__setattr__(self, "strings_intrastage_min_text_chars", policy_int(self.strings_intrastage_min_text_chars))
        object.__setattr__(self, "strings_intrastage_chunk_chars", policy_int(self.strings_intrastage_chunk_chars))
        object.__setattr__(self, "strings_intrastage_chunk_overlap", policy_int(self.strings_intrastage_chunk_overlap))
        object.__setattr__(self, "strings_intrastage_max_chunks", policy_int(self.strings_intrastage_max_chunks))
        object.__setattr__(self, "strings_ast_max_literal_chars", policy_int(self.strings_ast_max_literal_chars))
        object.__setattr__(self, "strings_ast_max_text_chars", policy_int(self.strings_ast_max_text_chars))
        object.__setattr__(self, "strings_ast_max_items", policy_int(self.strings_ast_max_items))
        object.__setattr__(self, "raw_queue_strings_blob_max_chars", policy_int(self.raw_queue_strings_blob_max_chars))
        object.__setattr__(self, "raw_chunk_default_read_size", policy_int(self.raw_chunk_default_read_size))
        object.__setattr__(self, "raw_chunk_strings_blob_max_chars", policy_int(self.raw_chunk_strings_blob_max_chars))
        object.__setattr__(self, "raw_chunk_text_probe_bytes", policy_int(self.raw_chunk_text_probe_bytes))
        object.__setattr__(self, "raw_chunk_mz_probe_bytes", policy_int(self.raw_chunk_mz_probe_bytes))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="scanner_limits_policy.v1"))


__all__ = ("ArchivePolicySnapshot", "ScannerLimitsPolicySnapshot")
