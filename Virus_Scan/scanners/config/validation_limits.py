"""Scanner config validator for scanner-wide limits policy."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners.config.contracts import ScannerConfigError, ScannerLimitsPolicySnapshot
from Virus_Scan.scanners.config.validation_helpers import _config_failure, _require_policy_mapping
from Virus_Scan.scanners.config.validation_helpers import _IntRequirement, _StringTupleRequirement, _require_int, _require_str_tuple

def validate_scanner_limits_policy(policy: dict[str, object], *, source: str) -> ScannerLimitsPolicySnapshot:
    config_name = "scanner_limits_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "scanner limits policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return ScannerLimitsPolicySnapshot(
        image_stego_max_file_bytes=_require_int(_IntRequirement(policy, 'image_stego_max_file_bytes', (1024, 512 * 1024 * 1024), source, config_name)),
        image_stego_max_pixels=_require_int(_IntRequirement(policy, 'image_stego_max_pixels', (1, 500000000), source, config_name)),
        image_stego_sample_pixels=_require_int(_IntRequirement(policy, 'image_stego_sample_pixels', (1, 50000000), source, config_name)),
        image_stego_resize_sample_max_side=_require_int(_IntRequirement(policy, 'image_stego_resize_sample_max_side', (16, 8192), source, config_name)),
        image_enrichment_thorough_bytes=_require_int(_IntRequirement(policy, 'image_enrichment_thorough_bytes', (1024, 512 * 1024 * 1024), source, config_name)),
        image_enrichment_auto_escalated_bytes=_require_int(_IntRequirement(policy, 'image_enrichment_auto_escalated_bytes', (1024, 512 * 1024 * 1024), source, config_name)),
        image_enrichment_fast_bytes=_require_int(_IntRequirement(policy, 'image_enrichment_fast_bytes', (1024, 512 * 1024 * 1024), source, config_name)),
        image_payload_magic_prefixes=_require_str_tuple(_StringTupleRequirement(policy, 'image_payload_magic_prefixes', (1, 32), source, config_name)),
        image_payload_needles=_require_str_tuple(_StringTupleRequirement(policy, 'image_payload_needles', (1, 128), source, config_name)),
        image_lsb_trigger_tags=_require_str_tuple(_StringTupleRequirement(policy, 'image_lsb_trigger_tags', (1, 128), source, config_name)),
        image_jpeg_lsb_weak_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'image_jpeg_lsb_weak_tags', (1, 128), source, config_name))),
        image_stego_tag_rewrite_map=_require_policy_mapping(policy, "image_stego_tag_rewrite_map", source=source, config_name=config_name),
        image_suspicious_png_text_needles=_require_str_tuple(_StringTupleRequirement(policy, 'image_suspicious_png_text_needles', (1, 128), source, config_name)),
        image_suspicious_binary_needles=_require_str_tuple(_StringTupleRequirement(policy, 'image_suspicious_binary_needles', (1, 128), source, config_name)),
        image_confirmed_tags=_require_str_tuple(_StringTupleRequirement(policy, 'image_confirmed_tags', (1, 128), source, config_name)),
        image_magic_prefixes_by_extension=_require_policy_mapping(policy, "image_magic_prefixes_by_extension", source=source, config_name=config_name),
        strings_intrastage_min_text_chars=_require_int(_IntRequirement(policy, 'strings_intrastage_min_text_chars', (1024, 256 * 1024 * 1024), source, config_name)),
        strings_intrastage_chunk_chars=_require_int(_IntRequirement(policy, 'strings_intrastage_chunk_chars', (1024, 256 * 1024 * 1024), source, config_name)),
        strings_intrastage_chunk_overlap=_require_int(_IntRequirement(policy, 'strings_intrastage_chunk_overlap', (0, 16 * 1024 * 1024), source, config_name)),
        strings_intrastage_max_chunks=_require_int(_IntRequirement(policy, 'strings_intrastage_max_chunks', (1, 100000), source, config_name)),
        strings_ast_max_literal_chars=_require_int(_IntRequirement(policy, 'strings_ast_max_literal_chars', (1, 16 * 1024 * 1024), source, config_name)),
        strings_ast_max_text_chars=_require_int(_IntRequirement(policy, 'strings_ast_max_text_chars', (1, 16 * 1024 * 1024), source, config_name)),
        strings_ast_max_items=_require_int(_IntRequirement(policy, 'strings_ast_max_items', (1, 100000), source, config_name)),
        raw_queue_strings_blob_max_chars=_require_int(_IntRequirement(policy, 'raw_queue_strings_blob_max_chars', (1024, 256 * 1024 * 1024), source, config_name)),
        raw_chunk_default_read_size=_require_int(_IntRequirement(policy, 'raw_chunk_default_read_size', (1024, 256 * 1024 * 1024), source, config_name)),
        raw_chunk_strings_blob_max_chars=_require_int(_IntRequirement(policy, 'raw_chunk_strings_blob_max_chars', (1024, 256 * 1024 * 1024), source, config_name)),
        raw_chunk_text_probe_bytes=_require_int(_IntRequirement(policy, 'raw_chunk_text_probe_bytes', (1024, 256 * 1024 * 1024), source, config_name)),
        raw_chunk_mz_probe_bytes=_require_int(_IntRequirement(policy, 'raw_chunk_mz_probe_bytes', (512, 256 * 1024 * 1024), source, config_name)),
        source=str(Path(source)),
    )

__all__ = (
    "validate_scanner_limits_policy",
)
