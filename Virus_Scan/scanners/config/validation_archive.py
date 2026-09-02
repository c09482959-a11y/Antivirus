"""Scanner config validator for archive/RPA policy."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners.config.contracts import ArchivePolicySnapshot, ScannerConfigError
from Virus_Scan.scanners.config.validation_helpers import _FloatRequirement, _config_failure, _require_float
from Virus_Scan.scanners.config.validation_helpers import _IntRequirement, _StringTupleRequirement, _require_int, _require_str_tuple

def validate_archive_policy(policy: dict[str, object], *, source: str) -> ArchivePolicySnapshot:
    config_name = "archive_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "archive policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return ArchivePolicySnapshot(
        default_max_depth=_require_int(_IntRequirement(policy, 'default_max_depth', (0, 32), source, config_name)),
        default_max_members=_require_int(_IntRequirement(policy, 'default_max_members', (1, 100000), source, config_name)),
        default_max_member_size=_require_int(_IntRequirement(policy, 'default_max_member_size', (1024, 2 * 1024 * 1024 * 1024), source, config_name)),
        member_probe_bytes=_require_int(_IntRequirement(policy, 'member_probe_bytes', (512, 16 * 1024 * 1024), source, config_name)),
        member_text_max_size=_require_int(_IntRequirement(policy, 'member_text_max_size', (1024, 128 * 1024 * 1024), source, config_name)),
        ecosystem_score_limit=_require_int(_IntRequirement(policy, 'ecosystem_score_limit', (1, 1000000), source, config_name)),
        ecosystem_score_warn=_require_int(_IntRequirement(policy, 'ecosystem_score_warn', (1, 1000000), source, config_name)),
        rpa_read_max_bytes=_require_int(_IntRequirement(policy, 'rpa_read_max_bytes', (1024, 128 * 1024 * 1024), source, config_name)),
        rpa_index_max_bytes=_require_int(_IntRequirement(policy, 'rpa_index_max_bytes', (1024, 128 * 1024 * 1024), source, config_name)),
        rpa_member_max_bytes=_require_int(_IntRequirement(policy, 'rpa_member_max_bytes', (1024, 128 * 1024 * 1024), source, config_name)),
        rpa_member_max_count=_require_int(_IntRequirement(policy, 'rpa_member_max_count', (1, 100000), source, config_name)),
        rpa_zip_max_depth=_require_int(_IntRequirement(policy, 'rpa_zip_max_depth', (0, 32), source, config_name)),
        rpa_zip_max_members=_require_int(_IntRequirement(policy, 'rpa_zip_max_members', (1, 100000), source, config_name)),
        rpa_zip_max_member_size=_require_int(_IntRequirement(policy, 'rpa_zip_max_member_size', (1024, 2 * 1024 * 1024 * 1024), source, config_name)),
        nested_archive_suffixes=_require_str_tuple(_StringTupleRequirement(policy, 'nested_archive_suffixes', (1, 64), source, config_name)),
        rarity_high_risk_probability=_require_float(_FloatRequirement(policy, "rarity_high_risk_probability", (0.0, 1.0), source, config_name)),
        rarity_high_risk_min_score=_require_float(_FloatRequirement(policy, "rarity_high_risk_min_score", (0.0, 1000.0), source, config_name)),
        rarity_high_risk_multiplier=_require_float(_FloatRequirement(policy, "rarity_high_risk_multiplier", (0.0, 1000.0), source, config_name)),
        rarity_rare_probability=_require_float(_FloatRequirement(policy, "rarity_rare_probability", (0.0, 1.0), source, config_name)),
        rarity_rare_multiplier=_require_float(_FloatRequirement(policy, "rarity_rare_multiplier", (0.0, 1000.0), source, config_name)),
        rarity_uncommon_probability=_require_float(_FloatRequirement(policy, "rarity_uncommon_probability", (0.0, 1.0), source, config_name)),
        rarity_uncommon_multiplier=_require_float(_FloatRequirement(policy, "rarity_uncommon_multiplier", (0.0, 1000.0), source, config_name)),
        rarity_common_probability=_require_float(_FloatRequirement(policy, "rarity_common_probability", (0.0, 1.0), source, config_name)),
        rarity_common_multiplier=_require_float(_FloatRequirement(policy, "rarity_common_multiplier", (0.0, 1000.0), source, config_name)),
        rarity_default_multiplier=_require_float(_FloatRequirement(policy, "rarity_default_multiplier", (0.0, 1000.0), source, config_name)),
        source=str(Path(source)),
    )

__all__ = (
    "validate_archive_policy",
)
