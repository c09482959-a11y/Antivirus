"""Scanner-owned API regex and group policy boundary for text analysis."""

import re
from types import MappingProxyType

from Virus_Scan.contracts.api_behavior import canonical_api_text
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scanners.text_policy import API_GROUPS as _POLICY_API_GROUPS


def _freeze_api_groups(api_groups: object) -> object:
    frozen = {}
    for group, apis in no_hook_mapping_items(api_groups, allow_dict_subclass=True) or ():
        frozen[canonical_api_text(group)] = tuple(canonical_api_text(api) for api in no_hook_sequence_items(apis))
    return MappingProxyType(frozen)


API_GROUPS = _freeze_api_groups(_POLICY_API_GROUPS)


def build_api_regex(api_groups: object = None) -> object:
    """Build a compiled regex from the schema-validated scanner API policy."""
    source = API_GROUPS if api_groups is None else _freeze_api_groups(api_groups)
    all_apis = set()
    for _group, apis in no_hook_mapping_items(source) or ():
        all_apis.update(canonical_api_text(api) for api in apis)
    pattern = r'\b(' + '|'.join(re.escape(api) for api in sorted(all_apis) if api) + r')\b'
    return re.compile(pattern, re.IGNORECASE)


API_REGEX = build_api_regex()


def map_api_to_group(api: object) -> object:
    """Return the scanner-visible behavioral group for a concrete API name."""
    api_name = canonical_api_text(api)
    api_low = api_name.lower()
    for group, apis in no_hook_mapping_items(API_GROUPS) or ():
        if api_name in apis or api_low in {canonical_api_text(item).lower() for item in apis}:
            return group
    return 'unknown'


__all__ = (
    'API_GROUPS',
    'API_REGEX',
    'build_api_regex',
    'map_api_to_group',
)
