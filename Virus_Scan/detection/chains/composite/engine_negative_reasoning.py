"""Game-engine negative reasoning over atomic evidence categories."""

from Virus_Scan.detection.chains.composite.behavior_taxonomy import (
    BLOCKCHAIN_ABUSE_TAGS,
    BLOCKCHAIN_REPORT_ONLY_TAGS,
    COMMAND_OBSERVATION_TAGS,
    CREDENTIAL_OBSERVATION_TAGS,
    DOWNLOAD_OBSERVATION_TAGS,
    EXECUTION_OBSERVATION_TAGS,
    EXFILTRATION_OBSERVATION_TAGS,
    GAME_ENGINE_WEAK_TEXT_ENCODED_TAGS,
    INJECTION_OBSERVATION_TAGS,
    PERSISTENCE_OBSERVATION_TAGS,
)

_GAME_ENGINE_CONTEXT_TAGS = frozenset({
    "renpy", "rpgm", "unity_engine", "unity_asset", "nwjs", "node_runtime",
})
_CONCRETE_OBSERVATION_TAGS = frozenset().union(
    EXECUTION_OBSERVATION_TAGS,
    COMMAND_OBSERVATION_TAGS,
    EXFILTRATION_OBSERVATION_TAGS,
    PERSISTENCE_OBSERVATION_TAGS,
    CREDENTIAL_OBSERVATION_TAGS,
    INJECTION_OBSERVATION_TAGS,
)
_NETWORK_OBSERVATION_TAGS = frozenset().union(
    COMMAND_OBSERVATION_TAGS,
    DOWNLOAD_OBSERVATION_TAGS,
    EXFILTRATION_OBSERVATION_TAGS,
)


def _text_set(value: object) -> frozenset[str]:
    if type(value) not in (tuple, list, set, frozenset):
        return frozenset()
    raw = tuple(value) if type(value) in (tuple, list) else tuple(sorted(value))
    return frozenset(
        str.__str__(item).strip().lower()
        for item in raw[:512]
        if type(item) is str and str.__str__(item).strip()
    )


def game_engine_context(tags: object) -> bool:
    return bool(_text_set(tags) & _GAME_ENGINE_CONTEXT_TAGS)


def game_engine_negative_reasoning(report_set: object, score_set: object) -> list[str]:
    report_tags = _text_set(report_set)
    score_tags = _text_set(score_set)
    if not game_engine_context(report_tags):
        return []
    notes: list[str] = []
    if report_tags & GAME_ENGINE_WEAK_TEXT_ENCODED_TAGS and not score_tags & _CONCRETE_OBSERVATION_TAGS:
        notes.append("negative_reasoning:game_engine_encoded_text_or_asset_support_only")
    reference_tags = {"url_present", "reference_url", "asset_resource_fetch", "browser_xhr_fetch"}
    if report_tags & reference_tags and not score_tags & _NETWORK_OBSERVATION_TAGS:
        notes.append("negative_reasoning:game_engine_reference_url_or_asset_fetch_support_only")
    if report_tags & BLOCKCHAIN_REPORT_ONLY_TAGS and not score_tags & BLOCKCHAIN_ABUSE_TAGS:
        notes.append("negative_reasoning:game_engine_blockchain_display_or_api_reference_only")
    return notes


__all__ = ("game_engine_context", "game_engine_negative_reasoning")
