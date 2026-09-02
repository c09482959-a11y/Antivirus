"""Scanner-owned text context helpers for file-type and engine context."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.scanners.text_policy import GAME_ENGINE_CONTEXT_TAGS, PASSIVE_TEXTUAL_CATEGORIES

_CONTEXT_ENGINES = frozenset(("unity", "renpy", "rpgm", "media"))


def _context_empty_scores() -> dict[str, object]:
    scores: dict[str, object] = dict.fromkeys(_CONTEXT_ENGINES, 0.0)
    scores["unknown"] = 0.0
    return scores


def _engine_hint_to_context(engine: object) -> object:
    engine_text, engine_reason = no_hook_text(
        engine,
        missing_reason="missing_context_engine_hint",
        unsupported_reason="unsafe_context_engine_hint_rejected",
    )
    engine_text = "auto" if engine_reason else engine_text.strip().lower()
    if engine_reason and engine_reason != "missing_context_engine_hint":
        ctx = _context_empty_scores()
        ctx["context_unavailable_reason"] = engine_reason
        ctx["context_unavailable_type"] = no_hook_type_name(engine)
        return ctx
    if engine_text in _CONTEXT_ENGINES:
        ctx = _context_empty_scores()
        ctx[engine_text] = 1.0
        return ctx
    if engine_text == "other":
        ctx = _context_empty_scores()
        ctx["unknown"] = 1.0
        return ctx
    return {}


def _filetype_claim_matches_actual(claimed: object, actual: object, magic_type: object = "") -> object:
    claimed_text, claimed_reason = no_hook_text(
        claimed,
        missing_reason="missing_claimed_filetype",
        unsupported_reason="unsafe_claimed_filetype_rejected",
    )
    actual_text, actual_reason = no_hook_text(
        actual,
        missing_reason="missing_actual_filetype",
        unsupported_reason="unsafe_actual_filetype_rejected",
    )
    magic_text, magic_reason = no_hook_text(
        magic_type,
        missing_reason="missing_magic_type",
        unsupported_reason="unsafe_magic_type_rejected",
    )
    claimed_text = "unknown" if claimed_reason else claimed_text.strip().lower()
    actual_text = "unknown" if actual_reason else actual_text.strip().lower()
    magic_text = "" if magic_reason else magic_text.strip().lower()
    if claimed_reason or actual_reason or magic_reason:
        return False
    if claimed_text == actual_text:
        return True
    if claimed_text in PASSIVE_TEXTUAL_CATEGORIES and actual_text in PASSIVE_TEXTUAL_CATEGORIES:
        return True
    if claimed_text == "unity_asset" and actual_text == "archive" and magic_text == "zip":
        return False
    return False


def _game_engine_context(report_set: object) -> object:
    normalized = normalize_tags(report_set)
    tagset = frozenset(tag.lower() for tag in normalized if type(tag) is str)
    return bool(tagset & GAME_ENGINE_CONTEXT_TAGS)


__all__ = (
    "_engine_hint_to_context",
    "_filetype_claim_matches_actual",
    "_game_engine_context",
)
