import math
from typing import Iterable, List, Mapping, TypedDict

from Virus_Scan.utils.stages import MEDIA_AUDIO_EXTENSIONS, sanitize_tag_part as _umige_sanitize_tag_part

_IMAGE_RECOVERY_TAGS = frozenset({
    "rpgm_recovered_magic_png",
    "rpgm_recovered_magic_jpeg",
    "rpgm_recovered_magic_gif",
    "rpgm_recovered_magic_webp",
})


def exact_magic_boundary_text(value: object) -> str:
    if isinstance(value, str):
        return str.__str__(value)
    if type(value) is bytes:
        return bytes(value).decode("utf-8", "replace")
    if type(value) is bytearray:
        return bytes(value).decode("utf-8", "replace")
    return ""


def _magic_tag_items_with_reason(tags: Iterable[object]) -> tuple[tuple[object, ...], str | None]:
    if tags is None:
        return (), None
    if type(tags) in (str, bytes, bytearray):
        return (tags,), None
    if type(tags) in (tuple, list, set, frozenset):
        return tuple(tags), None
    return (), "routing_magic_tags_rejected"


def _magic_tag_texts_with_reason(tags: Iterable[object]) -> tuple[frozenset[str], str | None]:
    items, reason = _magic_tag_items_with_reason(tags)
    return frozenset(text for tag in items if (text := exact_magic_boundary_text(tag)) != ""), reason


def _magic_tag_texts(tags: Iterable[object]) -> frozenset[str]:
    tag_texts, _reason = _magic_tag_texts_with_reason(tags)
    return tag_texts


def _has_rpgm_image_recovery_tag(tags: Iterable[object]) -> bool:
    return bool(_magic_tag_texts(tags) & _IMAGE_RECOVERY_TAGS)


class RpgmPassiveRecoveryRecord(TypedDict):
    recovered: bool
    tag_texts: frozenset[str]
    unavailable_reasons: Mapping[str, str]


def rpgm_passive_recovery_record(ext: str, ext_stage: str, magic_type: str, tags: Iterable[object]) -> RpgmPassiveRecoveryRecord:
    tag_texts, tags_reason = _magic_tag_texts_with_reason(tags)
    ext_text = exact_magic_boundary_text(ext)
    ext_stage_text = exact_magic_boundary_text(ext_stage)
    magic_type_text = exact_magic_boundary_text(magic_type)
    unavailable_reasons = {}
    if tags_reason is not None:
        unavailable_reasons["tags"] = tags_reason
    image_recovered = ext_stage_text == "image" and (
        "rpgm_encrypted_image" in tag_texts or bool(tag_texts & _IMAGE_RECOVERY_TAGS)
    )
    audio_recovered = ext_text in MEDIA_AUDIO_EXTENSIONS and "rpgm_encrypted_audio" in tag_texts
    recovered = (
        magic_type_text == "rpgm_mv_encrypted_asset"
        and "rpgm_encrypted_asset" in tag_texts
        and (image_recovered or audio_recovered)
    )
    return {
        "recovered": recovered,
        "tag_texts": tag_texts,
        "unavailable_reasons": dict(unavailable_reasons),
    }


def is_rpgm_passive_recovered(ext: str, ext_stage: str, magic_type: str, tags: Iterable[object]) -> bool:
    return rpgm_passive_recovery_record(ext, ext_stage, magic_type, tags)["recovered"]


def _sanitize_magic_tag_part(value: object) -> str:
    text = exact_magic_boundary_text(value)
    return _umige_sanitize_tag_part(text if text != "" else "unknown")


def _exact_magic_score(value: object) -> int:
    if type(value) is bool:
        return 0
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value) and value.is_integer():
        return int(value)
    return 0


def _exact_magic_score_text(value: object) -> str:
    return str(int.__str__(_exact_magic_score(value)))


def apply_extension_consistency_tags(tags: List[str], ext_stage: str, magic_stage: str, *, rpgm_recovered: bool) -> None:
    ext_stage_text = exact_magic_boundary_text(ext_stage) or "unknown"
    magic_stage_text = exact_magic_boundary_text(magic_stage) or "unknown"
    if magic_stage_text not in ("unknown", ext_stage_text):
        if rpgm_recovered is True:
            tags += ["extension_consistent", "rpgm_encrypted_wrapper_consistent"]
        elif ext_stage_text not in {"unknown", "other"}:
            tags += ["extension_mismatch", str.__add__("actual_stage_", magic_stage_text), str.__add__("claimed_stage_", ext_stage_text)]
        else:
            tags += ["extension_untrusted", str.__add__("actual_stage_", magic_stage_text)]
    else:
        tags += ["extension_consistent"]


def apply_magic_mismatch_tags(tags: List[str], ext: str, magic_type: str, *, mismatch: bool, rpgm_recovered: bool) -> None:
    if rpgm_recovered is not True and mismatch is True:
        tags += [
            "extension_magic_type_mismatch",
            "extension_mismatch",
            str.__add__("claimed_ext_", _sanitize_magic_tag_part(ext)),
            str.__add__("actual_magic_", _sanitize_magic_tag_part(magic_type)),
        ]


def apply_filetype_category_tags(
    tags: List[str],
    claimed_category: str,
    actual_category: str,
    misclassification_score: int,
    misclassification_severity: str,
) -> None:
    claimed_text = exact_magic_boundary_text(claimed_category)
    actual_text = exact_magic_boundary_text(actual_category)
    rejected_input = False
    if claimed_text == "" and claimed_category is not None:
        claimed_text = "unknown"
        rejected_input = True
    if actual_text == "" and actual_category is not None:
        actual_text = "unknown"
        rejected_input = True
    if not rejected_input and (claimed_text == "unknown" or actual_text == "unknown"):
        return
    tags += [
        str.__add__("claimed_filetype_", _sanitize_magic_tag_part(claimed_text)),
        str.__add__("actual_filetype_", _sanitize_magic_tag_part(actual_text)),
    ]
    if rejected_input:
        tags += ["filetype_category_input_rejected"]
    score = _exact_magic_score(misclassification_score)
    if score > 0:
        tags += [
            "filetype_misclassification",
            str.__add__("filetype_misclassification_", _sanitize_magic_tag_part(misclassification_severity)),
            str.__add__("filetype_misclassification_score_", _exact_magic_score_text(score)),
        ]
    else:
        tags += ["extension_magic_confirmed", "filetype_claim_confirmed"]
