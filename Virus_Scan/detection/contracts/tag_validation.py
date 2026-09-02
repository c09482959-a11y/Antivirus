"""Canonical normalize ownership for tag validation."""

from dataclasses import dataclass

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.contracts.string_predicates import is_renpy_bytecode_path, validate_high_risk_tag
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.utils.text_validation import text_boundary_value
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    ordered_unique_tags,
)

BROAD_UNVALIDATED_TAGS = frozenset(
    detection_registry_value(
        "BROAD_UNVALIDATED_TAGS",
        frozenset({"network_activity", "url_present", "reference_url", "encoded_data_context", "payload_decode_candidate", "packed_or_obfuscated", "high_entropy_packed"}),
    )
)
PICKLE_GRAPH_PROTECTED_TAGS = frozenset(
    detection_registry_value(
        "PICKLE_GRAPH_PROTECTED_TAGS",
        frozenset({"pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode", "pickle_external_executable_reference"}),
    )
)
PICKLE_GRAPH_PROOF_TAGS = frozenset(
    detection_registry_value(
        "PICKLE_GRAPH_PROOF_TAGS",
        frozenset({"pickle_opcode_graph_analyzed", "pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode"}),
    )
)
RPYC_HIGH_RISK_TAGS = frozenset(
    detection_registry_value(
        "RPYC_HIGH_RISK_TAGS",
        frozenset({"pickle_dangerous_global", "pickle_callable_reference", "pickle_reduce_opcode", "pickle_deserialization_context"}),
    )
)


@dataclass(frozen=True, slots=True)
class _TagValidationContext:
    is_rpyc: bool
    pickle_graph_proven: bool
    source_text: str
    strings_blob: object
    path: object


def _validation_failure_markers(validated: list[str]) -> None:
    validated.append(TAG_NORMALIZATION_FAILURE_EVIDENCE)
    validated.append('tag_validation_failure_evidence')
    validated.append(DETECTION_STAGE_DEGRADED_TAG)


def _iter_validation_tags(tags: object) -> object:
    if tags is None:
        return iter(())
    if type(tags) is tuple:
        return iter(tags)
    if type(tags) is list:
        return iter(tuple(tags))
    if type(tags) in (set, frozenset):
        return iter(tuple(sorted(tags, key=lambda value: _validation_exact_text(value) or "")))
    return None


def _validation_exact_text(value: object) -> object:
    return text_boundary_value(value, unsupported=None)


def _validation_tag_text(tag: object) -> object:
    text = _validation_exact_text(tag)
    if text is None:
        return None
    return text.strip()


def _validation_source_text(source: object) -> object:
    text = _validation_exact_text(source)
    if text is None:
        return ''
    return text.strip().lower()


def _readable_validation_tags(tags: object, validated: list[str]) -> object:
    tag_values = _iter_validation_tags(tags)
    if tag_values is None:
        _validation_failure_markers(validated)
        return None
    readable_tags: list[str] = []
    while True:
        try:
            tag = next(tag_values)
        except StopIteration:
            break
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            _validation_failure_markers(validated)
            break
        text = _validation_tag_text(tag)
        if text is None:
            _validation_failure_markers(validated)
        elif text:
            readable_tags.append(text)
    return readable_tags


def _pickle_graph_is_proven(is_rpyc: bool, all_lows: set[str]) -> bool:
    graph_analyzed = "pickle_opcode_graph_analyzed" in all_lows
    dangerous_callable = bool(
        all_lows & {"pickle_dangerous_global", "pickle_callable_reference"}
    )
    reduce_observed = "pickle_reduce_opcode" in all_lows
    return is_rpyc and graph_analyzed and dangerous_callable and reduce_observed


def _tag_passes_validation(tag: str, context: _TagValidationContext) -> bool:
    low = tag.lower()
    if context.pickle_graph_proven and low in PICKLE_GRAPH_PROTECTED_TAGS:
        return True
    if context.is_rpyc and low in RPYC_HIGH_RISK_TAGS and not validate_high_risk_tag(low, context.strings_blob, context.path):
        return False
    if low in BROAD_UNVALIDATED_TAGS and context.source_text in {'raw', 'binary', 'strings', 'router'} and not validate_high_risk_tag(low, context.strings_blob, context.path):
        return False
    return bool(validate_high_risk_tag(low, context.strings_blob, context.path))


def _append_validated_tags(readable_tags: list[str], context: _TagValidationContext, validated: list[str]) -> None:
    for tag in readable_tags:
        try:
            if _tag_passes_validation(tag, context):
                validated.append(tag)
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            validated.append(tag)
            _validation_failure_markers(validated)


def validate_tags_for_path(tags: object, path: object=None, strings_blob: object='', source: object='') -> object:
    """Validate high-risk tags before normalization/reporting/scoring."""
    validated: list[str] = []
    readable_tags = _readable_validation_tags(tags, validated)
    if readable_tags is None:
        return ordered_unique_tags(validated)
    is_rpyc = is_renpy_bytecode_path(path)
    all_lows = {tag.lower() for tag in readable_tags}
    context = _TagValidationContext(
        is_rpyc=is_rpyc,
        pickle_graph_proven=_pickle_graph_is_proven(is_rpyc, all_lows),
        source_text=_validation_source_text(source),
        strings_blob=strings_blob,
        path=path,
    )
    _append_validated_tags(readable_tags, context, validated)
    return ordered_unique_tags(validated)
