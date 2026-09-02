"""Runtime model baseline parsing support.

This support owner materializes persisted transition, tag, pair, and filetype
baseline records for :mod:`Virus_Scan.runtime.model_state` without owning the
runtime mutation maps themselves.
"""
from __future__ import annotations

from collections import Counter
from typing import Mapping

from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
    MARKOV_EVENT_KEY_TYPE,
    MARKOV_EVENT_VOCABULARY_KEY_TYPE,
    MARKOV_STAGE_KEY_TYPE,
    MARKOV_STAGE_VOCABULARY_KEY_TYPE,
)

from Virus_Scan.runtime.model_state_support import (
    _runtime_model_count,
    _runtime_model_count_with_reason,
    _runtime_model_display_text,
    _runtime_model_dot_path,
    _runtime_model_expected_name,
    _runtime_model_failure,
    _runtime_model_index_path,
    _runtime_model_join_text,
    _runtime_model_mapping_get,
    _runtime_model_matches_expected,
    _runtime_model_nonempty_text,
    _runtime_model_owned_mapping_get,
    _runtime_model_owned_mapping_items,
    _runtime_model_sequence_values,
    _runtime_model_sorted_items,
    _runtime_transition_row_error,
)

_RUNTIME_MODEL_SECTION_MISSING = object()

def _runtime_model_load_section(
    source: Mapping[str, object],
    name: str,
    expected: object,
    default: object,
    failures: list[dict[str, str]],
) -> tuple[object, bool]:
    raw = _runtime_model_mapping_get(
        source, name, _RUNTIME_MODEL_SECTION_MISSING
    )
    if raw is _RUNTIME_MODEL_SECTION_MISSING or raw is None:
        return default, False
    if _runtime_model_matches_expected(raw, expected):
        return raw, True
    failures.append(
        _runtime_model_failure(
            name,
            _runtime_model_join_text("non_", _runtime_model_expected_name(expected), "_runtime_model_section"),
        )
    )
    return default, False

def _runtime_model_parse_transition_rows(
    rows: object, failures: list[dict[str, str]]
) -> tuple[dict[object, Counter], int, int, bool]:
    prepared: dict[object, Counter] = {}
    loaded = 0
    skipped = 0
    corrupt = False
    for index, row in enumerate(_runtime_model_sequence_values(rows)):
        if _runtime_model_owned_mapping_items(row) is None:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_index_path("transition_counts", index),
                    "non_mapping_runtime_transition_row",
                )
            )
            continue
        raw_count = _runtime_model_mapping_get(row, "count", 0)
        count, reason = _runtime_model_count_with_reason(raw_count)
        if reason:
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_index_path("transition_counts", index, ".count"),
                    reason,
                    raw_count,
                )
            )
        row_error = _runtime_transition_row_error(row)
        if row_error:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_index_path("transition_counts", index), row_error
                )
            )
            continue
        if count <= 0:
            skipped += 1
            continue
        key = runtime_transition_key_from_json(row)
        target = _runtime_model_nonempty_text(
            _runtime_model_mapping_get(row, "target", "unknown")
        )
        counter = prepared.setdefault(key, Counter())
        counter[target] = _runtime_model_count(
            _runtime_model_owned_mapping_get(counter, target, 0)
        ) + count
        loaded += 1
    return prepared, loaded, skipped, not corrupt or loaded > 0

def _runtime_model_parse_tag_baseline(
    section: object, failures: list[dict[str, str]]
) -> tuple[dict[str, int], int, int, bool]:
    prepared: dict[str, int] = {}
    loaded = 0
    skipped = 0
    corrupt = False
    for key, value in _runtime_model_sorted_items(section):
        key_text = _runtime_model_nonempty_text(key)
        if not key_text:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    "global_tag_baseline.<empty>",
                    "invalid_runtime_tag_key",
                    key,
                )
            )
            continue
        count, reason = _runtime_model_count_with_reason(value)
        if reason:
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_dot_path("global_tag_baseline", key_text), reason, value
                )
            )
        if count <= 0:
            skipped += 1
            continue
        prepared[key_text] = count
        loaded += 1
    return prepared, loaded, skipped, not corrupt or loaded > 0

def _runtime_model_parse_pair_rows(
    rows: object, failures: list[dict[str, str]]
) -> tuple[dict[tuple[str, str], int], int, int, bool]:
    prepared: dict[tuple[str, str], int] = {}
    loaded = 0
    skipped = 0
    corrupt = False
    for index, row in enumerate(_runtime_model_sequence_values(rows)):
        if _runtime_model_owned_mapping_items(row) is None:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_index_path("global_tag_pair_baseline", index),
                    "non_mapping_runtime_pair_row",
                )
            )
            continue
        raw_count = _runtime_model_mapping_get(row, "count", 0)
        count, reason = _runtime_model_count_with_reason(raw_count)
        if reason:
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_index_path("global_tag_pair_baseline", index, ".count"),
                    reason,
                    raw_count,
                )
            )
        left = _runtime_model_nonempty_text(
            _runtime_model_mapping_get(row, "a")
        )
        right = _runtime_model_nonempty_text(
            _runtime_model_mapping_get(row, "b")
        )
        if not left or not right:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_index_path("global_tag_pair_baseline", index),
                    "invalid_runtime_pair_row_key",
                )
            )
            continue
        if count <= 0:
            skipped += 1
            continue
        prepared[(left, right)] = count
        loaded += 1
    return prepared, loaded, skipped, not corrupt or loaded > 0

def _runtime_model_parse_filetypes(
    section: object, failures: list[dict[str, str]]
) -> tuple[dict[str, Counter], int, int, bool]:
    prepared: dict[str, Counter] = {}
    loaded = 0
    skipped = 0
    corrupt = False
    for extension, raw_counter in _runtime_model_sorted_items(section):
        extension_text = _runtime_model_nonempty_text(extension)
        if not extension_text:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    "filetype_baseline.<empty>",
                    "invalid_runtime_filetype_key",
                    extension,
                )
            )
            continue
        if _runtime_model_owned_mapping_items(raw_counter) is None:
            skipped += 1
            corrupt = True
            failures.append(
                _runtime_model_failure(
                    _runtime_model_dot_path("filetype_baseline", extension_text),
                    "non_mapping_runtime_filetype_counter",
                )
            )
            continue
        counter: Counter[str] = Counter()
        extension_corrupt = False
        for tag, value in _runtime_model_sorted_items(raw_counter):
            tag_text = _runtime_model_nonempty_text(tag)
            if not tag_text:
                skipped += 1
                corrupt = extension_corrupt = True
                failures.append(
                    _runtime_model_failure(
                        _runtime_model_join_text("filetype_baseline.", extension_text, ".<empty>"),
                        "invalid_runtime_filetype_tag_key",
                        tag,
                    )
                )
                continue
            count, reason = _runtime_model_count_with_reason(value)
            if reason:
                corrupt = extension_corrupt = True
                failures.append(
                    _runtime_model_failure(
                        _runtime_model_join_text("filetype_baseline.", extension_text, ".", tag_text),
                        reason,
                        value,
                    )
                )
            if count <= 0:
                skipped += 1
                continue
            counter[tag_text] = count
            loaded += 1
        if counter:
            prepared[extension_text] = counter
        elif not extension_corrupt:
            skipped += 1
    return prepared, loaded, skipped, not corrupt or loaded > 0


def runtime_transition_key_from_json(item: Mapping[str, object] | object) -> object:
    """Materialize one already-validated canonical v2 Markov transition key."""
    row = item if _runtime_model_owned_mapping_items(item) is not None else {}
    typ = _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "type", ""))
    if typ == MARKOV_EVENT_KEY_TYPE:
        return (
            MARKOV_EVENT_KEY_TYPE,
            (
                _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "context")),
                _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "previous_stage")),
                _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "source_event")),
            ),
        )
    if typ == MARKOV_STAGE_KEY_TYPE:
        return (
            MARKOV_STAGE_KEY_TYPE,
            (
                _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "context")),
                _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "previous_stage")),
                _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "flow_class")),
            ),
        )
    if typ in {
        MARKOV_CONTEXT_SUPPORT_KEY_TYPE,
        MARKOV_EVENT_VOCABULARY_KEY_TYPE,
        MARKOV_STAGE_VOCABULARY_KEY_TYPE,
    }:
        return (
            typ,
            _runtime_model_nonempty_text(_runtime_model_mapping_get(row, "context")),
        )
    raise ValueError("invalid runtime Markov transition type")
