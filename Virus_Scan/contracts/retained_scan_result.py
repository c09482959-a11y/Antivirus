"""Integrity-protected compressed scheduler results retained until publication."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import math
import zlib


RETAINED_RESULT_CONTRACT_FIELD = "__umige_retained_result_contract__"
RETAINED_RESULT_PUBLICATION_FIELD = "__umige_retained_publication_zlib_b64__"
RETAINED_RESULT_REPLAY_FIELD = "__umige_parent_replay_payload_zlib_b64__"
RETAINED_RESULT_SCHEMA = "scheduler_retained_result_v2"
RETAINED_RESULT_COMPRESSION = "zlib_base64_v1"
_MAX_PUBLICATION_BYTES = 1_048_576
_MAX_REPLAY_BYTES = 262_144
_MAX_TREE_ITEMS = 20_000
_MAX_TREE_DEPTH = 32
_COMPRESSED_OVERHEAD_BYTES = 65_536
_CONTRACT_KEYS = frozenset({
    "schema_version",
    "compression",
    "publication_sha256",
    "replay_sha256",
    "publication_bytes",
    "replay_bytes",
    "publication_compressed_sha256",
    "replay_compressed_sha256",
    "publication_compressed_bytes",
    "replay_compressed_bytes",
})
_RETAINED_KEYS = frozenset({
    RETAINED_RESULT_CONTRACT_FIELD,
    RETAINED_RESULT_PUBLICATION_FIELD,
    RETAINED_RESULT_REPLAY_FIELD,
})


@dataclass(frozen=True, slots=True)
class RetainedScanResult:
    """Validated public compact record and deferred parent-replay payload."""

    publication: dict[str, object]
    replay_payload: dict[str, object] | None


def retained_result_marker_present(value: object) -> bool:
    return type(value) is dict and RETAINED_RESULT_CONTRACT_FIELD in value


def _validate_json_tree(value: object, *, depth: int, counter: list[int]) -> None:
    if depth > _MAX_TREE_DEPTH:
        raise ValueError("retained_result_tree_depth_exceeded")
    counter[0] += 1
    if counter[0] > _MAX_TREE_ITEMS:
        raise ValueError("retained_result_tree_items_exceeded")
    value_type = type(value)
    if value is None or value_type in {bool, int, str}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("retained_result_nonfinite_float")
        return
    if value_type in {list, tuple}:
        for item in value:
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    if value_type is dict:
        for key, item in dict.items(value):
            if type(key) is not str:
                raise TypeError("retained_result_non_string_key")
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    raise TypeError("retained_result_unsupported_type:" + value_type.__name__)


def _canonical_json_bytes(value: object, *, maximum_bytes: int, label: str) -> bytes:
    _validate_json_tree(value, depth=0, counter=[0])
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise ValueError(label + "_bytes_exceeded")
    return encoded


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _maximum_compressed_bytes(maximum_bytes: int) -> int:
    return maximum_bytes + _COMPRESSED_OVERHEAD_BYTES


def _maximum_base64_characters(maximum_bytes: int) -> int:
    maximum_compressed = _maximum_compressed_bytes(maximum_bytes)
    return 4 * ((maximum_compressed + 2) // 3)


def _compressed_payload(encoded: bytes, *, maximum_bytes: int, label: str) -> tuple[str, bytes]:
    compressed = zlib.compress(encoded, level=6)
    if len(compressed) > _maximum_compressed_bytes(maximum_bytes):
        raise ValueError(label + "_compressed_bytes_exceeded")
    return base64.b64encode(compressed).decode("ascii"), compressed


def _validated_contract(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError("retained_result_contract_exact_dict_required")
    if frozenset(dict.keys(value)) != _CONTRACT_KEYS:
        raise ValueError("retained_result_contract_field_set_invalid")
    if dict.get(value, "schema_version") != RETAINED_RESULT_SCHEMA:
        raise ValueError("retained_result_contract_schema_invalid")
    if dict.get(value, "compression") != RETAINED_RESULT_COMPRESSION:
        raise ValueError("retained_result_contract_compression_invalid")
    for key in (
        "publication_sha256",
        "replay_sha256",
        "publication_compressed_sha256",
        "replay_compressed_sha256",
    ):
        digest = dict.get(value, key)
        if type(digest) is not str or len(digest) != 64:
            raise ValueError("retained_result_contract_digest_invalid:" + key)
    for key in (
        "publication_bytes",
        "replay_bytes",
        "publication_compressed_bytes",
        "replay_compressed_bytes",
    ):
        size = dict.get(value, key)
        if type(size) is not int or type(size) is bool or size < 0:
            raise ValueError("retained_result_contract_size_invalid:" + key)
    if dict.get(value, "publication_bytes") > _MAX_PUBLICATION_BYTES:
        raise ValueError("retained_result_contract_publication_bytes_exceeded")
    if dict.get(value, "replay_bytes") > _MAX_REPLAY_BYTES:
        raise ValueError("retained_result_contract_replay_bytes_exceeded")
    if dict.get(value, "publication_compressed_bytes") > _maximum_compressed_bytes(_MAX_PUBLICATION_BYTES):
        raise ValueError("retained_result_contract_publication_compressed_bytes_exceeded")
    if dict.get(value, "replay_compressed_bytes") > _maximum_compressed_bytes(_MAX_REPLAY_BYTES):
        raise ValueError("retained_result_contract_replay_compressed_bytes_exceeded")
    return value


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str:
            raise TypeError("retained_result_json_non_string_key")
        if key in result:
            raise ValueError("retained_result_json_duplicate_key:" + key)
        dict.__setitem__(result, key, item)
    return result


def _reject_nonfinite_constant(value: str) -> object:
    raise ValueError("retained_result_json_nonfinite_constant:" + value)


def _strict_json_value(encoded: bytes, *, maximum_bytes: int, label: str) -> object:
    if len(encoded) > maximum_bytes:
        raise ValueError(label + "_bytes_exceeded")
    try:
        text = encoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(label + "_utf8_invalid") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("retained_result_"):
            raise
        raise ValueError(label + "_json_invalid") from exc


def _decoded_compressed_payload(
    value: object,
    *,
    contract: dict[str, object],
    maximum_bytes: int,
    label: str,
) -> object:
    if type(value) is not str:
        raise TypeError(label + "_base64_exact_str_required")
    if len(value) > _maximum_base64_characters(maximum_bytes):
        raise ValueError(label + "_base64_characters_exceeded")
    try:
        encoded_text = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(label + "_base64_ascii_invalid") from exc
    try:
        compressed = base64.b64decode(encoded_text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(label + "_base64_invalid") from exc
    expected_compressed_size = dict.get(contract, label + "_compressed_bytes")
    if len(compressed) != expected_compressed_size:
        raise ValueError(label + "_compressed_size_mismatch")
    expected_compressed_digest = dict.get(contract, label + "_compressed_sha256")
    if _sha256(compressed) != expected_compressed_digest:
        raise ValueError(label + "_compressed_digest_mismatch")
    try:
        decompressor = zlib.decompressobj()
        decoded = decompressor.decompress(compressed, maximum_bytes + 1)
    except zlib.error as exc:
        raise ValueError(label + "_compressed_payload_invalid") from exc
    if len(decoded) > maximum_bytes:
        raise ValueError(label + "_bytes_exceeded")
    if not decompressor.eof or decompressor.unconsumed_tail or decompressor.unused_data:
        raise ValueError(label + "_compressed_stream_invalid")
    expected_size = dict.get(contract, label + "_bytes")
    if len(decoded) != expected_size:
        raise ValueError(label + "_size_mismatch")
    expected_digest = dict.get(contract, label + "_sha256")
    if _sha256(decoded) != expected_digest:
        raise ValueError(label + "_digest_mismatch")
    materialized = _strict_json_value(decoded, maximum_bytes=maximum_bytes, label=label)
    canonical = _canonical_json_bytes(materialized, maximum_bytes=maximum_bytes, label=label)
    if canonical != decoded:
        raise ValueError(label + "_canonical_json_mismatch")
    return materialized


def build_retained_scan_result(
    publication: object,
    replay_payload: object,
) -> dict[str, object]:
    """Create the one current compressed bounded retained-result schema."""
    if type(publication) is not dict:
        raise TypeError("retained_result_publication_exact_dict_required")
    if any(field in publication for field in _RETAINED_KEYS):
        raise ValueError("retained_result_private_field_collision")
    if replay_payload is not None and type(replay_payload) is not dict:
        raise TypeError("retained_result_replay_exact_dict_or_none_required")
    publication_bytes = _canonical_json_bytes(
        publication,
        maximum_bytes=_MAX_PUBLICATION_BYTES,
        label="retained_result_publication",
    )
    replay_bytes = _canonical_json_bytes(
        replay_payload,
        maximum_bytes=_MAX_REPLAY_BYTES,
        label="retained_result_replay",
    )
    publication_payload, publication_compressed = _compressed_payload(
        publication_bytes,
        maximum_bytes=_MAX_PUBLICATION_BYTES,
        label="retained_result_publication",
    )
    replay_payload_text, replay_compressed = _compressed_payload(
        replay_bytes,
        maximum_bytes=_MAX_REPLAY_BYTES,
        label="retained_result_replay",
    )
    return {
        RETAINED_RESULT_CONTRACT_FIELD: {
            "schema_version": RETAINED_RESULT_SCHEMA,
            "compression": RETAINED_RESULT_COMPRESSION,
            "publication_sha256": _sha256(publication_bytes),
            "replay_sha256": _sha256(replay_bytes),
            "publication_bytes": len(publication_bytes),
            "replay_bytes": len(replay_bytes),
            "publication_compressed_sha256": _sha256(publication_compressed),
            "replay_compressed_sha256": _sha256(replay_compressed),
            "publication_compressed_bytes": len(publication_compressed),
            "replay_compressed_bytes": len(replay_compressed),
        },
        RETAINED_RESULT_PUBLICATION_FIELD: publication_payload,
        RETAINED_RESULT_REPLAY_FIELD: replay_payload_text,
    }


def validate_retained_scan_result(value: object) -> RetainedScanResult:
    """Validate integrity and return detached retained-result components."""
    if type(value) is not dict:
        raise TypeError("retained_result_exact_dict_required")
    if frozenset(dict.keys(value)) != _RETAINED_KEYS:
        raise ValueError("retained_result_field_set_invalid")
    contract = _validated_contract(dict.get(value, RETAINED_RESULT_CONTRACT_FIELD))
    publication_value = _decoded_compressed_payload(
        dict.get(value, RETAINED_RESULT_PUBLICATION_FIELD),
        contract=contract,
        maximum_bytes=_MAX_PUBLICATION_BYTES,
        label="publication",
    )
    replay_value = _decoded_compressed_payload(
        dict.get(value, RETAINED_RESULT_REPLAY_FIELD),
        contract=contract,
        maximum_bytes=_MAX_REPLAY_BYTES,
        label="replay",
    )
    if type(publication_value) is not dict:
        raise TypeError("retained_result_publication_materialization_failed")
    if replay_value is not None and type(replay_value) is not dict:
        raise TypeError("retained_result_replay_materialization_failed")
    return RetainedScanResult(
        publication=publication_value,
        replay_payload=replay_value,
    )


def retained_publication_record(value: object) -> dict[str, object]:
    return validate_retained_scan_result(value).publication


def retained_parent_replay_payload(value: object) -> dict[str, object] | None:
    return validate_retained_scan_result(value).replay_payload


__all__ = (
    "RETAINED_RESULT_COMPRESSION",
    "RETAINED_RESULT_CONTRACT_FIELD",
    "RETAINED_RESULT_PUBLICATION_FIELD",
    "RETAINED_RESULT_REPLAY_FIELD",
    "RETAINED_RESULT_SCHEMA",
    "RetainedScanResult",
    "build_retained_scan_result",
    "retained_parent_replay_payload",
    "retained_publication_record",
    "retained_result_marker_present",
    "validate_retained_scan_result",
)
