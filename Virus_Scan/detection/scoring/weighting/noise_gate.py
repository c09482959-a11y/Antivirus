"""Score-gate policy boundary for detection outputs.

Kept deliberately small: this isolates score-cap vocabulary from tag vocabulary
and from scheduler/runtime economics.
"""
from __future__ import annotations
from typing import Iterable

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_sequence_items,
    no_hook_text,
)


def noise_gate_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="noise_gate_text_missing",
        unsupported_reason="noise_gate_text_rejected",
    )
    if reason:
        return ""
    return text.strip().lower()


def noise_gate_text_set(values: object) -> set[str]:
    out: set[str] = set()
    for value in no_hook_sequence_items(values):
        text = noise_gate_text(value)
        if text:
            out.add(text)
    return out


def noise_gate_score(value: object) -> float:
    score, _reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="noise_gate_score_rejected",
        non_finite_reason="noise_gate_score_non_finite",
        allow_exact_text=True,
    )
    return score


def noise_gate_count(value: object) -> int:
    count, _reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason="noise_gate_count_rejected",
        non_finite_reason="noise_gate_count_non_finite",
        allow_exact_text=True,
    )
    return count


def cap_noise_only_score(score: float, normalized_tags: Iterable[str], scoreable_tags: Iterable[str], *, stage: object = None, concrete_count: int = 0) -> float:
    norm = noise_gate_text_set(normalized_tags)
    scoreable = noise_gate_text_set(scoreable_tags)
    bounded_concrete_count = noise_gate_count(concrete_count)
    entropy = bool(norm & {"high_entropy_packed", "very_high_entropy", "high_entropy_sections", "possible_packed_or_encrypted_blob", "possible_xor_encoded_blob"}) and bounded_concrete_count <= 1
    asset = noise_gate_text(stage) in {"asset", "image", "audio", "font", "archive"}
    weak_stego = bool(norm & {"stego_statistical_anomaly", "lsb_statistical_anomaly", "stego_candidate_observation", "jpeg_lsb_check_suppressed", "image_metadata_url_reference", "image_metadata_encoded_reference"}) and not bool(norm & {"image_payload_confirmed", "image_appended_payload", "embedded_payload_after_eof", "embedded_executable_or_command", "high_confidence_image_payload"})
    base = noise_gate_score(score)
    if asset and weak_stego:
        return min(base, 12.0)
    if asset and entropy:
        return min(base, 18.0)
    if entropy and not ({"memory_write", "thread_execution", "network_download", "certutil_exec", "powershell_exec"} & scoreable):
        return min(base, 28.0)
    return base
