"""Scanner-owned image LSB analysis and gated payload extraction."""
from __future__ import annotations


from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import report_scan_stage_progress, log_error
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join, scanner_contract_lower_token, scanner_contract_text, scanner_failure_evidence_tags
from Virus_Scan.scanners.image_bits import bits_to_bytes as _umige_bits_to_bytes
from Virus_Scan.scanners.image_bits import image_is_jpeg as _image_is_jpeg
from Virus_Scan.scanners.image_limits import (
    IMAGE_STEGO_MAX_PIXELS,
    IMAGE_STEGO_RESIZE_SAMPLE_MAX_SIDE,
    IMAGE_STEGO_SAMPLE_PIXELS,
)
from Virus_Scan.scanners.image_lsb_payload import (
    append_confirmed_lsb_payload_tags,
    append_decoded_lsb_payload_tags,
    decoded_lsb_payload_behavior_tags,
    has_lsb_trigger_tags,
    lsb_payload_magic_or_needle_hit,
)


class _UnavailableImageModule:
    """Explicit optional-dependency sentinel for Pillow-backed LSB scanning."""

    available = False
    dependency = "Pillow"

    def open(self, path: object) -> object:
        del path
        raise ImportError("pillow_unavailable")


try:
    from PIL import Image as _PILImageModule
except ImportError:
    Image: object = _UnavailableImageModule()
else:
    Image = _PILImageModule

_MAX_EXTRACT_BITS = 262144 * 8
_PROGRESS_BIT_INTERVAL = 131072
_PIXEL_PROGRESS_INTERVAL = 16384


def _lsb_channel_limit(mode: str) -> int:
    return 1 if mode in ("L", "P") else 3


def _prepare_lsb_sample(img: object, tags: list[str], *, record_resize: bool) -> tuple[object | None, int]:
    width, height = img.size
    pixels = int(width) * int(height)
    if pixels <= 0:
        return None, pixels
    if record_resize and pixels > IMAGE_STEGO_MAX_PIXELS:
        tags.append("image_stego_scan_skipped_large_image")
        return None, pixels
    sample = img
    if pixels > IMAGE_STEGO_SAMPLE_PIXELS:
        sample = img.copy()
        sample.thumbnail((IMAGE_STEGO_RESIZE_SAMPLE_MAX_SIDE, IMAGE_STEGO_RESIZE_SAMPLE_MAX_SIDE))
        tags.append("image_stego_sampled_resize")
    if sample.mode not in ("RGB", "RGBA", "L", "P"):
        sample = sample.convert("RGBA")
    elif sample.mode == "P" and record_resize:
        tags.append("palette_image")
    return sample, pixels


def _collect_lsb_stats(sample_img: object) -> tuple[int, float, float]:
    ones = 0
    total = 0
    transitions = 0
    prev = None
    channel_limit = _lsb_channel_limit(sample_img.mode)
    for px in sample_img.getdata():
        vals = px if isinstance(px, tuple) else (px,)
        for value in vals[:channel_limit]:
            bit = int(value) & 1
            ones += bit
            total += 1
            if prev is not None and bit != prev:
                transitions += 1
            prev = bit
        if total and total % _PIXEL_PROGRESS_INTERVAL == 0:
            report_scan_stage_progress("image_lsb_pixels", bytes_delta=total)
    if total < 2048:
        return total, 0.0, 0.0
    return total, ones / float(total), transitions / float(max(1, total - 1))


def _is_statistical_lsb_anomaly(total: int, ratio: float, transition_ratio: float) -> bool:
    balanced_short = 0.485 <= ratio <= 0.515 and transition_ratio >= 0.485
    balanced_large = total >= 100000 and abs(ratio - 0.5) <= 0.003
    return balanced_short or balanced_large


def _collect_lsb_bits(sample_img: object) -> list[int]:
    bits: list[int] = []
    channel_limit = _lsb_channel_limit(sample_img.mode)
    for px in sample_img.getdata():
        vals = px if isinstance(px, tuple) else (px,)
        for value in vals[:channel_limit]:
            bits.append(int(value) & 1)
            if len(bits) >= _MAX_EXTRACT_BITS:
                break
        if len(bits) > 0 and len(bits) % _PROGRESS_BIT_INTERVAL == 0:
            report_scan_stage_progress("image_lsb_extract_bits", bytes_delta=len(bits) // 8)
        if len(bits) >= _MAX_EXTRACT_BITS:
            break
    return bits


def scan_pillow_lsb(path: object, tags: object, data: object = None) -> bool:
    """Pillow-backed pixel LSB heuristics. PNG/BMP/GIF only; JPEG LSB is unreliable."""
    suspicious = False
    try:
        report_scan_stage_progress("image_lsb_open")
        if _image_is_jpeg(data=data, path=path, read_path=True):
            tags.append("jpeg_lsb_check_suppressed")
            return False
        with Image.open(path) as img:
            report_scan_stage_progress("image_lsb_header")
            tags += ["pillow_image_opened", scanner_contract_join("image_mode_", scanner_contract_lower_token(img.mode, replacement="unknown"))]
            sample_img, pixels = _prepare_lsb_sample(img, tags, record_resize=True)
            if sample_img is None or pixels <= 0:
                return False
            total, ratio, transition_ratio = _collect_lsb_stats(sample_img)
            if total >= 2048 and _is_statistical_lsb_anomaly(total, ratio, transition_ratio):
                tags += ["lsb_statistical_anomaly", "stego_statistical_anomaly"]
                suspicious = True
    except (OSError, ValueError) as exc:
        tags.extend(scanner_failure_evidence_tags(
            "image", "pillow_lsb_decode", exc,
            ["image_decode_failed", "malformed_image_input"],
            input_path=path, state="malformed", error_category="malformed_image",
        ))
        suspicious = bool(suspicious)
    except SCAN_CONTENT_ERRORS as exc:
        log_error(scanner_contract_join("Pillow LSB stego scan failed for ", scanner_contract_text(path, replacement=""), ": ", scanner_contract_error_message(exc)))
        tags.extend(scanner_failure_evidence_tags(
            "image", "pillow_lsb_scan", exc, ["image_stego_scan_error"],
            input_path=path, state="degraded", error_category="image_stego_scan_failure",
        ))
    return suspicious


def extract_lsb_payload_gated(path: object, tags: object, data: object = None) -> bool:
    """Gated image stego extraction with explicit payload decode evidence."""
    suspicious = False
    try:
        report_scan_stage_progress("image_lsb_extract_start")
        if _image_is_jpeg(data=data, path=path, read_path=True) or not has_lsb_trigger_tags(tags):
            return False
        with Image.open(path) as img:
            sample_img, _pixels = _prepare_lsb_sample(img, tags, record_resize=False)
            if sample_img is None:
                return False
            extracted = _umige_bits_to_bytes(_collect_lsb_bits(sample_img))
        if not extracted or len(extracted) < 64:
            return False
        if lsb_payload_magic_or_needle_hit(extracted):
            append_confirmed_lsb_payload_tags(tags)
            suspicious = True
        decoded_tags = decoded_lsb_payload_behavior_tags(extracted)
        if decoded_tags:
            append_decoded_lsb_payload_tags(tags, decoded_tags)
            suspicious = True
    except (OSError, ValueError) as exc:
        tags.extend(scanner_failure_evidence_tags(
            "image", "lsb_payload_decode", exc,
            ["image_decode_failed", "malformed_image_input"],
            input_path=path, state="malformed", error_category="malformed_image",
        ))
        suspicious = bool(suspicious)
    except SCAN_CONTENT_ERRORS as exc:
        try:
            log_error(scanner_contract_join("gated LSB extraction failed for ", scanner_contract_text(path, replacement=""), ": ", scanner_contract_error_message(exc)))
        except SCAN_CONTENT_ERRORS as log_exc:
            record_suppressed_failure("suppressed_exception", log_exc, domain="runtime")
        tags.extend(scanner_failure_evidence_tags(
            "image", "lsb_payload_extract", exc, ["image_lsb_payload_extract_error"],
            input_path=path, state="degraded", error_category="image_stego_extract_failure",
        ))
    return suspicious


__all__ = ("extract_lsb_payload_gated", "scan_pillow_lsb")
