"""Detection-owned cluster feature tag extraction from scanner-observed text views."""

from __future__ import annotations


from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.contracts.string_extraction import build_extraction_view

_BEHAVIOR_NEEDLES = (
    ("exec", ("exec(", "eval(", "subprocess", "powershell", "cmd.exe", "child_process")),
    ("network", ("http://", "https://", "socket", "requests.post", "webhook")),
    ("inject", ("virtualalloc", "writeprocessmemory", "createremotethread")),
    ("persist", ("currentversion\\run", "schtasks", "startup")),
)
_BINARY_MAGIC_NEEDLES = ("mz\x00", "pk\x03\x04", "%pdf", "\x7felf")
_DECODE_CONTEXT_NEEDLES = (
    "base64", "frombase64string", "atob(", "buffer.from", "encodedcommand",
    "payload_decode_candidate", "decoded_payload_rescanned", "decoded_",
)


def _cluster_decoded_behavior_tag(name: str) -> str:
    return "cluster_decoded_behavior_" + str.__str__(name)


def decode_feature_tags_for_cluster(strings_blob: object, decoded_payloads: object = None) -> list[str]:
    """Bounded decoded/timeline features for vector clustering; no scoring side effects.

    Scanner-owned extraction supplies decoded payload text in the extraction view.
    Detection only converts that observed text into clustering features.
    """
    features: list[str] = []
    try:
        text = build_extraction_view(strings_blob, decoded_payloads=decoded_payloads)[:65536].lower()
        if not text:
            return []
        has_decode_context = any(needle in text for needle in _DECODE_CONTEXT_NEEDLES)
        behavior_hit = False
        for name, needles in _BEHAVIOR_NEEDLES:
            if any(needle in text for needle in needles):
                behavior_hit = True
                features.append(_cluster_decoded_behavior_tag(name))
        if has_decode_context or behavior_hit:
            features.append("cluster_decoded_base64")
        if any(needle in text for needle in _BINARY_MAGIC_NEEDLES):
            features.append("cluster_decoded_binary_payload")
    except RECOVERABLE_RUNTIME_ERRORS:
        return features
    return sorted(set(features))


__all__ = ("decode_feature_tags_for_cluster",)
