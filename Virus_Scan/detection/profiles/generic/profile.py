"""Generic detection profile ownership."""

from Virus_Scan.detection.profiles.contracts import DetectionProfileSnapshot


DETECTION_PROFILE = DetectionProfileSnapshot(
    name="other",
    aliases=("generic", "unknown"),
    tag_markers=frozenset(("generic", "other")),
    file_extensions=frozenset(()),
    baseline_suppression_profile="other",
    selected_engine_context_key="other",
)


__all__ = ("DETECTION_PROFILE",)
