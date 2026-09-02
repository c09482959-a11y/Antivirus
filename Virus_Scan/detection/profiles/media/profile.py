"""Media detection profile ownership."""

from Virus_Scan.detection.profiles.contracts import DetectionProfileSnapshot


DETECTION_PROFILE = DetectionProfileSnapshot(
    name="media",
    aliases=("asset_media", "image_audio_video"),
    tag_markers=frozenset(("media", "image_payload_confirmed", "stego_payload_suspect", "audio_play", "image_load")),
    file_extensions=frozenset((".png", ".jpg", ".jpeg", ".gif", ".webp", ".ogg", ".wav", ".mp3", ".mp4", ".webm")),
    baseline_suppression_profile="media",
    selected_engine_context_key="media",
)


__all__ = ("DETECTION_PROFILE",)
