"""Unity detection profile ownership."""

from Virus_Scan.detection.profiles.contracts import DetectionProfileSnapshot


DETECTION_PROFILE = DetectionProfileSnapshot(
    name="unity",
    aliases=("unity_engine", "unity_game"),
    tag_markers=frozenset(("unity", "unity_engine", "unity_asset", "managed_dotnet", "il2cpp", "unityplayer")),
    file_extensions=frozenset((".assets", ".asset", ".bundle", ".dll", ".exe")),
    baseline_suppression_profile="unity",
    selected_engine_context_key="unity",
)


__all__ = ("DETECTION_PROFILE",)
