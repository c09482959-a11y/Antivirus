"""RPG Maker detection profile ownership."""

from Virus_Scan.detection.profiles.contracts import DetectionProfileSnapshot


DETECTION_PROFILE = DetectionProfileSnapshot(
    name="rpgm",
    aliases=("rpgmaker", "rpg_maker", "rpgmaker_mv", "rpgmaker_mz"),
    tag_markers=frozenset(("rpgm", "nwjs", "node_runtime", "rpgm_js", "rpgmaker")),
    file_extensions=frozenset((".rpgmvp", ".rpgmvo", ".rpgmvm", ".json", ".js")),
    baseline_suppression_profile="rpgm",
    selected_engine_context_key="rpgm",
)


__all__ = ("DETECTION_PROFILE",)
