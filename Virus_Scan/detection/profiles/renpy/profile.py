"""Ren'Py detection profile ownership."""

from Virus_Scan.detection.profiles.contracts import DetectionProfileSnapshot


DETECTION_PROFILE = DetectionProfileSnapshot(
    name="renpy",
    aliases=("renpy_engine", "renpy_game"),
    tag_markers=frozenset(("renpy", "renpy_script", "renpy_bytecode", "renpy_dialogue", "renpy_label")),
    file_extensions=frozenset((".rpy", ".rpyc", ".rpyb", ".rpa")),
    baseline_suppression_profile="renpy",
    selected_engine_context_key="renpy",
)


__all__ = ("DETECTION_PROFILE",)
