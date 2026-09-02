"""Detection-owned heuristic evaluators."""
from Virus_Scan.detection.heuristics.downloader import DOWNLOADER_PATTERNS, evaluate_downloader_behavior
from Virus_Scan.detection.heuristics.game_engine_threats import GameThreatHit, evaluate_game_engine_threats

__all__ = (
    "DOWNLOADER_PATTERNS",
    "GameThreatHit",
    "evaluate_downloader_behavior",
    "evaluate_game_engine_threats",
)
