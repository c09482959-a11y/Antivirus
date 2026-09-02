"""Centralized heuristic registries used by scanner collectors.

Scanner modules should collect context and call these evaluators instead of
duplicating suspicious primitive families.
"""
from .script_exec import evaluate_script_execution, SCRIPT_EXEC_PATTERNS
from .pickle_exec import evaluate_pickle_execution, PICKLE_EXEC_PATTERNS
from .downloader_patterns import evaluate_downloader_behavior, DOWNLOADER_PATTERNS
from .obfuscation import evaluate_obfuscation, OBFUSCATION_PATTERNS
from .game_engine_threats import evaluate_game_engine_threats, GameThreatHit

__all__ = (
    "DOWNLOADER_PATTERNS",
    "OBFUSCATION_PATTERNS",
    "PICKLE_EXEC_PATTERNS",
    "SCRIPT_EXEC_PATTERNS",
    "GameThreatHit",
    "evaluate_downloader_behavior",
    "evaluate_game_engine_threats",
    "evaluate_obfuscation",
    "evaluate_pickle_execution",
    "evaluate_script_execution",
)
