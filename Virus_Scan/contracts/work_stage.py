"""Work-stage ownership contracts.

Routing owns WorkStage classification; scheduler owns capacity mapping.  This file
is the shared import-light vocabulary, not a policy implementation sink.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_text

@dataclass(frozen=True)
class WorkStageCapacityClass:
    name: str
    default_limit: int
    weight: float = 1.0

CAPACITY_CLASSES: Mapping[str, WorkStageCapacityClass] = MappingProxyType({
    'archive': WorkStageCapacityClass('archive', 2, 8.0),
    'dotnet': WorkStageCapacityClass('dotnet', 1, 10.0),
    'yara': WorkStageCapacityClass('yara', 2, 6.0),
    'image': WorkStageCapacityClass('image', 3, 1.0),
    'raw': WorkStageCapacityClass('raw', 4, 4.0),
    'script': WorkStageCapacityClass('script', 4, 3.0),
    'generic': WorkStageCapacityClass('generic', 8, 1.0),
    'model': WorkStageCapacityClass('model', 2, 5.0),
    'reporting': WorkStageCapacityClass('reporting', 1, 2.0),
})


def _stage_text(value: object, default: str) -> str:
    text, reason = no_hook_text(value, missing_reason="missing_stage", unsupported_reason="unsafe_stage_value_rejected")
    if reason or not text:
        return default
    return str.__str__(text).lower()


def capacity_for_stage(stage: str) -> WorkStageCapacityClass:
    return CAPACITY_CLASSES.get(_stage_text(stage, 'generic'), CAPACITY_CLASSES['generic'])


STAGE_CODES = MappingProxyType({
    'start': 1,
    'stage_budget': 2,
    'yara': 10,
    'image': 20,
    'archive': 30,
    'dotnet': 40,
    'raw': 50,
    'scan': 60,
    'complete': 90,
})

_STAGE_NAMES_BY_CODE = MappingProxyType({
    1: 'start',
    2: 'stage_budget',
    10: 'yara',
    20: 'image',
    30: 'archive',
    40: 'dotnet',
    50: 'raw',
    60: 'scan',
    90: 'complete',
})


_STAGE_CODE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("start", "assign"), "start"),
    (("budget", "admission"), "stage_budget"),
    (("yara",), "yara"),
    (("image", "png", "stego", "pil"), "image"),
    (("archive", "extract", "rpa"), "archive"),
    (("ilspy", "dotnet", "dncil"), "dotnet"),
    (("raw", "decode", "string"), "raw"),
    (("complete", "done"), "complete"),
)


def stage_code(stage: str) -> int:
    text = _stage_text(stage, 'scan')
    code_name = "scan"
    for needles, candidate_name in _STAGE_CODE_RULES:
        if any(needle in text for needle in needles):
            code_name = candidate_name
            break
    return STAGE_CODES[code_name]


def stage_name_from_code(code: int) -> str:
    if type(code) is bool:
        return 'scan'
    if type(code) is int:
        target = code
    else:
        text, reason = no_hook_text(code, unsupported_reason="unsafe_stage_code_rejected")
        if reason:
            return 'scan'
        try:
            target = int(str.__str__(text).strip())
        except (TypeError, ValueError, OverflowError):
            return 'scan'
    stage_name = _STAGE_NAMES_BY_CODE.get(target)
    if stage_name is not None:
        return stage_name
    return 'stage_' + int.__str__(target)
