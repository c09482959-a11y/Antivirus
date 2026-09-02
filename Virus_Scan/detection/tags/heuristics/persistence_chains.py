"""Persistence-oriented behavior-chain detectors."""

from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags


def detect_scheduled_task_persistence(tags: object) -> object:
    """Scheduled-task detector with schtasks/scheduled_task alias support."""
    tagset = set(normalize_tags(tags))
    score = 0.0
    hits = []
    if {'schtasks', 'schtasks_create', 'scheduled_task'} & tagset:
        score += 8.0
        hits.append('schtasks persistence')
    if 'at_exec' in tagset or 'at.exe' in tagset:
        score += 6.0
        hits.append('at task scheduling')
    if 'delayed_execution' in tagset:
        score += 4.0
        hits.append('delayed execution staging')
    if 'scheduled_task' in tagset and 'process_exec' in tagset:
        score += 6.0
        hits.append('scheduled execution chain')
    return (score, sorted(set(hits)))


__all__ = ('detect_scheduled_task_persistence',)
