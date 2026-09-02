"""Ren'Py official updater identity policy."""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.detection.profiles.renpy.updater_constants import RENPY_UPDATER_FILENAMES
from Virus_Scan.detection.profiles.renpy.updater_text import profile_text_or_empty
from Virus_Scan.utils.text_validation import tag_validation_text


def is_renpy_official_updater_path(path: object=None, strings_blob: object='') -> object:
    """Detection-local Ren'Py updater path classifier without shared-state hydration."""
    path_text = profile_text_or_empty(path)
    name = Path(path_text).name.lower() if path_text else ''
    parts = {x.lower() for x in Path(path_text).parts} if path_text else set()
    text = tag_validation_text(strings_blob)
    if name not in RENPY_UPDATER_FILENAMES:
        return False
    if 'renpy' in parts or 'common' in parts:
        return True
    return bool(
        'tom rothamel' in text
        and ('class updater' in text or 'zsync' in text or 'zsync_path' in text)
        and ('downloadneeded' in text or 'requests' in text or 'tarfile' in text or 'zsync_update' in text)
    )


__all__ = ('is_renpy_official_updater_path',)
