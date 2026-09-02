"""Profile-specific detection policy dispatch ownership.

Generic detection modules call this bounded profile owner instead of importing
engine-specific profile implementations directly.  Engine-specific modules remain
under their owning profile packages.
"""

from Virus_Scan.detection.profiles.renpy.updater import (
    apply_renpy_updater_baseline,
    renpy_updater_behavior_abuse_tags,
    renpy_updater_has_hard_anchor,
    suppress_renpy_bytecode_noise,
)


def apply_profile_updater_baseline(tags: object, path: object=None, strings_blob: object="") -> object:
    """Apply profile-owned updater baseline policy for the active file context."""
    return apply_renpy_updater_baseline(tags, path=path, strings_blob=strings_blob)


def profile_updater_behavior_abuse_tags(path: object=None, strings_blob: object="") -> object:
    """Return profile-owned updater abuse tags for the active file context."""
    return renpy_updater_behavior_abuse_tags(path=path, strings_blob=strings_blob)


def suppress_profile_bytecode_noise(tags: object, path: object=None, strings_blob: object="") -> object:
    """Apply profile-owned bytecode noise suppression for the active file context."""
    return suppress_renpy_bytecode_noise(tags, path=path, strings_blob=strings_blob)


def profile_updater_has_hard_anchor(tags: object=None, strings_blob: object="", path: object=None) -> object:
    """Return whether profile-owned updater logic sees hard malicious proof."""
    return renpy_updater_has_hard_anchor(tags=tags, strings_blob=strings_blob, path=path)


__all__ = (
    'apply_profile_updater_baseline',
    'profile_updater_behavior_abuse_tags',
    'profile_updater_has_hard_anchor',
    'suppress_profile_bytecode_noise',
)
