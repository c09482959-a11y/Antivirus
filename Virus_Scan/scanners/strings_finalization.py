"""Scanner-owned raw string-tag normalization helper."""

from Virus_Scan.utils.tagging import normalize_tags


def normalize_string_tags(tags: object, path: object = None, strings_blob: object = '', source: object = 'strings') -> object:
    """Return deterministic scanner-owned raw string tags."""
    del path, source, strings_blob  # Explicitly unused contract parameters.
    return normalize_tags(tags or [])


__all__ = ('normalize_string_tags',)
