"""Scanner-owned raw string collector merge contract."""

from dataclasses import dataclass

from Virus_Scan.utils.tagging import normalize_tags


PLR2004N4 = 4

@dataclass(frozen=True, slots=True)
class StringCollectorMergeResult:
    tags: tuple[str, ...]
    meta: tuple[object, ...] = ()
    suspicious: tuple[object, ...] = ()
    errors: tuple[object, ...] = ()

    def as_tuple(self) -> object:
        return (list(self.tags), list(self.meta), list(self.suspicious), list(self.errors))


def _merge_item(item: object, tags: object, meta: object, suspicious: object, errors: object) -> object:
    if item is None:
        return
    if hasattr(item, 'as_tuple'):
        t, m, s, e = item.as_tuple()
        tags.extend(t or [])
        meta.extend(m or [])
        suspicious.extend(s or [])
        errors.extend(e or [])
        return
    if isinstance(item, dict):
        tags.extend(item.get('tags') or [])
        meta.extend(item.get('meta') or [])
        suspicious.extend(item.get('suspicious') or [])
        errors.extend(item.get('errors') or item.get('failure_evidence') or [])
        return
    if isinstance(item, tuple) and len(item) == PLR2004N4:
        t, m, s, e = item
        tags.extend(t or [])
        meta.extend(m or [])
        suspicious.extend(s or [])
        errors.extend(e or [])
        return
    if isinstance(item, (list, tuple, set)):
        tags.extend(item)
        return
    tags.append(str(item))


def merge_stage_collector_results(results: object) -> object:
    tags = []
    meta = []
    suspicious = []
    errors = []
    for item in results or []:
        _merge_item(item, tags, meta, suspicious, errors)
    return StringCollectorMergeResult(tuple(normalize_tags(tags)), tuple(meta), tuple(suspicious), tuple(errors))


__all__ = ('StringCollectorMergeResult', 'merge_stage_collector_results')
