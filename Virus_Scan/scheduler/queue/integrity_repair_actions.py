"""Bounded queue identity repair actions for queue integrity verification."""
from Virus_Scan.scheduler.queue.integrity_record_support import (
    identity_text,
    queue_identity_records,
    queue_record_mapping,
)


def identity_is_invalid(ident: object) -> bool:
    ident_text = ident if type(ident) is str else ""
    return ident_text.startswith(("invalid:", "file_incomplete:", "raw_incomplete:"))


def active_record_is_protected(
    record: dict[str, object],
    *,
    active_claim_is_protected: object,
    now: object,
) -> bool:
    if dict.get(record, "state") != "active":
        return False
    return bool(active_claim_is_protected(dict.get(record, "path"), job=dict.get(record, "job"), now=now))


def actionable_invalid_records(
    items: tuple[object, ...],
    *,
    active_claim_is_protected: object,
    now: object,
) -> tuple[dict[str, object], ...]:
    actionable: list[dict[str, object]] = []
    for item_value in items:
        record = queue_record_mapping(item_value)
        if active_record_is_protected(record, active_claim_is_protected=active_claim_is_protected, now=now):
            continue
        actionable.append(record)
    return tuple(actionable)


def quarantine_invalid_records(
    records: tuple[dict[str, object], ...],
    *,
    ident: object,
    quarantine_job: object,
) -> int:
    quarantined = 0
    for record in records:
        path = dict.__getitem__(record, "path")
        if quarantine_job(path, reason="invalid_queue_identity", job=dict.get(record, "job"), identity=ident):
            quarantined += 1
            continue
        raise RuntimeError("invalid queue identity quarantine failed: " + identity_text(ident))
    return quarantined


def state_rank_value(record: dict[str, object], *, active_claim_is_protected: object, now: object) -> object:
    state = dict.get(record, "state")
    if active_record_is_protected(record, active_claim_is_protected=active_claim_is_protected, now=now):
        return "active_protected"
    return state


def duplicate_rank_key(record: dict[str, object], *, active_claim_is_protected: object, now: object) -> tuple[int, str]:
    state_rank = {"done": 0, "active_protected": 1, "active": 2, "pending": 3, "failed": 4}
    state = state_rank_value(record, active_claim_is_protected=active_claim_is_protected, now=now)
    name = dict.get(record, "name")
    name_text = name if type(name) is str else identity_text(name)
    return (dict.get(state_rank, state, 9), name_text)


def sorted_duplicate_records(
    items: tuple[object, ...],
    *,
    active_claim_is_protected: object,
    now: object,
) -> tuple[dict[str, object], ...]:
    records = tuple(queue_record_mapping(item_value) for item_value in items)
    return tuple(
        sorted(
            records,
            key=lambda record: duplicate_rank_key(
                record,
                active_claim_is_protected=active_claim_is_protected,
                now=now,
            ),
        )
    )


def quarantine_duplicate_records(
    records: tuple[dict[str, object], ...],
    *,
    ident: object,
    active_claim_is_protected: object,
    quarantine_job: object,
    now: object,
) -> int:
    keep = records[0]
    quarantined = 0
    for duplicate_record in records[1:]:
        if active_record_is_protected(duplicate_record, active_claim_is_protected=active_claim_is_protected, now=now):
            continue
        keep_state = dict.get(keep, "state")
        keep_state_text = keep_state if type(keep_state) is str else identity_text(keep_state)
        if quarantine_job(dict.__getitem__(duplicate_record, "path"), reason="duplicate_queue_identity_keep_" + keep_state_text, job=dict.get(duplicate_record, "job"), identity=ident):
            quarantined += 1
            continue
        raise RuntimeError("duplicate queue identity quarantine failed: " + identity_text(ident))
    return quarantined


def process_invalid_identity_group(
    summary: dict[str, object],
    items: tuple[object, ...],
    *,
    ident: object,
    repair: bool,
    active_claim_is_protected: object,
    quarantine_job: object,
    now: object,
) -> None:
    records = actionable_invalid_records(items, active_claim_is_protected=active_claim_is_protected, now=now)
    summary["invalid"] += len(records)
    if repair:
        summary["quarantined"] += quarantine_invalid_records(records, ident=ident, quarantine_job=quarantine_job)


def process_duplicate_identity_group(
    summary: dict[str, object],
    items: tuple[object, ...],
    *,
    ident: object,
    repair: bool,
    active_claim_is_protected: object,
    quarantine_job: object,
    now: object,
) -> None:
    summary["duplicates"] += len(items) - 1
    if not repair:
        return
    records = sorted_duplicate_records(items, active_claim_is_protected=active_claim_is_protected, now=now)
    summary["quarantined"] += quarantine_duplicate_records(
        records,
        ident=ident,
        active_claim_is_protected=active_claim_is_protected,
        quarantine_job=quarantine_job,
        now=now,
    )


def process_identity_group(
    summary: dict[str, object],
    ident: object,
    items_value: object,
    *,
    repair: bool,
    active_claim_is_protected: object,
    quarantine_job: object,
    now: object,
) -> None:
    items = queue_identity_records(items_value)
    if identity_is_invalid(ident):
        process_invalid_identity_group(
            summary,
            items,
            ident=ident,
            repair=repair,
            active_claim_is_protected=active_claim_is_protected,
            quarantine_job=quarantine_job,
            now=now,
        )
        return
    if len(items) <= 1:
        return
    process_duplicate_identity_group(
        summary,
        items,
        ident=ident,
        repair=repair,
        active_claim_is_protected=active_claim_is_protected,
        quarantine_job=quarantine_job,
        now=now,
    )
