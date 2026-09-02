"""Profile extension-baseline mutation owners; this module does not import ``profiles.api``."""

from Virus_Scan.contracts.tag_evidence import (
    dangerous_anchor_learning_block_enabled,
    tag_evidence_records,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.models.profiles.vector_statistics import update_profile_vector_statistics
from Virus_Scan.models.profiles.baseline import ensure_extension_model_fields, profile_tag_behavior_bucket
from Virus_Scan.models.profiles.extension_learning_context import (
    apply_extension_learning_rejection,
    normalize_extension_learning_inputs,
    prepare_extension_baseline,
    resolve_extension_learning_key,
)
from Virus_Scan.models.contracts.learning_authority import learning_authorization_failure
from Virus_Scan.models.profiles.persistence import profile_ext_lock, profile_update_marker
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection
from Virus_Scan.utils.counters import increment_counter
from Virus_Scan.models.profiles.extension_state_learning import (
    learn_extension_chains,
    update_extension_risk_baseline,
    update_extension_timeline_baseline,
)
from Virus_Scan.models.profiles.profile_tag_learning import (
    learn_profile_tag_evidence,
    learnable_profile_tag_evidence,
    profile_dangerous_root_ids,
)

CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS = dangerous_anchor_learning_block_enabled()


def learn_extension_tags(extension_baseline: object, tags: object) -> None:
    """Learn canonical evidence and expose a deterministic string projection."""
    ensure_extension_model_fields(extension_baseline)
    extension_baseline.setdefault('dangerous_anchor_observations', {})
    original_bundle, original_roots, _root_tags, _correlation_group_count, reason = (
        profile_tag_evidence_projection(tags, 'malformed_profile_behavior_bucket_tags')
    )
    if reason is not None:
        extension_baseline['tags'] = {}
        return
    dangerous_roots = profile_dangerous_root_ids(original_roots, CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS)
    for record in original_roots:
        if record.root_observation_id in dangerous_roots:
            increment_counter(
                extension_baseline['dangerous_anchor_observations'],
                record.publication_name,
            )
    safe_records = tuple(
        record for record in tag_evidence_records(original_bundle.records)
        if record.root_observation_id not in dangerous_roots
    )
    learn_profile_tag_evidence(
        extension_baseline, TagEvidence.from_records(safe_records),
    )


def update_behavior_bucket_learning(extension_baseline: object, tags: object, strings_blob: object='', api_calls: object=None, ordered_events: object=None) -> object:
    """Update profile buckets and persisted provenance from distinct roots."""
    del strings_blob, api_calls, ordered_events
    ensure_extension_model_fields(extension_baseline)
    extension_baseline.setdefault('tags', {})
    tag_evidence, root_records, unavailable_reason = learnable_profile_tag_evidence(tags, CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS)
    if unavailable_reason:
        return {
            'updated': False,
            'degraded': True,
            'unavailable_reason': unavailable_reason,
            'final_json_must_record': True,
            'replay_record_required': True,
            'tags': (),
        }
    updated_tags = []
    for record in root_records:
        low = record.publication_name
        bucket = profile_tag_behavior_bucket(low)
        bucket_state = extension_baseline['behavior_buckets'].setdefault(
            bucket, {'files': 0, 'tags': {}, 'evidence': {}},
        )
        increment_counter(bucket_state.setdefault('tags', {}), low)
        increment_counter(bucket_state.setdefault('evidence', {}), record.evidence_kind)
        updated_tags.append({
            'tag': low,
            'bucket': bucket,
            'evidence': record.evidence_kind,
            'evidence_id': record.evidence_id,
            'root_observation_id': record.root_observation_id,
        })
    learn_profile_tag_evidence(extension_baseline, tag_evidence)
    return {
        'updated': len(updated_tags) > 0,
        'tags': tuple(tuple(sorted(dict.items(row))) for row in updated_tags),
        'tag_evidence_summary': dict(tag_evidence.summary),
        'tag_evidence_kinds_consumed': (
            'observed', 'normalized', 'derived', 'composite',
        ),
    }

def _apply_accepted_extension_learning(
    baseline: object, context: object, profile_vector: object, diversity_key: str,
) -> None:
    baseline['files'] += 1
    for bucket in {profile_tag_behavior_bucket(record.publication_name) for record in profile_tag_evidence_projection(context['tag_evidence'])[1]}:
        baseline['behavior_buckets'].setdefault(bucket, {'files': 0, 'tags': {}, 'evidence': {}})['files'] += 1
    update_behavior_bucket_learning(
        baseline,
        context['tag_evidence'],
        strings_blob=context['strings_blob'],
        api_calls=context['api_calls'],
        ordered_events=context['ordered_events'],
    )
    learn_extension_chains(baseline, context['chain_evidence'])
    update_extension_risk_baseline(baseline, context['risk'])
    baseline['vector_baseline'] = update_profile_vector_statistics(
        baseline.get('vector_baseline'), profile_vector,
        diversity_key=diversity_key,
    )
    update_extension_timeline_baseline(baseline, context['ordered_events'])
    baseline['learning_gate']['accepted'] += 1



def apply_extension_learning_decision(
    profile: object, request: object, profile_vector: object, *, diversity_key: str,
) -> dict[str, object]:
    """Apply one exact accepted transaction request to the profile baseline."""
    decision = getattr(request, "decision", None)
    authorization_reason = learning_authorization_failure(decision, "profile")
    if authorization_reason is not None:
        return {"updated": False, "reason": authorization_reason}
    if type(profile) is not dict:
        return {"updated": False, "reason": "profile_state_unavailable"}
    context = normalize_extension_learning_inputs(
        request.tag_evidence, request.ordered_events,
        file_path=request.file_path, strings_blob=request.strings_blob,
    )
    if context["unavailable_reason"] != "":
        return {"updated": False, "reason": context["unavailable_reason"]}
    context.update({
        "engine": request.engine,
        "file_path": request.file_path,
        "risk": request.risk,
        "strings_blob": request.strings_blob,
        "api_calls": request.api_calls,
    })
    validation = dict(request.validation)
    extension = resolve_extension_learning_key(
        request.file_path, True, validation,
    )
    with profile_ext_lock(request.engine, extension):
        model_state = profile.get("model_state")
        if type(model_state) is not dict:
            return {"updated": False, "reason": "profile_model_state_unavailable"}
        ledgers = model_state.get("learning_applied_keys")
        if type(ledgers) is not dict:
            return {"updated": False, "reason": "profile_learning_ledger_invalid"}
        applied = ledgers.get("profile")
        if type(applied) is not dict:
            return {"updated": False, "reason": "profile_learning_ledger_invalid"}
        baseline = prepare_extension_baseline(profile, extension)
        replay_key = request.decision.replay_key
        if replay_key in applied:
            return {
                "updated": True, "extension": extension, "baseline": baseline,
                "idempotent_replay": True,
            }
        _apply_accepted_extension_learning(
            baseline, context, profile_vector, diversity_key,
        )
        applied[replay_key] = request.decision.decision_ordinal
        if len(applied) > 4096:
            keep = {key for _ordinal, key in sorted(
                (ordinal if type(ordinal) is int else 0, key)
                for key, ordinal in applied.items()
            )[-4096:]}
            for key in tuple(applied):
                if key not in keep:
                    applied.pop(key, None)
        profile["updated"] = profile_update_marker(profile)
    return {
        "updated": True, "extension": extension, "baseline": baseline,
        "idempotent_replay": False,
    }


__all__ = (
    "apply_extension_learning_decision",
    "learn_extension_tags",
    "update_behavior_bucket_learning",
)
