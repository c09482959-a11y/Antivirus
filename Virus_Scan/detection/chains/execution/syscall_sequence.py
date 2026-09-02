"""Canonical execution-chain ownership for syscall and shellcode sequence evidence."""
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.detection.chains.execution.text_boundaries import execution_reason_hit, execution_unit_score
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    norm_lower_set,
    normalize_tags,
)


PLR2004N3 = 3


def _syscall_input(value: object) -> object:
    return () if value is None else value


def _syscall_blob_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_syscall_sequence_blob',
        unsupported_reason='unsafe_syscall_sequence_blob_rejected',
    )
    if reason:
        return ('', reason)
    return (text.strip().lower(), '')


def detect_syscall_sequence_model(strings_blob: object, tags: object=None) -> object:
    """Adds syscall / shellcode loader sequence scoring."""
    tags = norm_lower_set(normalize_tags(_syscall_input(tags)))
    blob, blob_reason = _syscall_blob_text(strings_blob)
    score = 0.0
    hits = []
    new_tags = set()
    if TAG_NORMALIZATION_FAILURE_EVIDENCE in tags or DETECTION_STAGE_DEGRADED_TAG in tags:
        new_tags.add(DETECTION_STAGE_DEGRADED_TAG)
        hits.append('syscall_sequence_tag_normalization_failure')
    if blob_reason:
        new_tags.add('syscall_sequence_input_unavailable')
        hits.append(execution_reason_hit('syscall_sequence_input_unavailable:', blob_reason))
    alloc_terms = ['virtualalloc', 'virtualallocex', 'ntallocatevirtualmemory']
    write_terms = ['writeprocessmemory', 'ntwritevirtualmemory', 'rtlmovememory']
    protect_terms = ['virtualprotect', 'virtualprotectex', 'ntprotectvirtualmemory']
    execute_terms = ['createremotethread', 'createthread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'resumethread']
    has_alloc = any((x in blob for x in alloc_terms))
    has_write = any((x in blob for x in write_terms))
    has_protect = any((x in blob for x in protect_terms))
    has_execute = any((x in blob for x in execute_terms))
    if has_alloc:
        new_tags.add('memory_allocate')
    if has_write:
        new_tags.add('memory_write')
    if has_protect:
        new_tags.add('memory_protect')
    if has_execute:
        new_tags.add('thread_execution')
    chain_count = sum([has_alloc, has_write, has_protect, has_execute])
    if chain_count >= 2:
        score += 0.25
        hits.append('partial memory loader sequence')
    if chain_count >= PLR2004N3:
        score += 0.35
        hits.append('strong memory loader sequence')
    if has_alloc and has_write and has_execute:
        score += 0.3
        hits.append('alloc-write-execute shellcode pattern')
        new_tags.add('shellcode_loader')
    nt_syscalls = ['ntallocatevirtualmemory', 'ntwritevirtualmemory', 'ntprotectvirtualmemory', 'ntcreatethreadex', 'ntmapviewofsection', 'ntqueueapcthread']
    nt_hits = [x for x in nt_syscalls if x in blob]
    if len(nt_hits) >= 2:
        score += 0.25
        hits.append('multiple native syscall indicators')
        new_tags.add('syscall_sequence')
    if 'process_injection' in tags and chain_count >= 2:
        score += 0.2
        hits.append('existing injection tag reinforced by syscall sequence')
    return {'score': execution_unit_score(score), 'tags': sorted(new_tags), 'hits': hits, 'chain_count': chain_count}
