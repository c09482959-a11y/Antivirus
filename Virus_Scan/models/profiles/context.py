"""Profile contextual identity and baseline-key ownership."""

from dataclasses import replace
from pathlib import Path

from Virus_Scan.contracts.profile_context_identity import profile_learning_context_identity
from Virus_Scan.utils.stages import normalize_profile_extension
from Virus_Scan.models.profiles.common import profile_safe_text


def _profile_context_container_root_result(file_path: object) -> object:
    path = Path(profile_safe_text(file_path, replacement=''))
    parent = path.parent
    if parent in {Path(''), Path('.')}:
        return None, None
    try:
        parent_exists = parent.exists()
    except OSError:
        return parent, 'profile_context_container_root_unavailable'
    if not parent_exists:
        return None, None
    return parent, None


def profile_context_container_root(file_path: object) -> object:
    """Return an explicit scan-root candidate or ``None`` for synthetic nodes."""
    root, _reason = _profile_context_container_root_result(file_path)
    return root


def contextual_profile_learning_policy(file_path: object, *, trusted_benign: object=False, degraded: object=False, evidence_context: object | None=None, router_identity: object | None=None) -> object:
    """Return canonical contextual learning policy for profile baseline writes."""
    container_root, root_reason = _profile_context_container_root_result(file_path)
    identity = (
        profile_learning_context_identity(
            file_path, container_root=container_root,
            trusted_benign=trusted_benign, degraded=degraded,
            router_identity=router_identity,
        )
        if evidence_context is None
        else profile_learning_context_identity(
            file_path, container_root=container_root,
            trusted_benign=trusted_benign, degraded=degraded,
            evidence_context=evidence_context,
            router_identity=router_identity,
        )
    )
    if root_reason is not None:
        identity = replace(identity, fingerprint_evidence=tuple(dict.fromkeys((root_reason, *tuple(identity.fingerprint_evidence))))[:64])
        identity.validate(context='contextual_profile_learning_policy')
    return identity


def contextual_profile_baseline_key(file_path: object, *, trusted_benign: object=False, degraded: object=False, evidence_context: object | None=None) -> object:
    ctx = contextual_profile_learning_policy(
        file_path,
        trusted_benign=trusted_benign,
        degraded=degraded,
        evidence_context=evidence_context,
    )
    return ctx.learning_baseline_key or ctx.baseline_key


def contextual_profile_bucket_key(file_path: object, *, trusted_benign: object=False, degraded: object=False, evidence_context: object | None=None, router_identity: object | None=None) -> object:
    """Return the canonical profile bucket for model reads/writes."""
    ctx = contextual_profile_learning_policy(
        file_path,
        trusted_benign=trusted_benign,
        degraded=degraded,
        evidence_context=evidence_context,
        router_identity=router_identity,
    )
    return ctx.learning_baseline_key or ctx.baseline_key, ctx


def engine_extension_key(engine: object, file_path: object) -> object:
    """Profile-owned engine/extension bucket key for adaptive model baselines."""
    engine_text = profile_safe_text(engine, replacement='other').lower()
    if engine_text == '':
        engine_text = 'other'
    return ':'.join((engine_text, normalize_profile_extension(file_path)))


__all__ = (
    'contextual_profile_baseline_key',
    'contextual_profile_bucket_key',
    'contextual_profile_learning_policy',
    'engine_extension_key',
    'profile_context_container_root',
)
